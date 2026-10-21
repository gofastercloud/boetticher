package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/labspeedtest"
)

// fakeLabHost models only the namespace and host veth; every native call is
// recorded so tests can assert exact ownership and ordering.
type fakeLabHost struct {
	ns, veth   bool
	calls      []string
	failOn     string
	output     map[string]string
	stuck      bool
	stopCalled int
}

func (h *fakeLabHost) run(_ context.Context, tool string, args ...string) (string, error) {
	call := tool + " " + strings.Join(args, " ")
	h.calls = append(h.calls, call)
	if h.failOn != "" && strings.Contains(call, h.failOn) {
		return "boom", errors.New("boom")
	}
	switch {
	case call == "ip netns add "+labspeedtest.Namespace:
		h.ns = true
	case strings.HasPrefix(call, "ip link add "+labspeedtest.HostVeth):
		h.veth = true
	case call == "ip netns del "+labspeedtest.Namespace:
		if !h.stuck {
			h.ns, h.veth = false, false
		}
	case call == "ip link del "+labspeedtest.HostVeth:
		if !h.stuck {
			h.veth = false
		}
	case strings.Contains(call, "arping"):
		return "Sent 2 probes (2 broadcast(s))\nReceived 0 response(s)\n", nil
	}
	for prefix, output := range h.output {
		if strings.HasPrefix(call, prefix) {
			return output, nil
		}
	}
	if strings.HasPrefix(call, "bridge -j vlan show") {
		return exactAccessJSON, nil
	}
	return "", nil
}

const exactAccessJSON = `[{"ifname":"bt4s-lab-h","vlans":[{"vlan":20,"flags":["PVID","Egress Untagged"]}]}]`

func (h *fakeLabHost) namespaceExists(string) bool             { return h.ns }
func (h *fakeLabHost) linkExists(context.Context, string) bool { return h.veth }
func (h *fakeLabHost) stopNamespaceChildren(string) error      { h.stopCalled++; return nil }
func (h *fakeLabHost) called(fragment string) bool             { return indexOf(h.calls, fragment) >= 0 }
func indexOf(calls []string, fragment string) int {
	for index, call := range calls {
		if strings.Contains(call, fragment) {
			return index
		}
	}
	return -1
}

const (
	nsLinks       = "1: lo: <LOOPBACK,UP> mtu 65536\n2: eth0@if42: <BROADCAST,UP> mtu 1500 link-netns x\n"
	hostOnBridge  = "42: bt4s-lab-h@if2: <BROADCAST,UP> mtu 1500 master vmbr1 state UP\n"
	hostUnbridged = "42: bt4s-lab-h@if2: <BROADCAST> mtu 1500 state DOWN\n"
)

// leftover builds recovery output; overrides replace individual commands.
func leftover(overrides map[string]string) map[string]string {
	output := map[string]string{
		"ip netns exec bt4s-lab ip -o link show":           nsLinks,
		"ip -o link show dev bt4s-lab-h":                   hostOnBridge,
		"bridge -j vlan show dev bt4s-lab-h":               exactAccessJSON,
		"ip netns exec bt4s-lab ip -4 -o address show dev": "2: eth0    inet 10.10.20.250/24 scope global eth0\n",
	}
	for key, value := range overrides {
		output[key] = value
	}
	return output
}

func ownedLeftoverOutput() map[string]string { return leftover(nil) }

func decodeLines(t *testing.T, data []byte) []labspeedtest.Event {
	t.Helper()
	events := []labspeedtest.Event{}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		event, err := labspeedtest.ParseEvent(line)
		if err != nil {
			t.Fatalf("helper emitted invalid line %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

func TestLabRunCreatesOwnedFixtureMeasuresAndCleansUp(t *testing.T) {
	host := &fakeLabHost{}
	var out bytes.Buffer
	terminal := runLabWith(context.Background(), host, &eventWriter{out: &out}, func(_ context.Context, emit func(labspeedtest.Event)) labspeedtest.Event {
		if !host.ns || !host.veth {
			t.Fatal("measurement ran before the fixture existed")
		}
		emit(labspeedtest.Event{Phase: labspeedtest.PhaseDownload, DownloadMbps: 300})
		return labspeedtest.Event{Phase: labspeedtest.PhaseDone, Server: "Example (Sydney)", DownloadMbps: 612, UploadMbps: 40, LatencyMS: 9}
	})
	if terminal.Phase != labspeedtest.PhaseDone || terminal.DownloadMbps != 612 {
		t.Fatalf("terminal = %#v", terminal)
	}
	if host.ns || host.veth {
		t.Fatal("fixture remained after a successful run")
	}
	for _, required := range []string{
		"ip link set bt4s-lab-h master vmbr1",
		"bridge vlan add dev bt4s-lab-h vid 20 pvid untagged",
		"ip netns exec bt4s-lab sysctl -q -w net.ipv6.conf.all.disable_ipv6=1",
		"ip netns exec bt4s-lab ip address add 10.10.20.250/24 dev eth0",
		"ip netns exec bt4s-lab ip route replace default via 10.10.20.1 dev eth0",
		"ip netns del bt4s-lab",
	} {
		if !host.called(required) {
			t.Errorf("missing native step %q in %#v", required, host.calls)
		}
	}
	events := decodeLines(t, out.Bytes())
	if len(events) != 2 || events[0].Phase != labspeedtest.PhaseSetup || events[0].Recovered || events[1].Phase != labspeedtest.PhaseDownload {
		t.Fatalf("progress events = %#v", events)
	}
}

func TestLabSetupFailureStillRemovesWhatWasCreated(t *testing.T) {
	host := &fakeLabHost{failOn: "bridge vlan add"}
	measured := false
	terminal := runLabWith(context.Background(), host, &eventWriter{out: &bytes.Buffer{}}, func(context.Context, func(labspeedtest.Event)) labspeedtest.Event {
		measured = true
		return labspeedtest.Event{}
	})
	if measured {
		t.Fatal("measurement ran after setup failure")
	}
	if terminal.Phase != labspeedtest.PhaseError || !strings.Contains(terminal.Error, "setup failed") {
		t.Fatalf("terminal = %#v", terminal)
	}
	if host.ns || host.veth || !host.called("ip netns del bt4s-lab") {
		t.Fatalf("partial fixture was not cleaned up: ns=%t veth=%t calls=%#v", host.ns, host.veth, host.calls)
	}
}

func TestLabNamespaceFailureCreatesAndRemovesNothing(t *testing.T) {
	host := &fakeLabHost{failOn: "ip netns add"}
	terminal := runLabWith(context.Background(), host, &eventWriter{out: &bytes.Buffer{}}, nil)
	if terminal.Phase != labspeedtest.PhaseError || host.called("ip netns del") || host.called("ip link del") {
		t.Fatalf("terminal=%#v calls=%#v", terminal, host.calls)
	}
}

func TestLabCleanupFailureTurnsResultIntoFailureAndKeepsFigures(t *testing.T) {
	host := &fakeLabHost{stuck: true}
	terminal := runLabWith(context.Background(), host, &eventWriter{out: &bytes.Buffer{}}, func(context.Context, func(labspeedtest.Event)) labspeedtest.Event {
		return labspeedtest.Event{Phase: labspeedtest.PhaseDone, DownloadMbps: 612, UploadMbps: 40}
	})
	if terminal.Phase != labspeedtest.PhaseError || !strings.Contains(terminal.Error, "cleanup failed") || terminal.DownloadMbps != 612 {
		t.Fatalf("cleanup failure was not reported as failure: %#v", terminal)
	}
}

func TestLabRecoversOwnedLeftoverBeforeRunning(t *testing.T) {
	host := &fakeLabHost{ns: true, veth: true, output: ownedLeftoverOutput()}
	var out bytes.Buffer
	terminal := runLabWith(context.Background(), host, &eventWriter{out: &out}, func(context.Context, func(labspeedtest.Event)) labspeedtest.Event {
		return labspeedtest.Event{Phase: labspeedtest.PhaseDone, DownloadMbps: 100}
	})
	if terminal.Phase != labspeedtest.PhaseDone {
		t.Fatalf("terminal = %#v", terminal)
	}
	deleteIndex, addIndex := indexOf(host.calls, "ip netns del bt4s-lab"), indexOf(host.calls, "ip netns add bt4s-lab")
	if deleteIndex < 0 || addIndex < 0 || deleteIndex > addIndex {
		t.Fatalf("leftover was not removed before the new fixture: %#v", host.calls)
	}
	if events := decodeLines(t, out.Bytes()); len(events) == 0 || !events[0].Recovered {
		t.Fatalf("recovery was not reported: %#v", events)
	}
}

func TestLabRecoveryRemovesNamespaceInterruptedBeforeVeth(t *testing.T) {
	host := &fakeLabHost{ns: true, output: map[string]string{"ip netns exec bt4s-lab ip -o link show": "1: lo: <LOOPBACK> mtu 65536\n"}}
	recovered, err := recoverLabLeftovers(context.Background(), host)
	if err != nil || !recovered || host.ns {
		t.Fatalf("recovered=%t err=%v ns=%t", recovered, err, host.ns)
	}
}

func TestLabRecoveryRefusesAmbiguousResources(t *testing.T) {
	cases := map[string]*fakeLabHost{
		"veth without namespace":     {veth: true},
		"same-named foreign veth":    {ns: true, veth: true, output: leftover(map[string]string{"ip -o link show dev bt4s-lab-h": "77: bt4s-lab-h@if9: <BROADCAST> master vmbr1\n"})},
		"peer not paired back":       {ns: true, veth: true, output: leftover(map[string]string{"ip netns exec bt4s-lab ip -o link show": "1: lo: x\n3: eth0@if42: x\n"})},
		"other bridge":               {ns: true, veth: true, output: leftover(map[string]string{"ip -o link show dev bt4s-lab-h": "42: bt4s-lab-h@if2: <BROADCAST> master vmbr0\n"})},
		"foreign VLAN":               {ns: true, veth: true, output: leftover(map[string]string{"bridge -j vlan show dev bt4s-lab-h": `[{"ifname":"bt4s-lab-h","vlans":[{"vlan":30,"flags":["PVID","Egress Untagged"]}]}]`})},
		"SERVERS tagged":             {ns: true, veth: true, output: leftover(map[string]string{"bridge -j vlan show dev bt4s-lab-h": `[{"ifname":"bt4s-lab-h","vlans":[{"vlan":20,"flags":[]}]}]`})},
		"foreign address":            {ns: true, veth: true, output: leftover(map[string]string{"ip netns exec bt4s-lab ip -4 -o address show dev": "2: eth0 inet 10.10.30.250/24 scope global eth0"})},
		"namespace with other links": {ns: true, output: map[string]string{"ip netns exec bt4s-lab ip -o link show": "1: lo: x\n3: wg0: x\n"}},
	}
	for name, host := range cases {
		t.Run(name, func(t *testing.T) {
			terminal := runLabWith(context.Background(), host, &eventWriter{out: &bytes.Buffer{}}, func(context.Context, func(labspeedtest.Event)) labspeedtest.Event {
				t.Fatal("measurement ran despite ambiguous leftovers")
				return labspeedtest.Event{}
			})
			if terminal.Phase != labspeedtest.PhaseError || !strings.Contains(terminal.Error, "could not be recovered") {
				t.Fatalf("terminal = %#v", terminal)
			}
			if host.called("ip netns del") || host.called("ip link del") {
				t.Fatalf("ambiguous resource was removed: %#v", host.calls)
			}
		})
	}
}

func TestRelayChildEventsForwardsProgressAndHoldsTerminal(t *testing.T) {
	stream := strings.Join([]string{
		`{"phase":"server","server":"Example"}`,
		`{"phase":"download","download_mbps":250.5}`,
		`{"phase":"done","download_mbps":600,"upload_mbps":40}`,
	}, "\n") + "\n"
	var relayed []labspeedtest.Event
	terminal, err := relayChildEvents(strings.NewReader(stream), func(event labspeedtest.Event) { relayed = append(relayed, event) })
	if err != nil || terminal == nil || terminal.Phase != labspeedtest.PhaseDone || len(relayed) != 2 {
		t.Fatalf("terminal=%#v relayed=%#v err=%v", terminal, relayed, err)
	}
	if _, err := relayChildEvents(strings.NewReader("not json\n"), func(labspeedtest.Event) {}); err == nil {
		t.Fatal("malformed child output was accepted")
	}
	if _, err := relayChildEvents(strings.NewReader(strings.Repeat("x", labspeedtest.MaxEventBytes+10)+"\n"), func(labspeedtest.Event) {}); err == nil {
		t.Fatal("oversized child output was accepted")
	}
}

func TestProgressThrottleBoundsLiveRates(t *testing.T) {
	now := time.Unix(1000, 0)
	var emitted []labspeedtest.Event
	throttle := newProgressThrottle(time.Second, func(event labspeedtest.Event) { emitted = append(emitted, event) })
	throttle.now = func() time.Time { return now }
	for step := 0; step < 30; step++ {
		throttle.offer(labspeedtest.Event{Phase: labspeedtest.PhaseDownload, DownloadMbps: float64(step + 1)})
		now = now.Add(100 * time.Millisecond)
	}
	if len(emitted) != 3 {
		t.Fatalf("throttle emitted %d events in 3 s, want 3", len(emitted))
	}
	throttle.flush(labspeedtest.Event{Phase: labspeedtest.PhaseDownload, DownloadMbps: 99})
	if len(emitted) != 4 || emitted[3].DownloadMbps != 99 {
		t.Fatalf("final rate was not flushed: %#v", emitted)
	}
}

func TestChildCommandLineMatchesOnlyTheHelperChild(t *testing.T) {
	if !childCommandLine([]string{"/usr/local/libexec/boetticher-host-speedtest", "--lab-child", "--gateway", "10.10.20.1", ""}) {
		t.Fatal("helper child was not recognised")
	}
	for _, parts := range [][]string{{"/usr/bin/sleep", "--lab-child"}, {"/usr/local/libexec/boetticher-host-speedtest", "--lab", "--stream"}, {"boetticher-host-speedtest"}} {
		if childCommandLine(parts) {
			t.Fatalf("foreign process matched: %#v", parts)
		}
	}
}

func TestLabRecoveryAcceptsPartiallyConfiguredOwnedFixture(t *testing.T) {
	cases := map[string]map[string]string{
		"veth not yet on vmbr1":  {"ip -o link show dev bt4s-lab-h": hostUnbridged, "bridge -j vlan show dev bt4s-lab-h": "[]"},
		"default VLAN only":      {"bridge -j vlan show dev bt4s-lab-h": `[{"ifname":"bt4s-lab-h","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]}]}]`},
		"VLAN 1 not yet removed": {"bridge -j vlan show dev bt4s-lab-h": `[{"ifname":"bt4s-lab-h","vlans":[{"vlan":1,"flags":["Egress Untagged"]},{"vlan":20,"flags":["PVID","Egress Untagged"]}]}]`},
		"no address yet":         {"ip netns exec bt4s-lab ip -4 -o address show dev": ""},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			host := &fakeLabHost{ns: true, veth: true, output: leftover(overrides)}
			recovered, err := recoverLabLeftovers(context.Background(), host)
			if err != nil || !recovered || host.ns || host.veth {
				t.Fatalf("recovered=%t err=%v ns=%t veth=%t", recovered, err, host.ns, host.veth)
			}
		})
	}
}

func TestLabSetupRemovesDefaultVLANAndRequiresExactAccessPort(t *testing.T) {
	host := &fakeLabHost{}
	runLabWith(context.Background(), host, &eventWriter{out: &bytes.Buffer{}}, func(context.Context, func(labspeedtest.Event)) labspeedtest.Event {
		return labspeedtest.Event{Phase: labspeedtest.PhaseDone, DownloadMbps: 1}
	})
	del, add := indexOf(host.calls, "bridge vlan del dev bt4s-lab-h vid 1"), indexOf(host.calls, "bridge vlan add dev bt4s-lab-h vid 20 pvid untagged")
	if del < 0 || add < 0 || del < add {
		t.Fatalf("default VLAN 1 was not removed after SERVERS was added: %#v", host.calls)
	}
	for name, vlans := range map[string]string{
		"VLAN 1 remains": `[{"ifname":"bt4s-lab-h","vlans":[{"vlan":1,"flags":[]},{"vlan":20,"flags":["PVID","Egress Untagged"]}]}]`,
		"SERVERS tagged": `[{"ifname":"bt4s-lab-h","vlans":[{"vlan":20,"flags":["PVID"]}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			host := &fakeLabHost{output: map[string]string{"bridge -j vlan show dev bt4s-lab-h": vlans}}
			terminal := runLabWith(context.Background(), host, &eventWriter{out: &bytes.Buffer{}}, func(context.Context, func(labspeedtest.Event)) labspeedtest.Event {
				t.Fatal("measured on a port that is not exactly SERVERS")
				return labspeedtest.Event{}
			})
			if terminal.Phase != labspeedtest.PhaseError || !strings.Contains(terminal.Error, "not exactly VLAN 20") || host.ns || host.veth {
				t.Fatalf("terminal=%#v ns=%t veth=%t", terminal, host.ns, host.veth)
			}
		})
	}
}

func TestLabCleanupOnlyRemovesOwnedLeftoverAndRefusesAmbiguous(t *testing.T) {
	host := &fakeLabHost{ns: true, veth: true, output: ownedLeftoverOutput()}
	if event := cleanupLabWith(host); event.Phase != labspeedtest.PhaseCleanup || !event.Recovered || host.ns || host.veth {
		t.Fatalf("cleanup-only = %#v ns=%t veth=%t", event, host.ns, host.veth)
	}
	if host.called("ip netns add") {
		t.Fatal("cleanup-only created a fixture")
	}
	if event := cleanupLabWith(&fakeLabHost{}); event.Phase != labspeedtest.PhaseCleanup || event.Recovered {
		t.Fatalf("clean Host cleanup-only = %#v", event)
	}
	ambiguous := &fakeLabHost{veth: true}
	if event := cleanupLabWith(ambiguous); event.Phase != labspeedtest.PhaseError || ambiguous.called("ip link del") {
		t.Fatalf("ambiguous cleanup-only = %#v calls=%#v", event, ambiguous.calls)
	}
}

// expiringLabHost answers existence like the native host does when its
// context is exhausted: unknown, therefore present.
type expiringLabHost struct{ fakeLabHost }

func (h *expiringLabHost) linkExists(ctx context.Context, name string) bool {
	if ctx.Err() != nil {
		return true
	}
	return h.fakeLabHost.linkExists(ctx, name)
}

func TestLabCleanupVerifiesWithAFreshContext(t *testing.T) {
	host := &expiringLabHost{fakeLabHost{ns: true, veth: true}}
	fixture := &labFixture{host: host, createdNS: true, createdVeth: true}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.cleanup(expired); err != nil {
		t.Fatalf("cleanup with an exhausted budget could not verify removal: %v", err)
	}
	stuck := &expiringLabHost{fakeLabHost{ns: true, veth: true, stuck: true}}
	if err := (&labFixture{host: stuck, createdNS: true, createdVeth: true}).cleanup(expired); err == nil {
		t.Fatal("surviving fixture reported clean")
	}
}

func TestNativeExistenceIsConservative(t *testing.T) {
	if !linkAbsent("Device \"bt4s-lab-h\" does not exist.\n", errors.New("exit status 1")) {
		t.Fatal("definite absence not recognised")
	}
	for _, item := range []struct {
		output string
		err    error
	}{{"", context.DeadlineExceeded}, {"", context.Canceled}, {"RTNETLINK answers: Operation not permitted", errors.New("exit status 2")}, {"42: bt4s-lab-h@if2: ...", nil}} {
		if linkAbsent(item.output, item.err) {
			t.Fatalf("linkAbsent(%q, %v) treated an unknown state as absent", item.output, item.err)
		}
	}
	if (nativeLabHost{}).namespaceExists("bt4s-definitely-missing-namespace") {
		t.Fatal("a missing namespace was reported present")
	}
	if !(nativeLabHost{}).linkExists(expiredContext(), "lo") {
		t.Fatal("expired context made a link look absent")
	}
}

func expiredContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestParseLinkLineReadsIndexPeerAndMaster(t *testing.T) {
	link, ok := parseLinkLine(hostOnBridge, "bt4s-lab-h")
	if !ok || link.index != 42 || link.peer != 2 || link.master != "vmbr1" {
		t.Fatalf("link = %#v ok=%t", link, ok)
	}
	if _, ok := parseLinkLine("42: bt4s-lab-hx@if2: x\n", "bt4s-lab-h"); ok {
		t.Fatal("prefix-named link matched")
	}
	if _, ok := parseLinkLine("42: bt4s-lab-h: <BROADCAST>\n", "bt4s-lab-h"); ok {
		t.Fatal("non-veth link matched")
	}
}
