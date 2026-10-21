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
	return "", nil
}

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

func ownedLeftoverOutput() map[string]string {
	return map[string]string{
		"ip netns exec bt4s-lab ip -o link show":           "1: lo: <LOOPBACK,UP> mtu 65536\n2: eth0@if42: <BROADCAST,UP> mtu 1500\n",
		"ip link show bt4s-lab-h":                          "42: bt4s-lab-h@if2: <BROADCAST,UP> mtu 1500 master vmbr1 state UP\n",
		"bridge vlan show dev bt4s-lab-h":                  "port              vlan-id\nbt4s-lab-h        20 PVID Egress Untagged\n",
		"ip netns exec bt4s-lab ip -4 -o address show dev": "2: eth0    inet 10.10.20.250/24 scope global eth0\n",
	}
}

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
		"foreign bridge":             {ns: true, veth: true, output: map[string]string{"ip netns exec bt4s-lab ip -o link show": "2: eth0@if42: x\n", "ip link show bt4s-lab-h": "master vmbr0", "bridge vlan show": "20"}},
		"foreign VLAN":               {ns: true, veth: true, output: map[string]string{"ip netns exec bt4s-lab ip -o link show": "2: eth0@if42: x\n", "ip link show bt4s-lab-h": "master vmbr1", "bridge vlan show": "bt4s-lab-h 30 PVID"}},
		"foreign address":            {ns: true, veth: true, output: map[string]string{"ip netns exec bt4s-lab ip -o link show": "2: eth0@if42: x\n", "ip link show bt4s-lab-h": "master vmbr1", "bridge vlan show": "bt4s-lab-h 20 PVID", "ip netns exec bt4s-lab ip -4 -o address": "2: eth0 inet 10.10.30.250/24 scope global eth0"}},
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
