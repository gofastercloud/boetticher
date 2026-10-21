package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewalltest"
	"github.com/gofastercloud/boetticher/internal/labspeedtest"
)

const (
	labTestBudget    = 150 * time.Second
	labCleanupBudget = 30 * time.Second
	labChildFlag     = "--lab-child"
)

// labHost is the small native surface the lab fixture needs. The production
// implementation runs ip/bridge/arping by absolute path; tests substitute a
// recording fake so setup failure, cleanup, and leftover recovery are
// exercised without touching the Host.
type labHost interface {
	run(ctx context.Context, tool string, args ...string) (string, error)
	namespaceExists(name string) bool
	linkExists(ctx context.Context, name string) bool
	stopNamespaceChildren(namespace string) error
}

type labFixture struct {
	host        labHost
	address     string
	createdNS   bool
	createdVeth bool
}

type eventWriter struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *eventWriter) emit(event labspeedtest.Event) {
	data, err := labspeedtest.Encode(event)
	if err != nil {
		data, _ = labspeedtest.Encode(labspeedtest.ErrorEvent("encode progress: %v", err))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.out.Write(data)
}

func runLab(stdout io.Writer) int {
	writer := &eventWriter{out: stdout}
	lock, err := acquireLabLock()
	if err != nil {
		writer.emit(labspeedtest.ErrorEvent("%v", err))
		return 1
	}
	defer lock.Close()
	// SIGPIPE/SIGHUP arrive when the Controller's SSH session goes away. They
	// cancel the run so cleanup still executes instead of the process dying.
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalContext, labTestBudget)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		writer.emit(labspeedtest.ErrorEvent("resolve helper path: %v", err))
		return 1
	}
	terminal := runLabWith(ctx, nativeLabHost{}, writer, func(ctx context.Context, emit func(labspeedtest.Event)) labspeedtest.Event {
		return runChildInNamespace(ctx, executable, emit)
	})
	writer.emit(terminal)
	if terminal.Phase != labspeedtest.PhaseDone {
		return 1
	}
	return 0
}

// runLabWith owns the fixture lifecycle: recover leftovers, register cleanup
// before the first mutation, measure, then clean up with a fresh budget. The
// terminal event is returned rather than emitted so a cleanup failure can
// still turn a measured result into a failure.
func runLabWith(ctx context.Context, host labHost, writer *eventWriter, measure func(context.Context, func(labspeedtest.Event)) labspeedtest.Event) (terminal labspeedtest.Event) {
	recoverCtx, recoverCancel := context.WithTimeout(context.Background(), labCleanupBudget)
	recovered, err := recoverLabLeftovers(recoverCtx, host)
	recoverCancel()
	if err != nil {
		return labspeedtest.ErrorEvent("previous lab speedtest fixture could not be recovered: %v", err)
	}
	writer.emit(labspeedtest.Event{Phase: labspeedtest.PhaseSetup, Recovered: recovered})
	fixture := &labFixture{host: host}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), labCleanupBudget)
		cleanupErr := fixture.cleanup(cleanupCtx)
		cleanupCancel()
		if cleanupErr != nil {
			detail := "lab speedtest fixture cleanup failed: " + cleanupErr.Error()
			if terminal.Phase == labspeedtest.PhaseError {
				detail = terminal.Error + "; " + detail
			}
			failed := labspeedtest.ErrorEvent("%s", detail)
			failed.Server, failed.LatencyMS, failed.JitterMS = terminal.Server, terminal.LatencyMS, terminal.JitterMS
			failed.DownloadMbps, failed.UploadMbps = terminal.DownloadMbps, terminal.UploadMbps
			terminal = failed
		}
	}()
	if err := fixture.setup(ctx); err != nil {
		return labspeedtest.ErrorEvent("lab speedtest setup failed: %v", err)
	}
	return measure(ctx, writer.emit)
}

func (f *labFixture) setup(ctx context.Context) error {
	ns, veth := labspeedtest.Namespace, labspeedtest.HostVeth
	if f.host.namespaceExists(ns) || f.host.linkExists(ctx, veth) {
		return fmt.Errorf("reserved lab speedtest resource %s or %s already exists", ns, veth)
	}
	if _, err := f.host.run(ctx, "ip", "netns", "add", ns); err != nil {
		return fmt.Errorf("create namespace: %w", err)
	}
	f.createdNS = true
	if _, err := f.host.run(ctx, "ip", "link", "add", veth, "type", "veth", "peer", "name", "eth0", "netns", ns); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}
	f.createdVeth = true
	steps := [][]string{
		{"ip", "netns", "exec", ns, "sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1"},
		{"ip", "netns", "exec", ns, "sysctl", "-q", "-w", "net.ipv6.conf.default.disable_ipv6=1"},
		{"ip", "link", "set", veth, "master", "vmbr1"},
		{"bridge", "vlan", "add", "dev", veth, "vid", strconv.Itoa(labspeedtest.VLAN), "pvid", "untagged"},
		{"ip", "link", "set", veth, "up"},
		{"ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", ns, "ip", "link", "set", "eth0", "up"},
	}
	for _, step := range steps {
		if _, err := f.host.run(ctx, step[0], step[1:]...); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(step, " "), err)
		}
	}
	address, err := chooseLabAddress(ctx, f.host)
	if err != nil {
		return err
	}
	f.address = address
	for _, step := range [][]string{
		{"ip", "netns", "exec", ns, "ip", "address", "add", address + "/24", "dev", "eth0"},
		{"ip", "netns", "exec", ns, "ip", "route", "replace", "default", "via", labspeedtest.Gateway, "dev", "eth0"},
	} {
		if _, err := f.host.run(ctx, step[0], step[1:]...); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(step, " "), err)
		}
	}
	return nil
}

// chooseLabAddress uses the same reserved .250-.254 probe space and bounded
// duplicate-address detection as the firewall packet fixtures.
func chooseLabAddress(ctx context.Context, host labHost) (string, error) {
	candidates, err := firewalltest.CandidateAddresses(labspeedtest.Subnet)
	if err != nil {
		return "", err
	}
	for _, candidate := range candidates {
		output, runErr := host.run(ctx, "ip", "netns", "exec", labspeedtest.Namespace, "arping", "-D", "-I", "eth0", "-c", "2", "-w", "3", candidate)
		if strings.Contains(output, "Received 0 response(s)") || strings.Contains(output, "100% packet loss") {
			return candidate, nil
		}
		if runErr != nil && ctx.Err() != nil {
			return "", ctx.Err()
		}
		if runErr != nil && !strings.Contains(output, "Received") {
			return "", fmt.Errorf("check probe address %s: %s", candidate, strings.TrimSpace(output))
		}
	}
	return "", errors.New("no free probe address remained in SERVERS .250-.254")
}

// cleanup removes only what this run created. Deleting the namespace removes
// the veth pair; the host end is removed explicitly if it survives.
func (f *labFixture) cleanup(ctx context.Context) error {
	if !f.createdNS && !f.createdVeth {
		return nil
	}
	ns, veth := labspeedtest.Namespace, labspeedtest.HostVeth
	cleanupErr := f.host.stopNamespaceChildren(ns)
	if f.createdNS && f.host.namespaceExists(ns) {
		if _, err := f.host.run(ctx, "ip", "netns", "del", ns); err != nil && f.host.namespaceExists(ns) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if f.createdVeth && f.host.linkExists(ctx, veth) {
		if _, err := f.host.run(ctx, "ip", "link", "del", veth); err != nil && f.host.linkExists(ctx, veth) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if f.host.namespaceExists(ns) || f.host.linkExists(ctx, veth) {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("lab speedtest resource %s or %s remains", ns, veth))
	}
	return cleanupErr
}

// recoverLabLeftovers removes a fixture left by an interrupted run. It only
// removes resources whose shape matches the fixture exactly and refuses
// ambiguous state. The bool reports that leftovers were found and removed;
// recovery is reported, not treated as a clean previous run.
func recoverLabLeftovers(ctx context.Context, host labHost) (bool, error) {
	ns, veth := labspeedtest.Namespace, labspeedtest.HostVeth
	nsPresent, vethPresent := host.namespaceExists(ns), host.linkExists(ctx, veth)
	if !nsPresent && !vethPresent {
		return false, nil
	}
	if !nsPresent {
		return false, fmt.Errorf("ownership of %s without %s is ambiguous", veth, ns)
	}
	owned, err := labLeftoverOwned(ctx, host, vethPresent)
	if err != nil {
		return false, err
	}
	if !owned {
		return false, fmt.Errorf("ownership of %s or %s is ambiguous", ns, veth)
	}
	fixture := &labFixture{host: host, createdNS: true, createdVeth: vethPresent}
	if err := fixture.cleanup(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func labLeftoverOwned(ctx context.Context, host labHost, vethPresent bool) (bool, error) {
	ns, veth := labspeedtest.Namespace, labspeedtest.HostVeth
	links, err := host.run(ctx, "ip", "netns", "exec", ns, "ip", "-o", "link", "show")
	if err != nil {
		return false, nil
	}
	if !vethPresent {
		// Interrupted between namespace and veth creation: only loopback.
		return onlyLoopback(links), nil
	}
	output, err := host.run(ctx, "ip", "link", "show", veth)
	if err != nil || !strings.Contains(output, "master vmbr1") {
		return false, nil
	}
	output, err = host.run(ctx, "bridge", "vlan", "show", "dev", veth)
	if err != nil || !vlanListed(output, labspeedtest.VLAN) {
		return false, nil
	}
	if !strings.Contains(links, "eth0@if") {
		return false, nil
	}
	output, err = host.run(ctx, "ip", "netns", "exec", ns, "ip", "-4", "-o", "address", "show", "dev", "eth0")
	if err != nil {
		return false, nil
	}
	if strings.Contains(output, "inet ") && !addressesInSubnet(output, labspeedtest.Subnet) {
		return false, nil
	}
	return true, nil
}

func onlyLoopback(links string) bool {
	for _, line := range strings.Split(strings.TrimSpace(links), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.TrimSuffix(fields[1], ":") != "lo" {
			return false
		}
	}
	return true
}

func vlanListed(output string, vlan int) bool {
	want := strconv.Itoa(vlan)
	for _, field := range strings.Fields(output) {
		if field == want {
			return true
		}
	}
	return false
}

func addressesInSubnet(output, subnet string) bool {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return false
	}
	fields := strings.Fields(output)
	for index, field := range fields {
		if field != "inet" || index+1 >= len(fields) {
			continue
		}
		address, err := netip.ParsePrefix(fields[index+1])
		if err != nil || !prefix.Contains(address.Addr()) {
			return false
		}
	}
	return true
}

// runChildInNamespace re-executes this helper inside the owned namespace and
// relays its validated progress lines. Only the terminal event is returned.
func runChildInNamespace(ctx context.Context, executable string, emit func(labspeedtest.Event)) labspeedtest.Event {
	command := exec.CommandContext(ctx, nativeTool("ip"), "netns", "exec", labspeedtest.Namespace, executable, labChildFlag, "--gateway", labspeedtest.Gateway)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 5 * time.Second
	var stderr strings.Builder
	command.Stderr = &limitedWriter{builder: &stderr, limit: 4096}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return labspeedtest.ErrorEvent("start measurement: %v", err)
	}
	if err := command.Start(); err != nil {
		return labspeedtest.ErrorEvent("start measurement: %v", err)
	}
	terminal, relayErr := relayChildEvents(stdout, emit)
	waitErr := command.Wait()
	switch {
	case ctx.Err() != nil:
		return labspeedtest.ErrorEvent("lab speedtest interrupted or exceeded its %s budget", labTestBudget)
	case relayErr != nil:
		return labspeedtest.ErrorEvent("%v", relayErr)
	case terminal == nil:
		detail := strings.TrimSpace(stderr.String())
		if detail == "" && waitErr != nil {
			detail = waitErr.Error()
		}
		return labspeedtest.ErrorEvent("measurement exited without a result: %s", detail)
	}
	return *terminal
}

func relayChildEvents(reader io.Reader, emit func(labspeedtest.Event)) (*labspeedtest.Event, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, labspeedtest.MaxEventBytes), labspeedtest.MaxEventBytes)
	var terminal *labspeedtest.Event
	for scanner.Scan() {
		event, err := labspeedtest.ParseEvent(scanner.Bytes())
		if err != nil {
			_, _ = io.Copy(io.Discard, reader)
			return nil, fmt.Errorf("measurement progress: %w", err)
		}
		if event.Terminal() {
			if terminal == nil {
				terminal = &event
			}
			continue
		}
		emit(event)
	}
	if err := scanner.Err(); err != nil {
		_, _ = io.Copy(io.Discard, reader)
		return nil, fmt.Errorf("measurement progress: %w", err)
	}
	return terminal, nil
}

type limitedWriter struct {
	builder *strings.Builder
	limit   int
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	if remaining := w.limit - w.builder.Len(); remaining > 0 {
		if len(data) > remaining {
			w.builder.Write(data[:remaining])
		} else {
			w.builder.Write(data)
		}
	}
	return len(data), nil
}

// acquireLabLock shares the firewall packet-test lock: both use owned
// namespaces in the same SERVERS probe space, so they never run together.
func acquireLabLock() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(firewalltest.LockPath), 0755); err != nil {
		return nil, fmt.Errorf("create test lock directory: %w", err)
	}
	file, err := os.OpenFile(firewalltest.LockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open test lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("a firewall test or lab speedtest is already running on the Host")
	}
	return file, nil
}

type nativeLabHost struct{}

func (nativeLabHost) run(ctx context.Context, tool string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, nativeTool(tool), args...)
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return string(output), ctx.Err()
		}
		return string(output), fmt.Errorf("%s %s: %s", tool, strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func (nativeLabHost) namespaceExists(name string) bool {
	_, err := os.Stat("/run/netns/" + name)
	return err == nil
}

func (h nativeLabHost) linkExists(ctx context.Context, name string) bool {
	_, err := h.run(ctx, "ip", "link", "show", "dev", name)
	return err == nil
}

// stopNamespaceChildren signals only this helper's own measurement processes
// inside the owned namespace, identified by command line and netns inode.
func (nativeLabHost) stopNamespaceChildren(namespace string) error {
	nsInfo, err := os.Stat("/run/netns/" + namespace)
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("inspect processes: %w", err)
	}
	pids := []int{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if err != nil || !childCommandLine(strings.Split(string(cmdline), "\x00")) {
			continue
		}
		processNS, err := os.Stat("/proc/" + entry.Name() + "/ns/net")
		if err != nil || !os.SameFile(processNS, nsInfo) {
			continue
		}
		pids = append(pids, pid)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	deadline := time.Now().Add(2 * time.Second)
	for _, pid := range pids {
		for processPresent(pid) && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
		}
		if processPresent(pid) {
			return fmt.Errorf("lab speedtest process %d did not exit", pid)
		}
	}
	return nil
}

func childCommandLine(parts []string) bool {
	return len(parts) >= 2 && filepath.Base(parts[0]) == "boetticher-host-speedtest" && parts[1] == labChildFlag
}

func processPresent(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// A zombie has exited; only its parent's wait remains.
	fields := strings.Fields(string(data))
	return len(fields) < 3 || fields[2] != "Z"
}

func nativeTool(name string) string {
	for _, directory := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		candidate := filepath.Join(directory, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return candidate
		}
	}
	return name
}
