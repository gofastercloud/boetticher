package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/firewalltest"
)

const maxRequestBytes = 128 * 1024

type ownedFixture struct {
	zone        firewalltest.Zone
	namespace   string
	hostVeth    string
	createdNS   bool
	createdVeth bool
}

type probeObservation struct {
	code   int
	detail string
}

func main() {
	if len(os.Args) > 1 {
		if handleChild(os.Args[1:]) {
			return
		}
		fmt.Fprintln(os.Stderr, "unsupported firewall test helper mode")
		os.Exit(2)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxRequestBytes+1))
	if err != nil || len(data) > maxRequestBytes {
		writeResponse(firewalltest.Response{Version: firewalltest.ProtocolVersion, Error: "firewall test request is missing or too large"})
		os.Exit(2)
	}
	var request firewalltest.Request
	if err := jsonUnmarshal(data, &request); err != nil {
		writeResponse(firewalltest.Response{Version: firewalltest.ProtocolVersion, Error: "firewall test request is malformed"})
		os.Exit(2)
	}
	if err := firewalltest.ValidateRequest(request); err != nil {
		writeResponse(firewalltest.Response{Version: firewalltest.ProtocolVersion, Error: err.Error()})
		os.Exit(2)
	}
	var response firewalltest.Response
	if request.Action == "cleanup" {
		response = cleanupOnly()
	} else {
		response = runSuite(request)
	}
	writeResponse(response)
	if !response.OK || !response.CleanupOK {
		os.Exit(1)
	}
}

// Kept as a tiny wrapper so the request boundary remains in one place and the
// helper has no generic command or JSON execution surface.
func jsonUnmarshal(data []byte, target any) error {
	return json.Unmarshal(data, target)
}

func writeResponse(response firewalltest.Response) {
	_ = json.NewEncoder(os.Stdout).Encode(response)
}

func handleChild(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "--listener":
		if len(args) != 4 || (args[1] != "tcp" && args[1] != "udp") || !validAddress(args[2]) || !validPort(args[3]) {
			os.Exit(12)
		}
		if args[1] == "tcp" {
			os.Exit(listenerTCP(args[2], args[3]))
		}
		os.Exit(listenerUDP(args[2], args[3]))
	case "--ping":
		if len(args) != 2 || !validAddress(args[1]) {
			os.Exit(12)
		}
		os.Exit(runPing(args[1]))
	case "--tcp":
		if len(args) != 3 || !validAddress(args[1]) || !validPort(args[2]) {
			os.Exit(12)
		}
		observation := runTCP(args[1], args[2])
		fmt.Fprintln(os.Stdout, observation.detail)
		os.Exit(observation.code)
	case "--udp":
		if len(args) != 3 || !validAddress(args[1]) || !validPort(args[2]) {
			os.Exit(12)
		}
		observation := runUDP(args[1], args[2])
		fmt.Fprintln(os.Stdout, observation.detail)
		os.Exit(observation.code)
	case "--https":
		if len(args) != 3 || !validAddress(args[1]) || args[2] != firewalltest.PublicHost {
			os.Exit(12)
		}
		observation := runHTTPS(args[1], args[2])
		fmt.Fprintln(os.Stdout, observation.detail)
		os.Exit(observation.code)
	default:
		return false
	}
	return true
}

func runSuite(request firewalltest.Request) (response firewalltest.Response) {
	response.Version = firewalltest.ProtocolVersion
	lock, err := acquireLock()
	if err != nil {
		response.Error = err.Error()
		return response
	}
	defer lock.Close()

	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalContext, 8*time.Minute)
	defer cancel()
	fixtures, err := prepareFixtures(ctx, request.Zones)
	if err != nil {
		response.Error = err.Error()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		response.CleanupOK = cleanupCreated(cleanupCtx, fixtures) == nil
		if !response.CleanupOK {
			response.Error = joinDetail(response.Error, "fixture cleanup failed")
		}
		cleanupCancel()
		return response
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		cleanupErr := cleanupCreated(cleanupCtx, fixtures)
		cleanupCancel()
		response.CleanupOK = cleanupErr == nil
		if cleanupErr != nil {
			response.Error = joinDetail(response.Error, "fixture cleanup failed: "+cleanupErr.Error())
		}
	}()
	listeners, err := startListeners(ctx, fixtures)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	defer func() { stopListeners(listeners) }()

	byZone := map[string]fixtureInfo{}
	for _, fixture := range fixtures {
		byZone[fixture.zone.Name] = fixtureInfo{fixture: fixture, namespace: fixture.namespace}
	}
	add := func(result firewalltest.Result) {
		response.Results = append(response.Results, result)
		if result.Status != "PASS" && response.Error == "" {
			response.Error = "one or more firewall packet journeys failed"
		}
	}
	for _, zone := range firewalltest.ZoneOrder {
		fixture := byZone[zone]
		observation := runInNamespace(ctx, fixture.namespace, "--ping", fixture.fixture.zone.Gateway)
		add(resultFor("gateway/"+zone, "Gateway access", zone, zone+" gateway", "icmp", "allow", observation, true))
	}
	for _, zone := range firewalltest.ZoneOrder {
		fixture := byZone[zone]
		observation := runInNamespace(ctx, fixture.namespace, "--https", request.PublicAddress, request.PublicHost)
		allow := zone != "TRANSIT"
		add(resultFor("internet/"+zone, "Ordinary Internet egress", zone, "public HTTPS", "https", expectedOutcome(allow), observation, allow))
	}
	crossZone := []struct {
		name, source, target, protocol string
		allowed                        bool
	}{
		{"trusted-to-servers-tcp", "TRUSTED", "SERVERS", "tcp", true},
		{"servers-to-trusted-tcp", "SERVERS", "TRUSTED", "tcp", false},
		{"mgmt-to-infra-tcp", "MGMT", "INFRA", "tcp", true},
		{"infra-to-trusted-tcp", "INFRA", "TRUSTED", "tcp", false},
		{"sandbox-to-servers-tcp", "SANDBOX", "SERVERS", "tcp", false},
		{"sandbox-to-trusted-tcp", "SANDBOX", "TRUSTED", "tcp", false},
		{"sandbox-to-infra-tcp", "SANDBOX", "INFRA", "tcp", false},
		{"trusted-to-servers-udp", "TRUSTED", "SERVERS", "udp", true},
		{"sandbox-to-servers-udp", "SANDBOX", "SERVERS", "udp", false},
	}
	// Establish target readiness through allowed paths before interpreting a
	// denied connection. A refusal from a stopped listener is not denial
	// evidence.
	for _, item := range crossZone {
		if !item.allowed {
			continue
		}
		port := firewalltest.TCPPort
		if item.protocol == "udp" {
			port = firewalltest.UDPPort
		}
		sourceFixture, targetFixture := byZone[item.source], byZone[item.target]
		observation := runInNamespace(ctx, sourceFixture.namespace, "--"+item.protocol, targetFixture.fixture.zone.Address, strconv.Itoa(port))
		add(resultFor("inter-zone/"+item.name, "Directional inter-zone policy", item.source, item.target, item.protocol, expectedOutcome(item.allowed), observation, item.allowed))
	}
	for _, item := range crossZone {
		if item.allowed {
			continue
		}
		port := firewalltest.TCPPort
		if item.protocol == "udp" {
			port = firewalltest.UDPPort
		}
		sourceFixture, targetFixture := byZone[item.source], byZone[item.target]
		observation := runInNamespace(ctx, sourceFixture.namespace, "--"+item.protocol, targetFixture.fixture.zone.Address, strconv.Itoa(port))
		add(resultFor("inter-zone/"+item.name, "Directional inter-zone policy", item.source, item.target, item.protocol, expectedOutcome(item.allowed), observation, item.allowed))
	}
	for _, zone := range []string{"INFRA", "SERVERS", "TRUSTED", "SANDBOX", "MGMT"} {
		fixture := byZone[zone]
		observation := runInNamespace(ctx, fixture.namespace, "--tcp", request.HomeProxmox, strconv.Itoa(firewalltest.ProxmoxPort))
		add(resultFor("home/proxmox-"+strings.ToLower(zone), "HOME protection", zone, "Proxmox HOME", "tcp", "deny", observation, false))
	}
	sandbox := byZone["SANDBOX"]
	observation := runInNamespace(ctx, sandbox.namespace, "--tcp", request.HomeController, strconv.Itoa(firewalltest.SSHPort))
	add(resultFor("home/sandbox-controller-ssh", "HOME protection", "SANDBOX", "Controller HOME", "tcp", "deny", observation, false))
	for _, zone := range firewalltest.ZoneOrder {
		fixture := byZone[zone]
		observation = runInNamespace(ctx, fixture.namespace, "--tcp", request.ProviderHome, strconv.Itoa(firewalltest.HTTPSPort))
		add(resultFor("admin/"+strings.ToLower(zone)+"-provider-home", "Appliance administration", zone, "firewall HOME", "tcp", "deny", observation, false))
		observation = runInNamespace(ctx, fixture.namespace, "--tcp", fixture.fixture.zone.Gateway, strconv.Itoa(firewalltest.HTTPSPort))
		add(resultFor("admin/"+strings.ToLower(zone)+"-provider-gateway", "Appliance administration", zone, zone+" gateway", "tcp", "deny", observation, false))
	}
	response.OK = response.Error == ""
	return response
}

type fixtureInfo struct {
	fixture   ownedFixture
	namespace string
}

func prepareFixtures(ctx context.Context, zones []firewalltest.Zone) ([]ownedFixture, error) {
	for _, zone := range zones {
		namespace := firewalltest.NamespaceName(zone.Name)
		hostVeth := firewalltest.FixtureName(zone.Name) + "-h"
		if resourceExists(namespace, hostVeth) {
			return nil, fmt.Errorf("reserved firewall test resource %s or %s already exists; run cleanup-only", namespace, hostVeth)
		}
	}
	fixtures := make([]ownedFixture, 0, len(zones))
	for _, zone := range zones {
		fixture := ownedFixture{zone: zone, namespace: firewalltest.NamespaceName(zone.Name), hostVeth: firewalltest.FixtureName(zone.Name) + "-h"}
		if err := native(ctx, "netns", "add", fixture.namespace); err != nil {
			return fixtures, fmt.Errorf("create %s namespace: %w", zone.Name, err)
		}
		fixture.createdNS = true
		fixtures = append(fixtures, fixture)
		if err := native(ctx, "link", "add", fixture.hostVeth, "type", "veth", "peer", "name", "eth0", "netns", fixture.namespace); err != nil {
			return fixtures, fmt.Errorf("create %s veth: %w", zone.Name, err)
		}
		fixtures[len(fixtures)-1].createdVeth = true
		if err := native(ctx, "link", "set", fixture.hostVeth, "master", "vmbr1"); err != nil {
			return fixtures, fmt.Errorf("attach %s veth to vmbr1: %w", zone.Name, err)
		}
		if err := native(ctx, "vlan", "add", "dev", fixture.hostVeth, "vid", strconv.Itoa(zone.VLAN), "pvid", "untagged"); err != nil {
			return fixtures, fmt.Errorf("assign %s VLAN: %w", zone.Name, err)
		}
		if err := native(ctx, "link", "set", fixture.hostVeth, "up"); err != nil {
			return fixtures, fmt.Errorf("enable %s veth: %w", zone.Name, err)
		}
		if err := native(ctx, "netns", "exec", fixture.namespace, "ip", "link", "set", "eth0", "up"); err != nil {
			return fixtures, fmt.Errorf("enable %s namespace link: %w", zone.Name, err)
		}
		address, err := chooseAddress(ctx, fixture.namespace, zone)
		if err != nil {
			return fixtures, err
		}
		fixtures[len(fixtures)-1].zone.Address = address
		if err := native(ctx, "netns", "exec", fixture.namespace, "ip", "address", "add", address+"/24", "dev", "eth0"); err != nil {
			return fixtures, fmt.Errorf("assign %s test address: %w", zone.Name, err)
		}
		if err := native(ctx, "netns", "exec", fixture.namespace, "ip", "route", "replace", "default", "via", zone.Gateway, "dev", "eth0"); err != nil {
			return fixtures, fmt.Errorf("set %s test route: %w", zone.Name, err)
		}
	}
	return fixtures, nil
}

func chooseAddress(ctx context.Context, namespace string, zone firewalltest.Zone) (string, error) {
	candidates, err := firewalltest.CandidateAddresses(zone.Subnet)
	if err != nil {
		return "", fmt.Errorf("choose %s test address: %w", zone.Name, err)
	}
	for _, candidate := range candidates {
		result, runErr := nativeResult(ctx, "netns", "exec", namespace, "arping", "-D", "-I", "eth0", "-c", "2", "-w", "3", candidate)
		if runErr == nil {
			return "", fmt.Errorf("refusing %s test address %s: duplicate address detected", zone.Name, candidate)
		}
		if result.exitCode == 1 && strings.Contains(result.output, "100% packet loss") {
			return candidate, nil
		}
		return "", fmt.Errorf("check %s test address %s: %s", zone.Name, candidate, strings.TrimSpace(result.output))
	}
	return "", fmt.Errorf("no free test address remained in %s .250-.254", zone.Name)
}

func startListeners(ctx context.Context, fixtures []ownedFixture) ([]*exec.Cmd, error) {
	byZone := map[string]ownedFixture{}
	for _, fixture := range fixtures {
		byZone[fixture.zone.Name] = fixture
	}
	listeners := make([]*exec.Cmd, 0, 4)
	for _, item := range []struct {
		zone, protocol string
		port           int
	}{
		{"SERVERS", "tcp", firewalltest.TCPPort},
		{"TRUSTED", "tcp", firewalltest.TCPPort},
		{"INFRA", "tcp", firewalltest.TCPPort},
		{"SERVERS", "udp", firewalltest.UDPPort},
	} {
		fixture, ok := byZone[item.zone]
		if !ok {
			return nil, fmt.Errorf("listener target zone %s is missing", item.zone)
		}
		command, err := startListener(ctx, fixture.namespace, item.protocol, fixture.zone.Address, item.port)
		if err != nil {
			stopListeners(listeners)
			return nil, err
		}
		listeners = append(listeners, command)
	}
	return listeners, nil
}

func startListener(ctx context.Context, namespace, protocol, address string, port int) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve firewall test helper: %w", err)
	}
	command := exec.CommandContext(ctx, nativeTool("ip"), "netns", "exec", namespace, executable, "--listener", protocol, address, strconv.Itoa(port))
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start %s listener: %w", protocol, err)
	}
	ready := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr != nil {
			ready <- readErr
			return
		}
		if strings.TrimSpace(line) != "ready" {
			ready <- errors.New("listener did not report readiness")
			return
		}
		ready <- nil
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, fmt.Errorf("start %s listener: %w", protocol, err)
		}
		return command, nil
	case <-ctx.Done():
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, ctx.Err()
	}
}

func stopListeners(listeners []*exec.Cmd) {
	for _, command := range listeners {
		if command == nil || command.Process == nil {
			continue
		}
		_ = command.Process.Signal(syscall.SIGTERM)
	}
	for _, command := range listeners {
		if command != nil && command.Process != nil {
			_ = command.Wait()
		}
	}
}

func resultFor(name, group, source, target, protocol, expected string, observation probeObservation, allowed bool) firewalltest.Result {
	passed := observation.code == 0
	if !allowed {
		passed = observation.code == 10
	}
	observed := "blocked"
	if observation.code == 0 {
		observed = "reachable"
	} else if observation.code == 12 {
		observed = "execution-error"
	}
	status := "FAIL"
	if passed {
		status = "PASS"
	}
	return firewalltest.Result{Name: name, Group: group, Source: source, Target: target, Protocol: protocol, Expected: expected, Observed: observed, Status: status, Detail: observation.detail}
}

func runInNamespace(ctx context.Context, namespace string, args ...string) probeObservation {
	executable, err := os.Executable()
	if err != nil {
		return probeObservation{code: 12, detail: err.Error()}
	}
	commandArgs := append([]string{"netns", "exec", namespace, executable}, args...)
	result, runErr := nativeResult(ctx, commandArgs...)
	if runErr == nil {
		return probeObservation{code: 0, detail: strings.TrimSpace(result.output)}
	}
	if result.exitCode == 10 {
		return probeObservation{code: 10, detail: strings.TrimSpace(result.output)}
	}
	return probeObservation{code: 12, detail: strings.TrimSpace(result.output)}
}

func runPing(address string) int {
	command := exec.Command(nativeTool("ping"), "-4", "-c", "1", "-W", "1", address)
	if err := command.Run(); err != nil {
		return 10
	}
	return 0
}

func listenerTCP(address, port string) int {
	listener, err := net.Listen("tcp4", net.JoinHostPort(address, port))
	if err != nil {
		return 12
	}
	defer listener.Close()
	fmt.Fprintln(os.Stdout, "ready")
	for {
		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if networkErr, ok := acceptErr.(net.Error); ok && networkErr.Timeout() {
				continue
			}
			return 0
		}
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		data := make([]byte, 64)
		n, readErr := connection.Read(data)
		if readErr == nil && n > 0 {
			_, _ = connection.Write(data[:n])
		}
		_ = connection.Close()
	}
}

func listenerUDP(address, port string) int {
	connection, err := net.ListenPacket("udp4", net.JoinHostPort(address, port))
	if err != nil {
		return 12
	}
	defer connection.Close()
	fmt.Fprintln(os.Stdout, "ready")
	for {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		data := make([]byte, 64)
		n, peer, readErr := connection.ReadFrom(data)
		if readErr != nil {
			if networkErr, ok := readErr.(net.Error); ok && networkErr.Timeout() {
				continue
			}
			return 0
		}
		_, _ = connection.WriteTo(data[:n], peer)
	}
}

func runTCP(address, port string) probeObservation {
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort(address, port), 2*time.Second)
	if err != nil {
		return probeObservation{code: 10, detail: "TCP connection was blocked: " + err.Error()}
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte("boetticher-firewall-test")); err != nil {
		return probeObservation{code: 11, detail: "TCP request failed after connection: " + err.Error()}
	}
	data := make([]byte, 64)
	n, err := connection.Read(data)
	if err != nil || string(data[:n]) != "boetticher-firewall-test" {
		return probeObservation{code: 11, detail: "TCP target did not echo the request"}
	}
	return probeObservation{code: 0, detail: "TCP echo reply received"}
}

func runUDP(address, port string) probeObservation {
	connection, err := net.DialTimeout("udp4", net.JoinHostPort(address, port), 2*time.Second)
	if err != nil {
		return probeObservation{code: 10, detail: "UDP request could not be sent: " + err.Error()}
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte("boetticher-firewall-test")); err != nil {
		return probeObservation{code: 10, detail: "UDP request was blocked: " + err.Error()}
	}
	data := make([]byte, 64)
	n, err := connection.Read(data)
	if err != nil {
		return probeObservation{code: 10, detail: "UDP response was blocked: " + err.Error()}
	}
	if string(data[:n]) != "boetticher-firewall-test" {
		return probeObservation{code: 11, detail: "UDP target returned an unrelated response"}
	}
	return probeObservation{code: 0, detail: "UDP echo reply received"}
}

func runHTTPS(address, hostname string) probeObservation {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(address, "443"))
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest(http.MethodGet, "https://"+hostname+firewalltest.PublicPath, nil)
	if err != nil {
		return probeObservation{code: 12, detail: "create HTTPS request: " + err.Error()}
	}
	response, err := client.Do(request)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "certificate") || strings.Contains(strings.ToLower(err.Error()), "tls") {
			return probeObservation{code: 11, detail: "HTTPS TLS verification failed: " + err.Error()}
		}
		return probeObservation{code: 10, detail: "HTTPS request was blocked: " + err.Error()}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return probeObservation{code: 11, detail: fmt.Sprintf("HTTPS returned HTTP %s", response.Status)}
	}
	return probeObservation{code: 0, detail: fmt.Sprintf("HTTPS returned HTTP %s", response.Status)}
}

func cleanupOnly() firewalltest.Response {
	response := firewalltest.Response{Version: firewalltest.ProtocolVersion, OK: true}
	lock, err := acquireLock()
	if err != nil {
		response.OK = false
		response.Error = err.Error()
		return response
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cleanupOwnedAfterCrash(ctx); err != nil {
		response.OK = false
		response.Error = err.Error()
		return response
	}
	response.CleanupOK = true
	return response
}

func cleanupCreated(ctx context.Context, fixtures []ownedFixture) error {
	stopOwnedListeners(fixtures)
	var cleanupErr error
	for index := len(fixtures) - 1; index >= 0; index-- {
		fixture := fixtures[index]
		if fixture.createdNS && resourcePresent(fixture.namespace) {
			cleanupErr = errors.Join(cleanupErr, native(ctx, "netns", "del", fixture.namespace))
		}
		if fixture.createdVeth && resourcePresent(fixture.hostVeth) {
			cleanupErr = errors.Join(cleanupErr, native(ctx, "link", "del", fixture.hostVeth))
		}
		if resourcePresent(fixture.namespace) || resourcePresent(fixture.hostVeth) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("test resource %s or %s remains", fixture.namespace, fixture.hostVeth))
		}
	}
	return cleanupErr
}

func cleanupOwnedAfterCrash(ctx context.Context) error {
	var cleanupErr error
	for _, zone := range firewalltest.ZoneOrder {
		namespace := firewalltest.NamespaceName(zone)
		hostVeth := firewalltest.FixtureName(zone) + "-h"
		nsPresent, vethPresent := resourcePresent(namespace), resourcePresent(hostVeth)
		if !nsPresent && !vethPresent {
			continue
		}
		if !nsPresent || !vethPresent {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("ownership of reserved resource %s or %s is ambiguous", namespace, hostVeth))
			continue
		}
		zoneIntent := firewalltest.Zone{Name: zone, VLAN: fixedZoneVLAN(zone)}
		owned, err := verifyOwnership(ctx, namespace, hostVeth, zoneIntent)
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		if !owned {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("ownership of reserved resource %s or %s is ambiguous", namespace, hostVeth))
			continue
		}
		stopListenersInNamespace(namespace)
		if err := native(ctx, "netns", "del", namespace); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove %s namespace: %w", namespace, err))
		}
		if resourcePresent(hostVeth) {
			if err := native(ctx, "link", "del", hostVeth); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove %s veth: %w", hostVeth, err))
			}
		}
		if resourcePresent(namespace) || resourcePresent(hostVeth) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("verify cleanup of %s or %s", namespace, hostVeth))
		}
	}
	return cleanupErr
}

func verifyOwnership(ctx context.Context, namespace, hostVeth string, zone firewalltest.Zone) (bool, error) {
	result, err := nativeResult(ctx, "link", "show", hostVeth)
	if err != nil {
		return false, nil
	}
	if !strings.Contains(result.output, "master vmbr1") && !strings.Contains(result.output, "master vmbr1 ") {
		return false, nil
	}
	result, err = nativeResult(ctx, "vlan", "show", "dev", hostVeth)
	if err != nil || !vlanOutputMatches(result.output, zone.VLAN) {
		return false, nil
	}
	result, err = nativeResult(ctx, "netns", "exec", namespace, "ip", "link", "show", "eth0")
	if err != nil || !strings.Contains(result.output, "eth0@if") {
		return false, nil
	}
	result, err = nativeResult(ctx, "netns", "exec", namespace, "ip", "-4", "address", "show", "dev", "eth0")
	if err != nil || !strings.Contains(result.output, ".25") && !strings.Contains(result.output, ".251") && !strings.Contains(result.output, ".252") && !strings.Contains(result.output, ".253") && !strings.Contains(result.output, ".254") {
		return false, nil
	}
	result, err = nativeResult(ctx, "netns", "exec", namespace, "ip", "route", "show", "default")
	if err != nil || !strings.Contains(result.output, "default via") {
		return false, nil
	}
	return true, nil
}

func vlanOutputMatches(output string, vlan int) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for _, field := range fields {
			if field == strconv.Itoa(vlan) {
				return true
			}
		}
	}
	return false
}

func fixedZoneVLAN(name string) int {
	return map[string]int{"TRANSIT": 5, "INFRA": 10, "SERVERS": 20, "TRUSTED": 30, "SANDBOX": 40, "MGMT": 99}[name]
}

func stopOwnedListeners(fixtures []ownedFixture) {
	for _, fixture := range fixtures {
		stopListenersInNamespace(fixture.namespace)
	}
}

func stopListenersInNamespace(namespace string) {
	// The command line and network namespace are both checked before a signal
	// is sent. This is deliberately narrower than killing by process name.
	nsLink, err := os.Readlink("/run/netns/" + namespace)
	if err != nil {
		return
	}
	pids := []int{}
	for _, entry := range numericProcEntries() {
		pid := entry
		cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if err != nil {
			continue
		}
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) < 5 || parts[1] != "--listener" || (parts[2] != "tcp" && parts[2] != "udp") {
			continue
		}
		processNamespace, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/net")
		if err != nil || processNamespace != nsLink {
			continue
		}
		pids = append(pids, pid)
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline := time.Now().Add(2 * time.Second)
	for _, pid := range pids {
		for processPresent(pid) && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
		}
		if processPresent(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func processPresent(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))
	return err == nil
}

func numericProcEntries() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	result := make([]int, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil && pid > 0 {
			result = append(result, pid)
		}
	}
	return result
}

type nativeOutput struct {
	output   string
	exitCode int
}

func native(ctx context.Context, args ...string) error {
	_, err := nativeResult(ctx, args...)
	return err
}

func nativeResult(ctx context.Context, args ...string) (nativeOutput, error) {
	if len(args) == 0 {
		return nativeOutput{}, errors.New("native command is required")
	}
	command := exec.CommandContext(ctx, nativeTool(args[0]), args[1:]...)
	output, err := command.CombinedOutput()
	result := nativeOutput{output: string(output), exitCode: 0}
	if command.ProcessState != nil {
		result.exitCode = command.ProcessState.ExitCode()
	}
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, fmt.Errorf("%s: %s", args[0], strings.TrimSpace(string(output)))
	}
	return result, nil
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

func acquireLock() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(firewalltest.LockPath), 0755); err != nil {
		return nil, fmt.Errorf("create firewall test lock directory: %w", err)
	}
	file, err := os.OpenFile(firewalltest.LockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open firewall test lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another firewall test is already running")
	}
	return file, nil
}

func resourceExists(namespace, hostVeth string) bool {
	return resourcePresent(namespace) || resourcePresent(hostVeth)
}

func resourcePresent(name string) bool {
	if strings.HasPrefix(name, "bt4a-") && strings.Contains(name, "-") {
		if _, err := os.Stat("/run/netns/" + name); err == nil {
			return true
		}
	}
	result, err := nativeResult(context.Background(), "link", "show", name)
	return err == nil && result.exitCode == 0
}

func validAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4()
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

func expectedOutcome(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

func joinDetail(left, right string) string {
	if left == "" {
		return right
	}
	return left + "; " + right
}
