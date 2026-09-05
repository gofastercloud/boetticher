package companion

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

func LoadConfig(path string) (Config, error) {
	var c Config
	file, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer file.Close()
	dec := json.NewDecoder(io.LimitReader(file, 16<<10))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, err
	}
	var tail any
	if dec.Decode(&tail) != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	u, err := url.Parse(c.PulseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return c, errors.New("Pulse URL must be an HTTPS origin")
	}
	for _, address := range []string{c.Address, c.Gateway, c.DNS, c.DNSAddress} {
		if net.ParseIP(address) == nil {
			return c, errors.New("invalid companion address")
		}
	}
	if _, err := net.ParseMAC(c.EthernetMAC); err != nil {
		return c, err
	}
	if c.CAFile == "" || c.DNSName == "" || c.AgentID == "" || c.AgentHostname == "" {
		return c, errors.New("incomplete companion configuration")
	}
	return c, nil
}

type Collector struct {
	Config Config
	State  *State
	HTTP   *http.Client
	token  string
}

func NewCollector(c Config, s *State, token string) (*Collector, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("missing Companion read credential")
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid private CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &Collector{Config: c, State: s, token: strings.TrimSpace(token), HTTP: &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Collector) Run(ctx context.Context) {
	run := func(interval time.Duration, refresh <-chan struct{}, fn func(context.Context)) {
		go func() {
			timer := time.NewTicker(interval)
			defer timer.Stop()
			for {
				bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
				fn(bounded)
				cancel()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				case <-refresh:
				}
			}
		}()
	}
	run(2*time.Second, nil, c.local)
	run(5*time.Second, nil, c.network)
	run(5*time.Second, c.State.Refresh, c.remote)
}
func (c *Collector) local(ctx context.Context) {
	now := time.Now().UTC()
	item := Item{ID: "pi", Status: Healthy, ObservedAt: now}
	data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		item.Status = Waiting
		item.Reason = "Temperature sensor unavailable"
		c.State.Update(item)
		return
	}
	temp, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		item.Status = Waiting
		item.Reason = "Temperature sensor unreadable"
		c.State.Update(item)
		return
	}
	temp /= 1000
	memory, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	var total, available float64
	for _, line := range strings.Split(string(memory), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseFloat(fields[1], 64)
		switch fields[0] {
		case "MemTotal:":
			total = value
		case "MemAvailable:":
			available = value
		}
	}
	var disk unix.Statfs_t
	if err = unix.Statfs("/", &disk); err != nil || total <= 0 || disk.Blocks == 0 {
		return
	}
	mem := 100 * (1 - available/total)
	used := 100 * (1 - float64(disk.Bavail)/float64(disk.Blocks))
	item.Value = fmt.Sprintf("%.0f°C", temp)
	item.Reason = fmt.Sprintf("Memory %.0f%% · disk %.0f%% used", mem, used)
	if temp >= 75 || mem >= 90 || used >= 90 {
		item.Status = Warning
	}
	if temp >= 85 || mem >= 97 || used >= 97 {
		item.Status = Failure
	}
	c.State.Update(item)
	if !c.Config.PulseAgent {
		return
	}
	// Delivery is evaluated independently from process liveness below.
	if err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "pulse-agent.service").Run(); err != nil {
		c.State.Update(Item{ID: "agent", Status: Failure, Reason: "Pulse agent service is not active", ObservedAt: now})
	}
}
func (c *Collector) labInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		if strings.EqualFold(iface.HardwareAddr.String(), c.Config.EthernetMAC) {
			return iface.Name, nil
		}
	}
	return "", errors.New("configured Ethernet MAC is absent")
}
func (c *Collector) network(ctx context.Context) {
	now := time.Now().UTC()
	link := Item{ID: "link", Status: Failure, ObservedAt: now, Reason: "Configured Ethernet interface is absent"}
	iface, err := c.labInterface()
	if err != nil {
		c.State.Update(link)
		return
	}
	carrier, _ := os.ReadFile("/sys/class/net/" + iface + "/carrier")
	link.Reason = "Ethernet has no carrier"
	if strings.TrimSpace(string(carrier)) != "1" {
		c.State.Update(link)
		c.unavailableNetwork(now)
		return
	}
	link.Reason = "Ethernet has carrier but no expected lab address/route"
	route, err := exec.CommandContext(ctx, "ip", "-j", "route", "get", c.Config.DNS).Output()
	var routes []struct {
		Dev        string `json:"dev"`
		PrefSource string `json:"prefsrc"`
		Gateway    string `json:"gateway"`
	}
	if err != nil || json.Unmarshal(route, &routes) != nil || len(routes) != 1 || routes[0].Dev != iface || routes[0].PrefSource != c.Config.Address || routes[0].Gateway != c.Config.Gateway {
		c.State.Update(link)
		c.unavailableNetwork(now)
		return
	}
	link.Status = Healthy
	link.Value = iface
	link.Reason = c.Config.Address + " via " + c.Config.Gateway
	c.State.Update(link)
	gateway := Item{ID: "gateway", Status: Healthy, Value: c.Config.Gateway, ObservedAt: now, Reason: "Gateway responds on the lab interface"}
	if exec.CommandContext(ctx, "ping", "-n", "-c", "1", "-W", "2", "-I", iface, c.Config.Gateway).Run() != nil {
		gateway.Status = Failure
		gateway.Reason = "No gateway response on the lab interface"
	}
	c.State.Update(gateway)
	dns := Item{ID: "dns", Status: Failure, ObservedAt: now, Reason: "Lab DNS did not return the expected service address"}
	if verifyDNS(ctx, net.JoinHostPort(c.Config.DNS, "53"), c.Config.DNSName, c.Config.DNSAddress) == nil {
		dns.Status = Healthy
		dns.Value = "Responding"
		dns.Reason = c.Config.DNSName + " resolves correctly"
	}
	c.State.Update(dns)
}
func (c *Collector) unavailableNetwork(now time.Time) {
	for _, id := range []string{"gateway", "dns"} {
		c.State.Update(Item{ID: id, Status: Waiting, Reason: "Waiting for the wired lab connection", ObservedAt: now})
	}
}
func (c *Collector) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.Config.PulseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Token", c.token)
	response, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("Pulse connection failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("Pulse HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("Pulse response too large")
	}
	return json.Unmarshal(data, out)
}

type pulseResource struct {
	ID           string                     `json:"id"`
	Name         string                     `json:"name"`
	Type         string                     `json:"type"`
	Technology   string                     `json:"technology"`
	PlatformType string                     `json:"platformType"`
	Status       string                     `json:"status"`
	Source       string                     `json:"source"`
	Sources      []string                   `json:"sources"`
	LastSeen     time.Time                  `json:"lastSeen"`
	Metrics      map[string]json.RawMessage `json:"metrics"`
	Agent        *struct {
		AgentID      string    `json:"agentId"`
		Hostname     string    `json:"hostname"`
		LastReportAt time.Time `json:"lastReportAt"`
		Stale        bool      `json:"stale"`
		Sensors      *struct {
			Custom []customSensor `json:"custom"`
		} `json:"sensors"`
	} `json:"agent"`
}

type customSensor struct {
	ID         string    `json:"id"`
	Value      *float64  `json:"value"`
	Status     string    `json:"status"`
	ObservedAt time.Time `json:"observedAt"`
	Stale      bool      `json:"stale"`
	Error      string    `json:"error"`
}

func source(r pulseResource, wanted string) bool {
	if r.Source == wanted {
		return true
	}
	for _, s := range r.Sources {
		if s == wanted {
			return true
		}
	}
	return false
}
func normalizedStatus(value string) string {
	switch strings.ToLower(value) {
	case "online", "up", "running", "healthy", "ok":
		return Healthy
	case "warning", "degraded":
		return Warning
	case "offline", "down", "stopped", "critical", "error":
		return Failure
	default:
		return Waiting
	}
}
func percent(raw json.RawMessage) *float64 {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	var value float64
	if json.Unmarshal(raw, &value) != nil {
		var wrapped struct {
			Percent *float64 `json:"percent"`
			Value   *float64 `json:"value"`
			Unit    string   `json:"unit"`
		}
		if json.Unmarshal(raw, &wrapped) != nil {
			return nil
		}
		if wrapped.Percent != nil {
			value = *wrapped.Percent
		} else if wrapped.Value != nil && wrapped.Unit == "percent" {
			value = *wrapped.Value
		} else {
			return nil
		}
	}
	if value < 0 || value > 100 {
		return nil
	}
	return &value
}
func (c *Collector) remote(ctx context.Context) {
	now := time.Now().UTC()
	var health struct {
		Status string `json:"status"`
	}
	var summary struct {
		LastUpdate time.Time `json:"lastUpdate"`
	}
	if err := c.get(ctx, "/api/health", &health); err != nil {
		c.remoteUnavailable(now, err.Error())
		return
	}
	if err := c.get(ctx, "/api/state/summary", &summary); err != nil {
		c.remoteUnavailable(now, err.Error())
		return
	}
	c.State.Update(Item{ID: "pulse", Status: normalizedStatus(health.Status), Value: health.Status, Reason: "Authenticated private-CA connection", ObservedAt: summary.LastUpdate})
	all := []pulseResource{}
	for page := 1; page <= 4; page++ {
		var result struct {
			Data      []pulseResource `json:"data"`
			Resources []pulseResource `json:"resources"`
		}
		if err := c.get(ctx, fmt.Sprintf("/api/resources?limit=100&page=%d&sort=name&order=asc", page), &result); err != nil {
			c.remoteUnavailable(now, err.Error())
			return
		}
		items := result.Resources
		if items == nil {
			items = result.Data
		}
		all = append(all, items...)
		if len(items) < 100 {
			break
		}
	}
	resources := []Resource{}
	nodes := []pulseResource{}
	agents := []pulseResource{}
	for _, r := range all {
		if proxmoxResource(r) {
			at := r.LastSeen
			if at.IsZero() || summary.LastUpdate.Before(at) {
				at = summary.LastUpdate
			}
			resources = append(resources, Resource{ID: r.ID, Name: r.Name, Type: r.Type, Status: normalizedStatus(r.Status), CPU: percent(r.Metrics["cpu"]), Memory: percent(r.Metrics["memory"]), ObservedAt: at})
			if r.Type == "node" || r.Type == "host" || r.Type == "pve" || r.Type == "agent" && (r.Technology == "proxmox" || r.PlatformType == "proxmox") {
				nodes = append(nodes, r)
			}
		}
		if source(r, "agent") && (r.ID == c.Config.AgentID || r.ID == "agent:"+c.Config.AgentID || r.Name == c.Config.AgentHostname || r.Agent != nil && (r.Agent.AgentID == c.Config.AgentID || r.Agent.Hostname == c.Config.AgentHostname)) {
			if r.Agent != nil {
				r.LastSeen = r.Agent.LastReportAt
				if r.Agent.Stale {
					r.LastSeen = time.Time{}
				}
			}
			agents = append(agents, r)
		}
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].Name < resources[j].Name })
	c.State.SetResources(resources)
	c.vpnMetrics(ctx, all)
	node := Item{ID: "proxmox", Status: Waiting, Reason: "Waiting for one unambiguous Proxmox host in Pulse", ObservedAt: summary.LastUpdate}
	if len(nodes) == 1 {
		node.Status = normalizedStatus(nodes[0].Status)
		node.Value = nodes[0].Name
		node.Reason = "Proxmox host reported by Pulse"
		if !nodes[0].LastSeen.IsZero() && nodes[0].LastSeen.Before(node.ObservedAt) {
			node.ObservedAt = nodes[0].LastSeen
		}
	}
	c.State.Update(node)
	if c.Config.PulseAgent {
		agent := Item{ID: "agent", Status: Waiting, Reason: "Waiting for fresh Companion telemetry in Pulse", ObservedAt: now}
		if len(agents) == 1 && fresh(agents[0].LastSeen, now) {
			agent.Status = normalizedStatus(agents[0].Status)
			agent.ObservedAt = agents[0].LastSeen
			agent.Value = "Reporting"
			agent.Reason = "Companion telemetry received by Pulse"
		}
		if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "pulse-agent.service").Run() != nil {
			agent.Status = Failure
			agent.Reason = "Pulse agent service is inactive"
		}
		c.State.Update(agent)
	}
}

func proxmoxResource(r pulseResource) bool {
	return source(r, "proxmox") || source(r, "pve") || r.Type == "agent" && (r.Technology == "proxmox" || r.PlatformType == "proxmox")
}

// Query the configured DNS server directly. net.Resolver.LookupHost can
// satisfy the request from /etc/hosts, masking an actual DNS outage.
func verifyDNS(ctx context.Context, server, name, expected string) error {
	var nonce [2]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := binary.BigEndian.Uint16(nonce[:])
	questionName, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return err
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: questionName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		return err
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp", server)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err = conn.Write(wire); err != nil {
		return err
	}
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}
	var answer dnsmessage.Message
	if err = answer.Unpack(buffer[:n]); err != nil {
		return err
	}
	if answer.ID != id || !answer.Response || answer.Truncated || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Questions) != 1 || answer.Questions[0] != query.Questions[0] {
		return errors.New("invalid DNS answer")
	}
	for _, resource := range answer.Answers {
		if record, ok := resource.Body.(*dnsmessage.AResource); ok && net.IP(record.A[:]).Equal(net.ParseIP(expected)) {
			return nil
		}
	}
	return errors.New("DNS answer lacks the expected address")
}
func (c *Collector) remoteUnavailable(now time.Time, reason string) {
	for _, id := range []string{"pulse", "proxmox", "agent"} {
		if id == "agent" && !c.Config.PulseAgent {
			continue
		}
		c.State.Update(Item{ID: id, Status: Waiting, Reason: reason, ObservedAt: now})
	}
	for _, module := range c.State.Snapshot().Modules {
		if module.Status != Disabled {
			c.State.Update(Item{ID: module.ID, Status: Waiting, Reason: reason, ObservedAt: now})
		}
	}
}

func (c *Collector) vpnMetrics(ctx context.Context, resources []pulseResource) {
	for _, module := range []struct {
		id, hostname string
		enabled      bool
	}{{"airvpn", "lab-airvpn-01", c.Config.AirVPN}, {"tailnet-router", "lab-tailnet-01", c.Config.Tailnet}} {
		if !module.enabled {
			continue
		}
		item := Item{ID: module.id, Status: Waiting, Reason: "Waiting for module-local sensors in Pulse", ObservedAt: time.Now().UTC()}
		matches := []pulseResource{}
		for _, resource := range resources {
			if source(resource, "agent") && (resource.Name == module.hostname || resource.Agent != nil && resource.Agent.Hostname == module.hostname) {
				matches = append(matches, resource)
			}
		}
		if len(matches) != 1 {
			c.State.Update(item)
			continue
		}
		resource := matches[0]
		if resource.Agent == nil || resource.Agent.Sensors == nil {
			if resource.ID == "" || c.get(ctx, "/api/resources/"+url.PathEscape(resource.ID), &resource) != nil {
				c.State.Update(item)
				continue
			}
		}
		if resource.Agent == nil || resource.Agent.Stale || !fresh(resource.Agent.LastReportAt, time.Now()) || resource.Agent.Sensors == nil {
			c.State.Update(item)
			continue
		}
		item = moduleSensorStatus(module.id, resource.Agent.Sensors.Custom, time.Now())
		c.State.Update(item)
	}
}

func moduleSensorStatus(module string, sensors []customSensor, now time.Time) Item {
	item := Item{ID: module, Status: Healthy, Value: "Healthy", Reason: "Module-local checks reported by Pulse", ObservedAt: now}
	for _, check := range model.VPNHealthChecks(true, true) {
		if check.Module != module {
			continue
		}
		entry := Item{ID: check.ID, Label: check.Name, Status: Waiting, Value: "No data", Reason: "Waiting for fresh Pulse sensor data"}
		var found *customSensor
		duplicates := false
		for i, sensor := range sensors {
			if sensor.ID == check.ID {
				if found != nil {
					duplicates = true
				}
				found = &sensors[i]
			}
		}
		if found != nil && !duplicates {
			entry.ObservedAt = found.ObservedAt
			if !found.Stale && found.Error == "" && fresh(found.ObservedAt, now) && found.Value != nil {
				if *found.Value == 1 && (found.Status == "ok" || found.Status == "normal" || found.Status == "healthy") {
					entry.Status = Healthy
					entry.Value = "OK"
					entry.Reason = "Local check passed"
				} else {
					entry.Status = Failure
					entry.Value = "Failed"
					entry.Reason = "Local check failed; inspect the module in Pulse"
				}
			}
		}
		item.Checks = append(item.Checks, entry)
		if entry.Status != Healthy {
			item.Value = "Attention"
			if entry.Status == Failure {
				item.Status = Failure
			} else if item.Status != Failure {
				item.Status = Waiting
			}
		}
	}
	if item.Status != Healthy {
		names := []string{}
		for _, check := range item.Checks {
			if check.Status != Healthy {
				names = append(names, check.Label)
			}
		}
		item.Reason = "Check " + strings.Join(names, ", ")
	}
	return item
}
