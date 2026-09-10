package companion

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

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
	for _, address := range []string{c.Address, c.Gateway, c.DNS, c.DNSAddress} {
		if net.ParseIP(address) == nil {
			return c, errors.New("invalid companion address")
		}
	}
	if _, err := net.ParseMAC(c.EthernetMAC); err != nil {
		return c, err
	}
	if c.DNSName == "" {
		return c, errors.New("incomplete companion configuration")
	}
	return c, nil
}

// Collector observes only local Controller health and the wired lab path.
// The Companion collector is local-only; the live lab's monitoring owner is
// the unified Victoria/Grafana/Gatus observability guest.
type Collector struct {
	Config Config
	State  *State
}

func NewCollector(c Config, s *State, _ string) (*Collector, error) {
	if s == nil {
		return nil, errors.New("companion state is required")
	}
	return &Collector{Config: c, State: s}, nil
}

func (c *Collector) Run(ctx context.Context) {
	run := func(interval time.Duration, fn func(context.Context)) {
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
				}
			}
		}()
	}
	run(2*time.Second, c.local)
	run(5*time.Second, c.network)
}

func (c *Collector) local(_ context.Context) {
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
		c.unavailableNetwork(now)
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

// Query the configured DNS server directly so /etc/hosts cannot mask an outage.
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
