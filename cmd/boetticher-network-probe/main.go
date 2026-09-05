package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const maxRequestBytes = 64 * 1024

type request struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Target  string `json:"target,omitempty"`
	Port    int    `json:"port,omitempty"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	URL     string `json:"url,omitempty"`
	CA      string `json:"ca,omitempty"`
	Cert    string `json:"cert,omitempty"`
	Key     string `json:"key,omitempty"`
	Capture bool   `json:"capture,omitempty"`
}

type response struct {
	Completed    bool              `json:"completed"`
	OK           bool              `json:"ok"`
	ExitCode     int               `json:"exit_code,omitempty"`
	Output       string            `json:"output,omitempty"`
	Measurements map[string]string `json:"measurements,omitempty"`
	Error        string            `json:"error,omitempty"`
}

func main() {
	reader := bufio.NewReader(io.LimitReader(os.Stdin, maxRequestBytes+1))
	data, err := io.ReadAll(reader)
	if err != nil || len(data) > maxRequestBytes {
		write(response{Error: "request is missing or too large"})
		os.Exit(2)
	}
	var req request
	if err := json.Unmarshal(data, &req); err != nil || req.Version != 1 {
		write(response{Error: "unsupported probe request"})
		os.Exit(2)
	}
	result := run(req)
	write(result)
	if !result.OK {
		os.Exit(1)
	}
}

func write(value response) {
	_ = json.NewEncoder(os.Stdout).Encode(value)
}

func run(req request) response {
	if (req.Target != "" && !safeTarget(req.Target)) || strings.ContainsAny(req.URL, "\r\n") || req.Port < 0 || req.Port > 65535 {
		return response{Error: "invalid probe target"}
	}
	args := []string{}
	switch req.Kind {
	case "ntp":
		port := req.Port
		if port == 0 {
			port = 123
		}
		return ntpProbe(req.Target, port)
	case "identity":
		args = []string{"-j", "address", "show"}
	case "ping":
		if req.Target == "" {
			return response{Error: "ping case requires a target"}
		}
		args = []string{"-c", "2", "-W", "1", req.Target}
	case "tcp":
		if req.Target == "" || !validPort(req.Port) {
			return response{Error: "TCP case requires a valid port"}
		}
		args = []string{"-zvw", "2", req.Target, strconv.Itoa(req.Port)}
	case "dns":
		if req.Target == "" || req.Name == "" || !safeTarget(req.Name) || (req.Type != "A" && req.Type != "PTR" && req.Type != "AAAA") {
			return response{Error: "DNS case requires a name and A, AAAA, or PTR type"}
		}
		args = []string{"+time=2", "+tries=1", "@" + req.Target, req.Name, req.Type}
	case "http", "mtls":
		var err error
		args, err = curlArguments(req)
		if err != nil {
			return response{Error: err.Error()}
		}
	case "nmap":
		if req.Target == "" || !validPort(req.Port) {
			return response{Error: "nmap case requires a valid port"}
		}
		args = []string{"-Pn", "-n", "-sT", "--host-timeout", "5s", "--max-retries", "1", "-p", strconv.Itoa(req.Port), req.Target}
	case "iperf-client":
		if req.Target == "" || !validPort(req.Port) {
			return response{Error: "iperf case requires a valid port"}
		}
		args = []string{"-c", req.Target, "-p", strconv.Itoa(req.Port), "-t", "5", "-J"}
		if req.Type == "udp" {
			args = append(args, "-u", "-b", "5M")
		}
	case "iperf-server":
		if !validPort(req.Port) {
			return response{Error: "iperf case requires a valid port"}
		}
		args = []string{"-s", "-1", "-p", strconv.Itoa(req.Port), "-J"}
	case "capture":
		args = []string{"-i", "eth0", "-c", "32", "-nn", "-s", "128"}
		if req.Target != "" {
			args = append(args, "host", req.Target)
		}
	case "arping":
		if req.Target == "" {
			return response{Error: "ARP probe requires a target"}
		}
		args = []string{"-D", "-I", "eth0", "-S", "0.0.0.0", "-c", "2", "-w", "3", req.Target}
	case "arp-peer":
		if net.ParseIP(req.Target).To4() == nil {
			return response{Error: "ARP peer probe requires IPv4"}
		}
		args = []string{"-I", "eth0", "-c", "2", "-w", "3", req.Target}
	case "configure":
		var err error
		args, err = networkConfigurationArguments(req.Kind, req.Target)
		if err != nil {
			return response{Error: err.Error()}
		}
	case "route":
		var err error
		args, err = networkConfigurationArguments(req.Kind, req.Target)
		if err != nil {
			return response{Error: err.Error()}
		}
	default:
		return response{Error: "unsupported probe case"}
	}
	tool := map[string]string{"identity": "ip", "ping": "ping", "tcp": "nc", "dns": "dig", "http": "curl", "mtls": "curl", "nmap": "nmap", "iperf-client": "iperf3", "iperf-server": "iperf3", "capture": "tcpdump", "arping": "arping", "configure": "ip", "route": "ip"}[req.Kind]
	if req.Kind == "arp-peer" {
		tool = "arping"
	}
	if tool == "" {
		return response{Error: "unsupported probe tool"}
	}
	var cleanup []string
	if req.CA != "" {
		cleanup = append(cleanup, "/run/boetticher-ca.pem")
		if err := os.WriteFile("/run/boetticher-ca.pem", []byte(req.CA), 0600); err != nil {
			return response{Error: err.Error()}
		}
	}
	if req.Cert != "" && req.Key != "" {
		cleanup = append(cleanup, "/run/boetticher-client.pem", "/run/boetticher-client-key.pem")
		if err := os.WriteFile("/run/boetticher-client.pem", []byte(req.Cert), 0600); err != nil {
			return response{Error: err.Error()}
		}
		if err := os.WriteFile("/run/boetticher-client-key.pem", []byte(req.Key), 0600); err != nil {
			return response{Error: err.Error()}
		}
	}
	defer func() {
		for _, path := range cleanup {
			_ = os.Remove(path)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, tool, args...)
	output, err := command.CombinedOutput()
	if len(output) > 48*1024 {
		output = append(output[:24*1024], append([]byte("\n[output truncated]\n"), output[len(output)-24*1024:]...)...)
	}
	exitCode := 0
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	ok := commandSucceeded(req.Kind, exitCode, output, err)
	result := response{Completed: command.ProcessState != nil && ctx.Err() == nil, OK: ok, Output: string(output), ExitCode: exitCode}
	if err != nil && !ok {
		result.Error = err.Error()
	}
	if !ok && err == nil {
		switch req.Kind {
		case "arping":
			result.Error = "duplicate address detected"
		case "nmap":
			result.Error = "nmap target port is not open"
		case "dns":
			result.Error = "DNS query returned no answer"
		}
	}
	return result
}

func curlArguments(req request) ([]string, error) {
	parsedURL, err := url.Parse(req.URL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return nil, errors.New("HTTP case requires a URL")
	}
	args := []string{"--silent", "--show-error", "--max-time", "5", "--connect-timeout", "2", "--output", "/dev/null", "--write-out", "http_code=%{http_code} time=%{time_total}"}
	if req.CA != "" {
		args = append(args, "--cacert", "/run/boetticher-ca.pem")
	}
	if req.Cert != "" && req.Key != "" {
		args = append(args, "--cert", "/run/boetticher-client.pem", "--key", "/run/boetticher-client-key.pem")
	}
	if req.Target != "" {
		port := parsedURL.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[parsedURL.Scheme]
		}
		args = append(args, "--resolve", fmt.Sprintf("%s:%s:%s", parsedURL.Hostname(), port, req.Target))
	}
	return append(args, req.URL), nil
}

func networkConfigurationArguments(kind, target string) ([]string, error) {
	if net.ParseIP(target) == nil {
		if kind == "configure" {
			return nil, errors.New("interface configuration requires an address")
		}
		return nil, errors.New("route configuration requires a gateway")
	}
	if kind == "configure" {
		return []string{"addr", "replace", target + "/24", "dev", "eth0"}, nil
	}
	if kind == "route" {
		return []string{"route", "replace", "default", "via", target}, nil
	}
	return nil, errors.New("unsupported network configuration")
}

func commandSucceeded(kind string, exitCode int, output []byte, err error) bool {
	if kind == "http" {
		if err != nil {
			return false
		}
		for _, field := range strings.Fields(string(output)) {
			if strings.HasPrefix(field, "http_code=") {
				code, e := strconv.Atoi(strings.TrimPrefix(field, "http_code="))
				return e == nil && code >= 200 && code < 300
			}
		}
		return false
	}
	if kind == "arping" {
		// arping -D returns 1 when no peer answers, which is the successful
		// duplicate-address check result for a candidate address. A reply
		// returns 0 and must fail the check.
		return err != nil && exitCode == 1 && strings.Contains(string(output), "100% packet loss")
	}
	if kind == "nmap" {
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "open" {
				return true
			}
		}
		return false
	}
	if kind == "dns" {
		return err == nil && dnsAnswerSucceeded(output)
	}
	return err == nil
}

func dnsAnswerSucceeded(output []byte) bool {
	statusOK := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "status: NOERROR") {
			statusOK = true
		}
		fields := strings.Fields(line)
		for index, field := range fields {
			if field != "ANSWER:" || index+1 >= len(fields) {
				continue
			}
			answers, parseErr := strconv.Atoi(strings.TrimSuffix(fields[index+1], ","))
			return statusOK && parseErr == nil && answers > 0
		}
	}
	return false
}

func safeTarget(value string) bool {
	return value == "" || !strings.HasPrefix(value, "-") && !strings.ContainsAny(value, " \t\r\n")
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}
