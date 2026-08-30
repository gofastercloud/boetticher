package main

import (
	"bufio"
	"context"
	"encoding/json"
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
		parsedURL, err := url.Parse(req.URL)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
			return response{Error: "HTTP case requires a URL"}
		}
		args = []string{"--silent", "--show-error", "--max-time", "5", "--connect-timeout", "2", "--output", "/dev/null", "--write-out", "http_code=%{http_code} time=%{time_total}"}
		if req.CA != "" {
			args = append(args, "--cacert", "/run/boetticher-ca.pem")
		}
		if req.Cert != "" && req.Key != "" {
			args = append(args, "--cert", "/run/boetticher-client.pem", "--key", "/run/boetticher-client-key.pem")
		}
		args = append(args, req.URL)
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
		args = []string{"-D", "-I", "eth0", "-c", "2", "-w", "3", req.Target}
	case "configure":
		if net.ParseIP(req.Target) == nil {
			return response{Error: "interface configuration requires an address"}
		}
		args = []string{"addr", "add", req.Target + "/24", "dev", "eth0"}
	case "route":
		if net.ParseIP(req.Target) == nil {
			return response{Error: "route configuration requires a gateway"}
		}
		args = []string{"route", "add", "default", "via", req.Target}
	default:
		return response{Error: "unsupported probe case"}
	}
	tool := map[string]string{"identity": "ip", "ping": "ping", "tcp": "nc", "dns": "dig", "http": "curl", "mtls": "curl", "nmap": "nmap", "iperf-client": "iperf3", "iperf-server": "iperf3", "capture": "tcpdump", "arping": "arping", "configure": "ip", "route": "ip"}[req.Kind]
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
	result := response{OK: err == nil, Output: string(output), ExitCode: exitCode}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func safeTarget(value string) bool {
	return value == "" || !strings.HasPrefix(value, "-") && !strings.ContainsAny(value, " \t\r\n")
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}
