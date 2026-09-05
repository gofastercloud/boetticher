package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ntpProbe requires a real server response carrying our unpredictable origin
// timestamp. A successful UDP send is not proof of DNS/NTP reachability.
func ntpProbe(target string, port int) response {
	if target == "" || !safeTarget(target) || !validPort(port) {
		return response{Error: "invalid NTP target"}
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(target, strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return response{Completed: true, Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	packet := make([]byte, 48)
	packet[0] = 0x23
	if _, err = rand.Read(packet[40:48]); err != nil {
		return response{Error: "NTP nonce unavailable"}
	}
	if _, err = conn.Write(packet); err != nil {
		return response{Completed: true, Error: err.Error()}
	}
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil {
		return response{Completed: true, Error: err.Error()}
	}
	if n < 48 || reply[0]&7 != 4 || reply[1] == 0 || reply[1] > 15 || !bytes.Equal(reply[24:32], packet[40:48]) {
		return response{Completed: true, Error: "invalid or unrelated NTP response"}
	}
	return response{Completed: true, OK: true, Measurements: map[string]string{"stratum": fmt.Sprint(reply[1]), "bytes": fmt.Sprint(n)}}
}
