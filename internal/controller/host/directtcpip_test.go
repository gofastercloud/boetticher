package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/openwrt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestFirewallDialContextRejectsNonFixedTargetsBeforeSSH(t *testing.T) {
	dial := FirewallDialContext(Transport{Address: LabHostAddress, User: "root"})
	if _, err := dial(context.Background(), "tcp", "192.168.4.28:443"); err == nil {
		t.Fatal("accepted non-fixed target")
	}
}

// This is a real TCP, SSH direct-tcpip, TLS, and HTTP path, not a mock.
func TestFirewallDialContextUsesStrictSSHAndPinnedTLS(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ubus" {
			t.Errorf("path=%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"test-session"}]}`)
	}))
	defer tlsServer.Close()
	transport, listener, stop := testSSHForwarder(t, tlsServer.Listener.Addr().String(), false)
	defer stop()
	old := directTCPDial
	directTCPDial = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener)
	}
	defer func() { directTCPDial = old }()

	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client, err := openwrt.NewClient(openwrt.Config{BaseURL: "https://" + FirewallLabAddress, Username: "boetticher", Password: "test", TrustPEM: trust, ServerName: "example.com", DialContext: FirewallDialContext(transport)})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatalf("pinned TLS tunnel: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close idle SSH tunnel: %v", err)
	}
	wrongTrust := unrelatedTrust(t)
	wrongClient, err := openwrt.NewClient(openwrt.Config{BaseURL: "https://" + FirewallLabAddress, Username: "boetticher", Password: "test", TrustPEM: wrongTrust, ServerName: "example.com", DialContext: FirewallDialContext(transport)})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongClient.Authenticate(context.Background()); err == nil {
		t.Fatal("wrong TLS pin authenticated")
	}

	badKnown := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(badKnown, []byte("[10.10.99.5]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), 0600); err != nil {
		t.Fatal(err)
	}
	badTransport := transport
	badTransport.KnownHosts = badKnown
	if _, err := DialFirewallViaLabHost(context.Background(), badTransport); err == nil {
		t.Fatal("wrong SSH host key accepted")
	}
}

func TestFirewallDialContextBoundsBlockedHTTPSAndClientCloseReleasesTunnel(t *testing.T) {
	release := make(chan struct{})
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer tlsServer.Close()
	transport, listener, stop := testSSHForwarder(t, tlsServer.Listener.Addr().String(), false)
	old := directTCPDial
	directTCPDial = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener)
	}
	defer func() { directTCPDial = old; close(release); stop() }()
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	client, err := openwrt.NewClient(openwrt.Config{BaseURL: "https://" + FirewallLabAddress, Username: "boetticher", Password: "test", TrustPEM: trust, ServerName: "example.com", DialContext: FirewallDialContext(transport)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := client.Authenticate(ctx); err == nil {
		t.Fatal("blocked HTTPS request succeeded")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDialFirewallViaLabHostCancelsStalledChannelOpen(t *testing.T) {
	transport, listener, stop := testSSHForwarder(t, "", true)
	defer stop()
	old := directTCPDial
	directTCPDial = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener)
	}
	defer func() { directTCPDial = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := DialFirewallViaLabHost(ctx, transport); err == nil {
		t.Fatal("stalled direct-tcpip channel open succeeded")
	} else if time.Since(started) > time.Second {
		t.Fatalf("stalled channel did not cancel promptly: %v", time.Since(started))
	}
}

func unrelatedTrust(t *testing.T) []byte {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testSSHForwarder(t *testing.T, target string, stall bool) (Transport, string, func()) {
	t.Helper()
	_, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverSigner, err := ssh.NewSignerFromKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	server := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(clientSigner.PublicKey()) {
			return nil, fmt.Errorf("unexpected client key")
		}
		return nil, nil
	}}
	server.AddHostKey(serverSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	identity, known := filepath.Join(dir, "id_ed25519"), filepath.Join(dir, "known_hosts")
	private, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(known, []byte(knownhosts.Line([]string{"[10.10.99.5]:22"}, serverSigner.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); serveSSHForward(conn, server, target, stall) }()
		}
	}()
	return Transport{Address: LabHostAddress, User: "root", Identity: identity, KnownHosts: known}, listener.Addr().String(), func() { _ = listener.Close(); wg.Wait() }
}

func serveSSHForward(conn net.Conn, config *ssh.ServerConfig, target string, stall bool) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "direct-tcpip required")
			continue
		}
		if stall {
			continue
		}
		var payload struct {
			Raddr string
			Rport uint32
			Laddr string
			Lport uint32
		}
		if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil || payload.Raddr != "10.10.99.1" || payload.Rport != 443 {
			_ = newChannel.Reject(ssh.Prohibited, "fixed target required")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(requests)
		dst, err := net.DialTimeout("tcp", target, time.Second)
		if err != nil {
			_ = channel.Close()
			continue
		}
		go func() { _, _ = io.Copy(dst, channel); _ = dst.Close() }()
		go func() { _, _ = io.Copy(channel, dst); _ = channel.Close() }()
	}
}
