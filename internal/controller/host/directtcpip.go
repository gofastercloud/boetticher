package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	LabHostAddress     = "10.10.99.5"
	FirewallLabAddress = "10.10.99.1:443"
)

// DialFirewallViaLabHost opens one bounded SSH direct-tcpip channel through
// the enrolled LAB Host. Both endpoints are fixed product bindings.
func DialFirewallViaLabHost(ctx context.Context, transport Transport) (net.Conn, error) {
	if transport.Address != LabHostAddress || transport.User != "root" {
		return nil, errors.New("LAB firewall route requires the enrolled root Host at 10.10.99.5")
	}
	if transport.Identity == "" || transport.KnownHosts == "" {
		return nil, errors.New("LAB firewall route requires the enrolled SSH identity and known-hosts")
	}
	if err := validateSSHMaterial(transport.Identity, transport.KnownHosts); err != nil {
		return nil, err
	}
	private, err := os.ReadFile(transport.Identity)
	if err != nil {
		return nil, fmt.Errorf("read Host identity: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("Host identity must be an Ed25519 private key")
	}
	hostKey, err := knownhosts.New(transport.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("load Host known-hosts: %w", err)
	}
	config := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: hostKey, HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, Timeout: 10 * time.Second}
	tcp, err := directTCPDial(ctx, net.JoinHostPort(transport.Address, "22"))
	if err != nil {
		return nil, fmt.Errorf("connect enrolled LAB Host: %w", err)
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = tcp.SetDeadline(deadline)
	}
	setupDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = tcp.Close()
		case <-setupDone:
		}
	}()
	cc, chans, reqs, err := ssh.NewClientConn(tcp, net.JoinHostPort(transport.Address, "22"), config)
	if err != nil {
		close(setupDone)
		_ = tcp.Close()
		return nil, fmt.Errorf("authenticate enrolled LAB Host: %w", err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	payload := struct {
		Raddr string
		Rport uint32
		Laddr string
		Lport uint32
	}{Raddr: "10.10.99.1", Rport: 443}
	channel, requests, err := client.OpenChannel("direct-tcpip", ssh.Marshal(&payload))
	close(setupDone)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("open fixed firewall direct-tcpip channel: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	go ssh.DiscardRequests(requests)
	return &directConn{Conn: channelConn{Channel: channel}, client: client}, nil
}

var directTCPDial = func(ctx context.Context, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}

// FirewallDialContext adapts the fixed route to http.Transport.DialContext.
// The network and address arguments are validated on every request so a
// caller cannot turn this into a general proxy.
func FirewallDialContext(transport Transport) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != FirewallLabAddress {
			return nil, errors.New("LAB firewall route target is fixed to 10.10.99.1:443")
		}
		return DialFirewallViaLabHost(ctx, transport)
	}
}

type directConn struct {
	net.Conn
	client *ssh.Client
	once   sync.Once
	err    error
}

type channelConn struct{ ssh.Channel }

func (channelConn) LocalAddr() net.Addr  { return fixedAddr("lab-host") }
func (channelConn) RemoteAddr() net.Addr { return fixedAddr(FirewallLabAddress) }
func (channelConn) SetDeadline(time.Time) error {
	return errors.New("SSH direct-tcpip channel does not support deadlines")
}
func (channelConn) SetReadDeadline(time.Time) error {
	return errors.New("SSH direct-tcpip channel does not support read deadlines")
}
func (channelConn) SetWriteDeadline(time.Time) error {
	return errors.New("SSH direct-tcpip channel does not support write deadlines")
}

type fixedAddr string

func (a fixedAddr) Network() string { return "tcp" }
func (a fixedAddr) String() string  { return string(a) }

func (c *directConn) Close() error {
	c.once.Do(func() {
		channelErr := c.Conn.Close()
		clientErr := c.client.Close()
		if channelErr != nil {
			c.err = channelErr
		} else {
			c.err = clientErr
		}
	})
	return c.err
}

func validateSSHMaterial(identity, known string) error {
	for _, path := range []string{identity, known} {
		if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
			return fmt.Errorf("validate SSH path: %w", err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || (path == identity && info.Mode().Perm()&0077 != 0) {
			return errors.New("SSH identity and known-hosts must be regular files")
		}
	}
	return nil
}
