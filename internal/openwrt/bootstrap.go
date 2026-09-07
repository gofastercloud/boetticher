package openwrt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"
)

// CaptureLeafCertificate is a bootstrap-only trust capture. It is intentionally
// separate from NewClient: normal management always uses the stored PEM as a
// verified trust root and never enables insecure certificate verification.
func CaptureLeafCertificate(ctx context.Context, address string) ([]byte, error) {
	if net.ParseIP(address) == nil || net.ParseIP(address).To4() == nil {
		return nil, errors.New("provider management address must be an IPv4 address")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(address, "443"), &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) // #nosec G402 -- bootstrap captures the fresh provider leaf before pinning it.
	if err != nil {
		return nil, fmt.Errorf("capture provider TLS certificate: %w", err)
	}
	defer connection.Close()
	if err := connection.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("complete provider TLS bootstrap: %w", err)
	}
	state := connection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("provider TLS bootstrap returned no certificate")
	}
	if _, err := x509.ParseCertificate(state.PeerCertificates[0].Raw); err != nil {
		return nil, errors.New("provider TLS bootstrap returned an invalid certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: state.PeerCertificates[0].Raw}), nil
}
