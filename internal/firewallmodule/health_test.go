package firewallmodule

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestGatewayCountAndFirewallHealthAreCoarseAndTruthful(t *testing.T) {
	desired, err := DesiredFromSite(model.NewSite("installation", "age1example", model.GatewayModeManaged))
	if err != nil {
		t.Fatal(err)
	}
	runtime := json.RawMessage(`{"interface":[{"interface":"boetticher_iface_transit","up":true,"ipv4-address":[{"address":"10.10.5.1","mask":24}]},{"interface":"boetticher_iface_infra","up":true,"ipv4-address":[{"address":"10.10.10.1","mask":24}]},{"interface":"boetticher_iface_servers","up":true,"ipv4-address":[{"address":"10.10.20.1","mask":24}]},{"interface":"boetticher_iface_trusted","up":true,"ipv4-address":[{"address":"10.10.30.1","mask":24}]},{"interface":"boetticher_iface_sandbox","up":true,"ipv4-address":[{"address":"10.10.40.1","mask":24}]},{"interface":"boetticher_iface_mgmt","up":true,"ipv4-address":[{"address":"10.10.99.1","mask":24}]}]}`)
	if got := GatewayCount(runtime, desired); got != 6 {
		t.Fatalf("gateway count = %d, want 6", got)
	}
	health := FirewallHealth{Provider: Status{Exists: true, Running: true, OwnershipProven: true, NetworkShapeOK: true, StorageIdentity: true}, APIReachable: true, GatewaysPresent: 6, GatewaysExpected: 6, FirewallActive: true, HOMEDefaultRoute: true}
	if !health.Healthy() {
		t.Fatalf("healthy facts were rejected: %s", health.Detail())
	}
	health.HOMEDefaultRoute = false
	if health.Healthy() {
		t.Fatal("missing HOME route was reported healthy")
	}
}

func TestNormalizeProviderCertificateAcceptsNativeDERAndPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "192.168.4.28"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})} {
		trust, err := normalizeProviderCertificate(input)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(trust)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("normalized trust is not PEM certificate: %q", trust)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := normalizeProviderCertificate([]byte("not a certificate")); err == nil {
		t.Fatal("invalid provider certificate was accepted")
	}
}
