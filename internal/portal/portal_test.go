package portal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	networkmodel "github.com/gofastercloud/boetticher/internal/network"
)

func TestExternalPortalDoesNotPublishManagedGatewayOrBackupID(t *testing.T) {
	dir := t.TempDir()
	site := model.NewSite("installation", "age1example", model.GatewayModeExternal)
	if err := Build(site, filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	networkPage, err := os.ReadFile(filepath.Join(dir, "portal", "network.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(networkPage), "managed gateway vNICs") || strings.Contains(string(networkPage), "Debian lab-fw-01") {
		t.Fatal("external portal published managed gateway details")
	}
	recoveryPage, err := os.ReadFile(filepath.Join(dir, "portal", "recovery.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(recoveryPage), "100, 110") {
		t.Fatal("external portal published the absent firewall VMID")
	}
}

func TestManagedPortalPublishesGatewayDetails(t *testing.T) {
	dir := t.TempDir()
	site := model.NewDefaultSite("installation", "age1example")
	if err := Build(site, filepath.Join(dir, "portal"), "", Evidence{}, networkmodel.Discovery{Mode: model.ModeVirtualOnly}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	networkPage, err := os.ReadFile(filepath.Join(dir, "portal", "network.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(networkPage), "managed gateway vNICs") {
		t.Fatal("managed portal omitted gateway vNIC details")
	}
}
