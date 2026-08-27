package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func TestGuestConfigMACsAcceptQEMUAndLXCNetworkSyntax(t *testing.T) {
	macs, err := guestConfigMACs(map[string]any{
		"net0": "virtio=02:00:00:00:02:61,bridge=vmbr1,tag=20",
	})
	if err != nil || len(macs) != 1 || macs[0] != "02:00:00:00:02:61" {
		t.Fatalf("QEMU network MACs = %#v, %v", macs, err)
	}
	macs, err = guestConfigMACs(map[string]any{
		"net0": "name=eth0,bridge=vmbr1,hwaddr=02:00:00:00:02:62",
	})
	if err != nil || len(macs) != 1 || macs[0] != "02:00:00:00:02:62" {
		t.Fatalf("LXC network MACs = %#v, %v", macs, err)
	}
	macs, err = guestConfigMACs(map[string]any{
		"net0": "virtio=02:00:00:00:02:61",
		"net1": "virtio=02:00:00:00:02:62",
	})
	if err != nil || len(macs) != 2 {
		t.Fatal("multi-interface guest was accepted as an unambiguous reservation identity")
	}
}

func TestDNSRecordCLIUsesPresentDesiredStateAndPendingDeletion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BOETTICHER_RUNTIME_DIR", filepath.Join(t.TempDir(), "runtime"))
	config := model.ConfigFromSite(model.NewDefaultSite("installation", "age1example"))
	if err := site.SaveConfig(dir, config); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	args := []string{"dns", "record", "add", "--site", dir, "--name", "app.lab.home.arpa", "--type", "CNAME", "--value", "app-01.servers.lab.home.arpa"}
	if err := Run(args, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "DNS record added") {
		t.Fatalf("unexpected add output: %s", output.String())
	}
	output.Reset()
	if err := Run([]string{"dns", "record", "remove", "--site", dir, "--name", "app.lab.home.arpa", "--type", "CNAME"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	resolved, err := site.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.DNSRecords) != 0 || len(resolved.PendingDNSDeletions) != 1 {
		t.Fatalf("remove did not separate desired state from pending deletion: %#v %#v", resolved.DNSRecords, resolved.PendingDNSDeletions)
	}
	output.Reset()
	if err := Run(args, &output, &output); err != nil {
		t.Fatal(err)
	}
	resolved, err = site.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.DNSRecords) != 1 || len(resolved.PendingDNSDeletions) != 0 {
		t.Fatalf("re-add did not clear matching pending deletion: %#v %#v", resolved.DNSRecords, resolved.PendingDNSDeletions)
	}
	pendingPath := filepath.Join(os.Getenv("BOETTICHER_RUNTIME_DIR"), "installation", "dns", "pending-deletions.json")
	if data, err := os.ReadFile(pendingPath); err != nil || string(data) != "[]\n" {
		t.Fatalf("pending state should be empty after re-add: %q, %v", data, err)
	}
}
