package model

import (
	"strings"
	"testing"
)

func TestRevisionIsIndependentOfComponentOrder(t *testing.T) {
	first := NewDefaultSite("installation", "age1example")
	first.TestedVersions.Gateway = QualifiedGatewayImage
	second := first
	second.Components = append([]Component(nil), first.Components...)
	for i, j := 0, len(second.Components)-1; i < j; i, j = i+1, j-1 {
		second.Components[i], second.Components[j] = second.Components[j], second.Components[i]
	}
	a, err := first.Revision()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("revisions differ for equivalent component sets: %s != %s", a, b)
	}
}

func TestOfficialModuleDeclarationsDoNotBecomePlatformComponents(t *testing.T) {
	without := NewDefaultSite("installation", "age1example")
	with := without
	with.Modules = []ModuleInstance{{Name: "future-remote-access", Enabled: true}}

	withoutRevision, err := without.Revision()
	if err != nil {
		t.Fatal(err)
	}
	withRevision, err := with.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if withoutRevision == withRevision {
		t.Fatal("module declaration was omitted from the canonical model revision")
	}
	if len(with.PlatformComponents()) != len(without.PlatformComponents()) {
		t.Fatal("official module declaration changed the core component projection")
	}
}

func TestRevisionIgnoresOperatorLocalSSHPath(t *testing.T) {
	first := NewDefaultSite("installation", "age1example")
	second := first
	first.TestedVersions.Gateway = QualifiedGatewayImage
	second.TestedVersions.Gateway = QualifiedGatewayImage
	second.SSHIdentityFile = "/different/operator/key"
	a, err := first.Revision()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("operator-local SSH path changed platform revision: %s != %s", a, b)
	}
}

func TestUnqualifiedGatewayImageIsRejected(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.TestedVersions.Gateway = "debian-13-genericcloud-amd64-old"
	if err := site.Validate(); err == nil {
		t.Fatal("unqualified gateway image was accepted")
	}
}

func TestExternalGatewayOmitsManagedFirewall(t *testing.T) {
	site := NewSite("installation", "age1example", GatewayModeExternal)
	if err := site.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, component := range site.Components {
		if component.Name == "lab-fw-01" {
			t.Fatal("external gateway site retained managed firewall component")
		}
	}
}

func TestOldSiteSchemaRequiresFreshV02Initialization(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.APIVersion = "boetticher/v1"
	site.SchemaVersion = 1
	err := site.Validate()
	if err == nil || !strings.Contains(err.Error(), "recreate the site with boetticher init") {
		t.Fatalf("old schema did not produce the recreation guidance: %v", err)
	}
}

func TestUserManagedVMIDMustUseReservedRange(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	site.Components = append(site.Components, Component{Name: "user-vm", VMID: 450, Hostname: "user-vm", Zone: "SANDBOX", Address: "10.10.50.50", Role: "user workload"})
	if err := site.Validate(); err == nil || !strings.Contains(err.Error(), "reserved user-workload range") {
		t.Fatalf("invalid user VMID was accepted: %v", err)
	}
}

func TestPlatformGuestsCarryCanonicalTags(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	for _, component := range site.PlatformComponents() {
		if !component.ProductOwned {
			continue
		}
		for _, required := range []string{TagBoetticher, TagManaged} {
			if !containsString(component.Tags, required) {
				t.Fatalf("platform component %s is missing %q: %#v", component.Name, required, component.Tags)
			}
		}
		if component.VMID != 0 && component.Backup && !containsString(component.Tags, TagBackup) {
			t.Fatalf("backed-up platform guest %s is missing %q: %#v", component.Name, TagBackup, component.Tags)
		}
	}
}

func TestBackedUpPlatformGuestRequiresBackupTag(t *testing.T) {
	site := NewDefaultSite("installation", "age1example")
	for i := range site.Components {
		if site.Components[i].Name == "lab-dns-01" {
			tags := []string{}
			for _, tag := range site.Components[i].Tags {
				if tag != TagBackup {
					tags = append(tags, tag)
				}
			}
			site.Components[i].Tags = tags
		}
	}
	if err := site.Validate(); err == nil || !strings.Contains(err.Error(), "missing required tag \"backup\"") {
		t.Fatalf("missing backup tag was accepted: %v", err)
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
