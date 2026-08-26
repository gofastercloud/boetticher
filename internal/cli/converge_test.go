package cli

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
)

func TestResolvedArtifactContentReachesRuntimeDeclaration(t *testing.T) {
	declaration := model.ModuleDeclaration{Module: "dns", Artifact: model.Artifact{
		Name: "boetticher-dns-blocky", Version: "1.0.0", Kind: "lxc", Architecture: "amd64", DefinitionSHA256: strings.Repeat("a", 64),
	}}
	guest := proxmox.GuestPlan{VMID: model.DNS01VMID, Name: "lab-dns-01", Owner: "boetticher/module/dns", Artifact: model.Artifact{
		Name: "boetticher-dns-blocky", Version: "1.0.0", Kind: "lxc", Architecture: "amd64", DefinitionSHA256: strings.Repeat("a", 64), ContentSHA256: strings.Repeat("b", 64),
	}}
	resolved, err := resolvedDeclarationForGuest(declaration, guest)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Artifact.ContentSHA256 != guest.Artifact.ContentSHA256 {
		t.Fatalf("resolved content digest = %q, want %q", resolved.Artifact.ContentSHA256, guest.Artifact.ContentSHA256)
	}
}

func TestRuntimeDeclarationRejectsUnqualifiedGuestArtifact(t *testing.T) {
	_, err := resolvedDeclarationForGuest(model.ModuleDeclaration{Module: "dns"}, proxmox.GuestPlan{Owner: "boetticher/module/dns"})
	if err == nil || !strings.Contains(err.Error(), "qualified artifact") {
		t.Fatalf("unqualified guest artifact was accepted: %v", err)
	}
}
