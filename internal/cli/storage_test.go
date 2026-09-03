package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestStorageUsesEnrolledProxmoxSSHProjection(t *testing.T) {
	s := model.NewDefaultSite("storage-runner", "age1storage")
	s.SSHIdentityFile = "/tmp/operator"
	runner := proxmoxRootSSHRunner(s, "/tmp/site")
	if runner.IdentityFile != "/tmp/operator" || runner.ConfigFile != "/tmp/site/generated/ssh/boetticher.conf" || runner.HostAlias != model.LogicalProxmoxIdentity || runner.StrictHostKey != "yes" {
		t.Fatalf("storage runner does not use enrolled SSH projection: %#v", runner)
	}
}
