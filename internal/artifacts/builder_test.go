package artifacts

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestBuilderUsesPinnedQualifiedCapacityAndToolchain(t *testing.T) {
	builder := Builder()
	if builder.VMID != model.BuilderVMID || builder.Hostname != "lab-builder-01" {
		t.Fatalf("builder identity = %#v", builder)
	}
	if !builder.Temporary || builder.Network != "bootstrap-upstream-only" {
		t.Fatalf("builder isolation contract = %#v", builder)
	}
	if builder.Cores != 4 || builder.MemoryMiB != 8192 || builder.DiskGiB != 32 || builder.MinimumFreeGiB != 20 {
		t.Fatalf("builder sizing = %#v", builder)
	}
	if model.BuilderGoVersion != "1.26.5" || model.BuilderGoURL != "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz" || model.BuilderGoSHA256 != "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053" {
		t.Fatalf("builder Go toolchain is not pinned: %q %q %q", model.BuilderGoVersion, model.BuilderGoURL, model.BuilderGoSHA256)
	}
}
