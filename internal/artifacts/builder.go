package artifacts

import "github.com/gofastercloud/boetticher/internal/model"

// BuilderPlan describes the ephemeral Core build environment. It receives
// public build inputs only and is never a module or a runtime secret holder.
type BuilderPlan struct {
	VMID      int
	Hostname  string
	Platform  string
	Temporary bool
	Network   string
}

func Builder() BuilderPlan {
	return BuilderPlan{VMID: model.BuilderVMID, Hostname: "lab-builder-01", Platform: "debian-13-amd64", Temporary: true, Network: "bootstrap-upstream-only"}
}
