package backup

import (
	"github.com/dave/labinabox/internal/model"
	"github.com/dave/labinabox/internal/proxmox"
)

const PlatformJobName = "labinabox-platform"

type Plan struct {
	ModelRevision        string `json:"model_revision"`
	ManagedBy            string `json:"managed_by"`
	JobName              string `json:"job_name"`
	PlatformOnly         bool   `json:"platform_only"`
	UserWorkloadsManaged bool   `json:"user_workloads_managed"`
	DisasterRecovery     string `json:"disaster_recovery"`
	GuestVMIDs           []int  `json:"guest_vmids"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	proxmoxPlan, err := proxmox.PlanFromSite(s)
	if err != nil {
		return Plan{}, err
	}
	ids := make([]int, 0, len(proxmoxPlan.Guests))
	for _, guest := range proxmoxPlan.Guests {
		ids = append(ids, guest.VMID)
	}
	return Plan{
		ModelRevision: revision, ManagedBy: "Lab-in-a-Box", JobName: PlatformJobName,
		PlatformOnly: true, UserWorkloadsManaged: false,
		DisasterRecovery: "local backup is not independent disaster recovery; user workloads remain user-owned",
		GuestVMIDs:       ids,
	}, nil
}
