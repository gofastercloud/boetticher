package backup

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/storage"
)

const (
	PlatformJobName      = "boetticher-platform"
	DedicatedStorageID   = storage.BackupStorageID
	DedicatedStoragePath = storage.BackupMount
)

type Plan struct {
	ModelRevision        string `json:"model_revision"`
	ManagedBy            string `json:"managed_by"`
	JobName              string `json:"job_name"`
	PlatformOnly         bool   `json:"platform_only"`
	UserWorkloadsManaged bool   `json:"user_workloads_managed"`
	DisasterRecovery     string `json:"disaster_recovery"`
	GuestVMIDs           []int  `json:"guest_vmids"`
	SelectionTag         string `json:"selection_tag"`
	StorageTarget        string `json:"storage_target"`
	Schedule             string `json:"schedule"`
	Retention            string `json:"retention"`
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
		if guest.Backup && hasTag(guest.Tags, model.TagBackup) {
			ids = append(ids, guest.VMID)
		}
	}
	if len(ids) == 0 {
		return Plan{}, fmt.Errorf("no boetticher platform guests carry the %q backup tag", model.TagBackup)
	}
	sort.Ints(ids)
	storage := "local"
	if s.StorageProfile == "dedicated-data-disk" {
		storage = DedicatedStorageID
	}
	return Plan{
		ModelRevision: revision, ManagedBy: "boetticher", JobName: PlatformJobName,
		PlatformOnly: true, UserWorkloadsManaged: false,
		DisasterRecovery: "local backup is not independent disaster recovery; user workloads remain user-owned",
		SelectionTag:     model.TagBackup,
		GuestVMIDs:       ids, StorageTarget: storage, Schedule: "daily", Retention: "keep-last=7",
	}, nil
}

func hasTag(tags []string, wanted string) bool {
	for _, tag := range tags {
		if tag == wanted {
			return true
		}
	}
	return false
}

func (p Plan) VMIDList() string {
	values := make([]string, 0, len(p.GuestVMIDs))
	for _, id := range p.GuestVMIDs {
		values = append(values, strconv.Itoa(id))
	}
	return strings.Join(values, ",")
}
