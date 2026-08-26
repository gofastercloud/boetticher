package zabbix

import "github.com/gofastercloud/boetticher/internal/model"

const PlatformHostGroup = "boetticher/platform"

type Plan struct {
	ModelRevision string         `json:"model_revision"`
	Target        string         `json:"target"`
	ManagedBy     string         `json:"managed_by"`
	HostGroup     string         `json:"host_group"`
	PlatformOnly  bool           `json:"platform_only"`
	Modules       []model.Module `json:"modules"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		ModelRevision: revision,
		Target:        model.ZabbixSeries,
		ManagedBy:     "boetticher",
		HostGroup:     PlatformHostGroup,
		PlatformOnly:  true,
		Modules:       s.PlatformModules(),
	}, nil
}
