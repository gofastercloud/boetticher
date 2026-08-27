package logging

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

const (
	CollectorName      = "lab-log-01"
	CollectorAddress   = "10.10.10.40"
	CollectorPort      = 19532
	RemoteJournalPath  = "/var/log/journal/remote"
	CollectorVolumeGiB = 10
	CollectorMaxUse    = "8G"
	CollectorKeepFree  = "1G"
	LocalJournalMaxUse = "256M"
)

type Plan struct {
	ModelRevision       string   `json:"model_revision"`
	Collector           string   `json:"collector"`
	CollectorAddress    string   `json:"collector_address"`
	CollectorURL        string   `json:"collector_url"`
	CollectorPort       int      `json:"collector_port"`
	RemoteJournalPath   string   `json:"remote_journal_path"`
	SplitMode           string   `json:"split_mode"`
	MaxUse              string   `json:"max_use"`
	KeepFree            string   `json:"keep_free"`
	LocalJournalMaxUse  string   `json:"local_journal_max_use"`
	Sources             []string `json:"sources"`
	SourceUnitsOptional bool     `json:"source_units_optional"`
	MTLS                bool     `json:"mtls"`
}

func PlanFromSite(s model.Site) (Plan, error) {
	if err := s.Validate(); err != nil {
		return Plan{}, err
	}
	revision, err := s.Revision()
	if err != nil {
		return Plan{}, err
	}
	var collectorFound bool
	sources := make([]string, 0)
	for _, component := range s.PlatformComponents() {
		if component.Name == CollectorName {
			collectorFound = true
		}
		if component.Logging && component.Name != CollectorName {
			sources = append(sources, component.Name)
		}
	}
	if !collectorFound {
		return Plan{}, fmt.Errorf("mandatory logging collector %s is absent", CollectorName)
	}
	sort.Strings(sources)
	return Plan{
		ModelRevision: revision, Collector: CollectorName, CollectorAddress: CollectorAddress,
		CollectorURL: "https://logs." + s.Network.Domain + ":19532", CollectorPort: CollectorPort,
		RemoteJournalPath: RemoteJournalPath, SplitMode: "host", MaxUse: CollectorMaxUse,
		KeepFree: CollectorKeepFree, LocalJournalMaxUse: LocalJournalMaxUse, Sources: sources,
		SourceUnitsOptional: true, MTLS: true,
	}, nil
}

func CollectorConfiguration(plan Plan) string {
	return strings.Join([]string{
		"[Remote]", "Seal=true", "SplitMode=" + plan.SplitMode,
		"ServerKeyFile=/var/lib/boetticher/identity/logging/collector.key",
		"ServerCertificateFile=/var/lib/boetticher/identity/logging/collector.crt",
		"TrustedCertificateFile=/var/lib/boetticher/identity/logging/ca.crt",
		"MaxUse=" + plan.MaxUse, "KeepFree=" + plan.KeepFree,
	}, "\n") + "\n"
}

func CollectorServiceOverride(plan Plan) string {
	return strings.Join([]string{
		"[Service]", "LogsDirectory=", "ReadWritePaths=" + plan.RemoteJournalPath, "ExecStart=", "ExecStart=/usr/lib/systemd/systemd-journal-remote --listen-https=-3 --output=" + plan.RemoteJournalPath,
	}, "\n") + "\n"
}

func UploadConfiguration(plan Plan, endpoint string) string {
	return strings.Join([]string{
		"[Upload]", "URL=" + plan.CollectorURL, "ServerKeyFile=/var/lib/boetticher/identity/logging/" + endpoint + ".key",
		"ServerCertificateFile=/var/lib/boetticher/identity/logging/" + endpoint + ".crt",
		"TrustedCertificateFile=/var/lib/boetticher/identity/logging/ca.crt",
	}, "\n") + "\n"
}
