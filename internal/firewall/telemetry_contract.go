package firewall

import "fmt"

const (
	TelemetryServiceName       = "boetticher-firewall-telemetry"
	TelemetrySnapshotService   = "boetticher-firewall-snapshot.service"
	TelemetrySnapshotTimer     = "boetticher-firewall-snapshot.timer"
	TelemetryListenAddress     = "10.10.10.1"
	TelemetryPulseSource       = "10.10.10.20/32"
	TelemetryPort              = 9765
	TelemetrySampleIntervalSec = 15
	TelemetryRawRetentionDays  = 7
	TelemetryStatePath         = "/var/lib/boetticher/firewall-telemetry"
	TelemetryDatabasePath      = TelemetryStatePath + "/telemetry.db"
	TelemetrySnapshotPath      = "/run/boetticher/firewall-ruleset.json"
)

// TelemetryPlan is the fixed Core firewall capability contract. It is not a
// user-configurable monitoring module or a generic nftables integration.
type TelemetryPlan struct {
	Enabled           bool     `json:"enabled"`
	ListenAddress     string   `json:"listen_address"`
	Port              int      `json:"port"`
	AllowedSources    []string `json:"allowed_sources"`
	SnapshotPath      string   `json:"snapshot_path"`
	DatabasePath      string   `json:"database_path"`
	SampleIntervalSec int      `json:"sample_interval_seconds"`
	RawRetentionDays  int      `json:"raw_retention_days"`
}

func DefaultTelemetryPlan(managed bool) TelemetryPlan {
	if !managed {
		return TelemetryPlan{}
	}
	return TelemetryPlan{
		Enabled:           true,
		ListenAddress:     TelemetryListenAddress,
		Port:              TelemetryPort,
		AllowedSources:    []string{TelemetryPulseSource},
		SnapshotPath:      TelemetrySnapshotPath,
		DatabasePath:      TelemetryDatabasePath,
		SampleIntervalSec: TelemetrySampleIntervalSec,
		RawRetentionDays:  TelemetryRawRetentionDays,
	}
}

func (p TelemetryPlan) Validate() error {
	if !p.Enabled {
		return nil
	}
	if p.ListenAddress != TelemetryListenAddress || p.Port != TelemetryPort || p.SnapshotPath != TelemetrySnapshotPath || p.DatabasePath != TelemetryDatabasePath || p.SampleIntervalSec != TelemetrySampleIntervalSec || p.RawRetentionDays != TelemetryRawRetentionDays {
		return fmt.Errorf("firewall telemetry has an unexpected fixed contract")
	}
	if len(p.AllowedSources) != 1 || p.AllowedSources[0] != TelemetryPulseSource {
		return fmt.Errorf("firewall telemetry must be reachable only from Pulse")
	}
	return nil
}

func semanticCounterComment(kind, id string) string {
	return "boetticher:" + kind + ":" + id
}

func SemanticCounterComment(kind, id string) (string, error) {
	if kind != "allow" && kind != "deny" && kind != "drop" {
		return "", fmt.Errorf("unsupported firewall telemetry counter kind %q", kind)
	}
	if id == "" {
		return "", fmt.Errorf("firewall telemetry counter id is required")
	}
	for index, character := range id {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_') || index == 0 && character == '-' {
			return "", fmt.Errorf("firewall telemetry counter id %q is not a stable token", id)
		}
	}
	comment := semanticCounterComment(kind, id)
	if len(comment) > MaxNFTComment {
		return "", fmt.Errorf("firewall telemetry counter comment is too long")
	}
	return comment, nil
}
