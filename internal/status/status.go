// Package status defines the one semantic status contract shared by the CLI,
// generated status JSON, verification presentation, and the portal.
package status

import "strings"

const ModelVersion = "boetticher/status/v1"

type EvidenceStatus string

const (
	PASS         EvidenceStatus = "PASS"
	FAIL         EvidenceStatus = "FAIL"
	HOLD         EvidenceStatus = "HOLD"
	NOTTESTED    EvidenceStatus = "NOT TESTED"
	INCONCLUSIVE EvidenceStatus = "INCONCLUSIVE"
)

type OperatorState string

const (
	Healthy        OperatorState = "HEALTHY"
	Degraded       OperatorState = "DEGRADED"
	Failed         OperatorState = "FAILED"
	Disabled       OperatorState = "DISABLED"
	ActionRequired OperatorState = "ACTION REQUIRED"
)

type EvidenceTier string

const (
	TierLocal    EvidenceTier = "local"
	TierRemote   EvidenceTier = "remote"
	TierDeployed EvidenceTier = "deployed"
	TierJourney  EvidenceTier = "journey"
	TierProduct  EvidenceTier = "product"
)

type Check struct {
	Component  string         `json:"component"`
	State      OperatorState  `json:"state"`
	Evidence   EvidenceStatus `json:"evidence_status"`
	Tier       EvidenceTier   `json:"evidence_tier"`
	ObservedAt string         `json:"observed_at,omitempty"`
	Reason     string         `json:"reason"`
	NextAction string         `json:"next_action"`
}

type Report struct {
	StatusModelVersion string        `json:"status_model_version"`
	ModelRevision      string        `json:"model_revision"`
	ObservedAt         string        `json:"observed_at"`
	OverallState       OperatorState `json:"overall_state"`
	Checks             []Check       `json:"checks"`
}

// LegacyCheck is the small internal bridge used while existing verification
// evidence is presented through the v1 semantic status model.
type LegacyCheck struct {
	Name   string
	Status string
	Detail string
}

func FromLegacy(modelRevision, observedAt string, checks []LegacyCheck) Report {
	result := Report{
		StatusModelVersion: ModelVersion,
		ModelRevision:      modelRevision,
		ObservedAt:         observedAt,
		Checks:             make([]Check, 0, len(checks)),
	}
	for _, check := range checks {
		evidence := EvidenceStatus(strings.TrimSpace(check.Status))
		if evidence == "STATIC PASS" {
			evidence = PASS
		}
		if evidence != PASS && evidence != FAIL && evidence != HOLD && evidence != NOTTESTED && evidence != INCONCLUSIVE {
			evidence = INCONCLUSIVE
		}
		result.Checks = append(result.Checks, Check{
			Component:  check.Name,
			State:      operatorState(evidence),
			Evidence:   evidence,
			Tier:       tierFor(evidence, check.Detail),
			ObservedAt: observedAt,
			Reason:     check.Detail,
			NextAction: nextAction(evidence),
		})
	}
	result.OverallState = Overall(result.Checks)
	if len(result.Checks) == 0 {
		result.OverallState = ActionRequired
	}
	return result
}

func Overall(checks []Check) OperatorState {
	state := Healthy
	for _, check := range checks {
		if check.State == Disabled {
			continue
		}
		switch check.State {
		case Failed:
			return Failed
		case ActionRequired:
			state = ActionRequired
		case Degraded:
			if state == Healthy {
				state = Degraded
			}
		}
	}
	return state
}

func operatorState(evidence EvidenceStatus) OperatorState {
	switch evidence {
	case PASS:
		return Healthy
	case FAIL:
		return Failed
	case HOLD, NOTTESTED:
		return ActionRequired
	case INCONCLUSIVE:
		return Degraded
	default:
		return Degraded
	}
}

func tierFor(evidence EvidenceStatus, detail string) EvidenceTier {
	lower := strings.ToLower(detail)
	if strings.Contains(lower, "journey") || strings.Contains(lower, "authenticated") {
		return TierJourney
	}
	if strings.Contains(lower, "deployed") || strings.Contains(lower, "gateway") {
		return TierDeployed
	}
	return TierLocal
}

func nextAction(evidence EvidenceStatus) string {
	switch evidence {
	case PASS:
		return "No action required"
	case FAIL:
		return "Review the detailed evidence and correct the failed check"
	case HOLD:
		return "Resolve the stated prerequisite before continuing"
	case NOTTESTED:
		return "Run the corresponding live or acceptance check"
	case INCONCLUSIVE:
		return "Collect complete evidence and repeat the check"
	default:
		return "Review the detailed evidence"
	}
}
