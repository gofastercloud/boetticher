// Package status defines the shared result shape used by the CLI and generated
// status JSON.
package status

import "strings"

// ModelVersion identifies the machine-readable status format.
const ModelVersion = "boetticher/status/v1"

// EvidenceStatus describes the result recorded for one check.
type EvidenceStatus string

const (
	// PASS means the check completed successfully.
	PASS EvidenceStatus = "PASS"
	// FAIL means the check ran and found a failure.
	FAIL EvidenceStatus = "FAIL"
	// HOLD means a prerequisite or ownership condition prevents the check.
	HOLD EvidenceStatus = "HOLD"
	// NOTTESTED means the corresponding check has not been run.
	NOTTESTED EvidenceStatus = "NOT TESTED"
	// INCONCLUSIVE means the available result cannot support a conclusion.
	INCONCLUSIVE EvidenceStatus = "INCONCLUSIVE"
)

// OperatorState is the plain-language state shown by Boetticher.
type OperatorState string

const (
	Healthy        OperatorState = "HEALTHY"
	Degraded       OperatorState = "DEGRADED"
	Failed         OperatorState = "FAILED"
	Disabled       OperatorState = "DISABLED"
	ActionRequired OperatorState = "ACTION REQUIRED"
)

// EvidenceTier identifies where a check was performed.
type EvidenceTier string

const (
	TierLocal    EvidenceTier = "local"
	TierRemote   EvidenceTier = "remote"
	TierDeployed EvidenceTier = "deployed"
	TierJourney  EvidenceTier = "journey"
	TierProduct  EvidenceTier = "product"
)

// Check is one component result in a status report.
type Check struct {
	ID         string         `json:"id"`
	Component  string         `json:"component"`
	State      OperatorState  `json:"state"`
	Evidence   EvidenceStatus `json:"evidence_status"`
	Tier       EvidenceTier   `json:"evidence_tier"`
	ObservedAt string         `json:"observed_at,omitempty"`
	Reason     string         `json:"reason"`
	NextAction string         `json:"next_action"`
}

// Report is the versioned status document shared by CLI and JSON output.
type Report struct {
	StatusModelVersion string        `json:"status_model_version"`
	ModelRevision      string        `json:"model_revision"`
	ObservedAt         string        `json:"observed_at"`
	OverallState       OperatorState `json:"overall_state"`
	Checks             []Check       `json:"checks"`
}

// CheckResult is the legacy-shaped internal result collected by the read-only
// status checks before it is converted into Report. It is kept here because
// status collection and semantic reporting share the shape; it is not a web
// page or a separate persisted authority.
type CheckResult struct {
	ID         string       `json:"id,omitempty"`
	Name       string       `json:"name"`
	Status     string       `json:"status"`
	Detail     string       `json:"detail,omitempty"`
	Tier       EvidenceTier `json:"evidence_tier,omitempty"`
	ObservedAt string       `json:"observed_at,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	NextAction string       `json:"next_action,omitempty"`
}

// Evidence is the local status-check input used to build the semantic report.
// It is not a deployment input or component-specific projection.
type Evidence struct {
	GeneratedAt string        `json:"generated_at"`
	Results     []CheckResult `json:"results"`
	Status      *Report       `json:"-"`
}

// LegacyCheck is the small internal bridge used while existing verification
// results are presented through the v1 status model.
type LegacyCheck struct {
	ID         string
	Name       string
	Status     string
	Detail     string
	Tier       EvidenceTier
	ObservedAt string
	Reason     string
	NextAction string
}

// FromLegacy converts existing verification results into the status model.
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
		tier := check.Tier
		if tier == "" {
			tier = TierLocal
		}
		observed := check.ObservedAt
		if observed == "" {
			observed = observedAt
		}
		reason := check.Reason
		if reason == "" {
			reason = check.Detail
		}
		next := check.NextAction
		if next == "" {
			next = nextAction(evidence)
		}
		result.Checks = append(result.Checks, Check{
			ID:         check.ID,
			Component:  check.Name,
			State:      operatorState(evidence),
			Evidence:   evidence,
			Tier:       tier,
			ObservedAt: observed,
			Reason:     reason,
			NextAction: next,
		})
	}
	result.OverallState = Overall(result.Checks)
	if len(result.Checks) == 0 {
		result.OverallState = ActionRequired
	}
	return result
}

// Overall returns the most serious current state in checks.
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

func nextAction(evidence EvidenceStatus) string {
	switch evidence {
	case PASS:
		return "No action required"
	case FAIL:
		return "Review the details and correct the failed check"
	case HOLD:
		return "Resolve the stated prerequisite before continuing"
	case NOTTESTED:
		return "Run the corresponding live or acceptance check"
	case INCONCLUSIVE:
		return "Gather the missing details and repeat the check"
	default:
		return "Review the details"
	}
}
