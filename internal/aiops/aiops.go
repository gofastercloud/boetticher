package aiops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	MaxQueue              = 32
	MaxInvestigationsHour = 4
	MaxInvestigationsDay  = 24
	MaxInvestigationTime  = 10 * time.Minute
	MaxHolmesSteps        = 12
	MaxEvidenceCalls      = 4
	MaxEvidenceBytes      = 64 * 1024
	MaxJournalLines       = 200
	MaxJournalWindow      = 2 * time.Hour
	MaxOutputTokens       = 1200
	MaxPromptTokens       = 24000
	MaxDatabaseBytes      = 256 * 1024 * 1024
	Retention             = 30 * 24 * time.Hour
)

type State string

const (
	StateQueued       State = "queued"
	StateRunning      State = "running"
	StateCompleted    State = "completed"
	StateInconclusive State = "inconclusive"
	StateDeferred     State = "deferred"
	StateFailed       State = "failed"
	StateResolved     State = "resolved"
)

type Outcome string

const (
	OutcomeCompleted    Outcome = "completed"
	OutcomeInconclusive Outcome = "inconclusive"
)

type Alert struct {
	PulseAlertID string    `json:"id"`
	StartedAt    time.Time `json:"startTime"`
	ResourceID   string    `json:"resourceId"`
	Kind         string    `json:"type"`
	Severity     string    `json:"level"`
	Title        string    `json:"message"`
	Status       string    `json:"status,omitempty"`
}

func (a Alert) Validate() error {
	if !safeIdentifier(a.PulseAlertID) || a.StartedAt.IsZero() || !safeResourceID(a.ResourceID) || !safeToken(a.Kind) || !safeToken(a.Severity) {
		return errors.New("alert identity, resource, kind, severity, and start_time are required and bounded")
	}
	if len(a.Title) == 0 || len(a.Title) > 512 || strings.ContainsRune(a.Title, 0) {
		return errors.New("alert title must be 1-512 safe bytes")
	}
	if a.Status != "" && a.Status != "firing" && a.Status != "resolved" {
		return errors.New("alert status must be firing or resolved")
	}
	return nil
}

func (a Alert) Fingerprint() string {
	sum := sha256.Sum256([]byte(a.PulseAlertID + "\x00" + a.StartedAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:])
}

type Incident struct {
	ID            string
	Fingerprint   string
	PulseAlertID  string
	ResourceID    string
	Kind          string
	Severity      string
	Title         string
	State         State
	Outcome       Outcome
	DeferReason   string
	DeliveryCount int
	AcceptedAt    time.Time
	LastSeenAt    time.Time
	QueuedAt      time.Time
	StartedAt     time.Time
}

type Usage struct {
	InputTokens  int
	OutputTokens int
	HolmesSteps  int
}

type EvidenceReference struct {
	Reference   string
	Source      Operation
	SHA256      string
	Bytes       int
	CollectedAt time.Time
}

type Operation string

const (
	OperationAlert    Operation = "alert_context"
	OperationResource Operation = "resource_state"
	OperationMetric   Operation = "metric_history"
	OperationJournal  Operation = "central_journal"
)

type EvidenceRequest struct {
	Operation    Operation `json:"operation"`
	IncidentID   string    `json:"incident_id"`
	ResourceID   string    `json:"resource_id,omitempty"`
	Metric       string    `json:"metric,omitempty"`
	Host         string    `json:"host,omitempty"`
	Unit         string    `json:"unit,omitempty"`
	Priority     string    `json:"priority,omitempty"`
	SinceMinutes int       `json:"since_minutes,omitempty"`
	Limit        int       `json:"limit,omitempty"`
}

type Evidence struct {
	Reference   string          `json:"reference"`
	Source      Operation       `json:"source"`
	CollectedAt time.Time       `json:"collected_at"`
	SHA256      string          `json:"sha256"`
	Data        json.RawMessage `json:"data"`
}

type EvidencePolicy struct {
	IncidentID   string
	PulseAlertID string
	ResourceIDs  map[string]bool
	Hosts        map[string]map[string]bool
}

var metrics = map[string]bool{"cpu": true, "memory": true, "disk": true, "availability": true}
var priorities = map[string]bool{"emerg": true, "alert": true, "crit": true, "err": true, "warning": true, "notice": true, "info": true, "debug": true}

func (p EvidencePolicy) Validate(r EvidenceRequest) error {
	if r.IncidentID != p.IncidentID {
		return errors.New("evidence request is not bound to this incident")
	}
	switch r.Operation {
	case OperationAlert:
		return nil
	case OperationResource:
		if !p.ResourceIDs[r.ResourceID] {
			return errors.New("resource is not bound to this incident")
		}
	case OperationMetric:
		if !p.ResourceIDs[r.ResourceID] || !metrics[r.Metric] || r.SinceMinutes < 1 || r.SinceMinutes > 120 {
			return errors.New("metric request is outside the typed evidence policy")
		}
	case OperationJournal:
		units, ok := p.Hosts[r.Host]
		if !ok || r.Limit < 1 || r.Limit > MaxJournalLines || r.SinceMinutes < 1 || r.SinceMinutes > 120 || (r.Unit != "" && !units[r.Unit]) || (r.Priority != "" && !priorities[r.Priority]) {
			return errors.New("journal request is outside the typed evidence policy")
		}
	default:
		return errors.New("unknown evidence operation")
	}
	return nil
}

type Report struct {
	Outcome            Outcome  `json:"outcome"`
	Summary            string   `json:"summary"`
	LikelyCause        string   `json:"likely_cause,omitempty"`
	Confidence         string   `json:"confidence"`
	EvidenceReferences []string `json:"evidence_references"`
	EvidenceGaps       []string `json:"evidence_gaps"`
	SuggestedChecks    []string `json:"suggested_manual_checks"`
}

func (r Report) Validate(issued map[string]bool) error {
	if r.Outcome != OutcomeCompleted && r.Outcome != OutcomeInconclusive {
		return errors.New("report outcome is invalid")
	}
	if len(r.Summary) == 0 || len(r.Summary) > 8192 {
		return errors.New("report summary is empty or too large")
	}
	if r.Confidence != "low" && r.Confidence != "medium" && r.Confidence != "high" {
		return errors.New("report confidence is invalid")
	}
	if r.Outcome == OutcomeInconclusive && r.LikelyCause != "" {
		return errors.New("inconclusive report requires a null cause")
	}
	if r.Outcome == OutcomeCompleted && r.LikelyCause == "" {
		return errors.New("completed report requires a cause")
	}
	for _, ref := range r.EvidenceReferences {
		if !issued[ref] {
			return fmt.Errorf("report references unissued evidence %q", ref)
		}
	}
	return nil
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}$`)
var resourcePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}$`)

func safeToken(v string) bool      { return tokenPattern.MatchString(v) }
func safeIdentifier(v string) bool { return identifierPattern.MatchString(v) }
func safeResourceID(v string) bool { return resourcePattern.MatchString(v) }
