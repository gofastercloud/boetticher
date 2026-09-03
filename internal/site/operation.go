package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const (
	OperationStateVersion = 1
	operationStatePath    = "generated/operation.json"
	lastAppliedStatePath  = "generated/last-applied.json"
)

type OperationPhase string

const (
	PhasePlan    OperationPhase = "PLAN"
	PhaseApply   OperationPhase = "APPLY"
	PhaseVerify  OperationPhase = "VERIFY"
	PhaseCleanup OperationPhase = "CLEANUP"
	PhaseCommit  OperationPhase = "COMMIT"
	PhaseFailed  OperationPhase = "FAILED"
)

// OperationState is recoverable execution state, not desired configuration.
// It records what a running deployment intended to apply and where it
// stopped, so retry and diagnosis do not infer intent from partial files.
type OperationState struct {
	Version       int            `json:"version"`
	ID            string         `json:"id"`
	Kind          string         `json:"kind"`
	Phase         OperationPhase `json:"phase"`
	ModelRevision string         `json:"model_revision"`
	PlanDigest    string         `json:"plan_digest"`
	BundleDigest  string         `json:"bundle_digest,omitempty"`
	StartedAt     string         `json:"started_at"`
	UpdatedAt     string         `json:"updated_at"`
	Error         string         `json:"error,omitempty"`
}

// LastAppliedState is the narrow commit record used to distinguish desired
// state from the exact revision and plan that passed deployment verification.
type LastAppliedState struct {
	Version       int    `json:"version"`
	ModelRevision string `json:"model_revision"`
	PlanDigest    string `json:"plan_digest"`
	BundleDigest  string `json:"bundle_digest,omitempty"`
	AppliedAt     string `json:"applied_at"`
}

func OperationStatePath(dir string) string   { return filepath.Join(dir, operationStatePath) }
func LastAppliedStatePath(dir string) string { return filepath.Join(dir, lastAppliedStatePath) }

func SaveOperationState(dir string, state OperationState) error {
	if state.Version == 0 {
		state.Version = OperationStateVersion
	}
	if state.UpdatedAt == "" {
		state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if state.StartedAt == "" {
		state.StartedAt = state.UpdatedAt
	}
	if err := validateOperationState(state); err != nil {
		return err
	}
	return writeOperationJSON(OperationStatePath(dir), state)
}

func LoadOperationState(dir string) (OperationState, bool, error) {
	var state OperationState
	found, err := readOperationJSON(OperationStatePath(dir), &state)
	if err != nil || !found {
		return state, found, err
	}
	if err := validateOperationState(state); err != nil {
		return OperationState{}, true, err
	}
	return state, true, nil
}

func ClearOperationState(dir string) error {
	path := OperationStatePath(dir)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	return pathguard.RemoveAll(path)
}

func SaveLastAppliedState(dir string, state LastAppliedState) error {
	if state.Version == 0 {
		state.Version = OperationStateVersion
	}
	if state.AppliedAt == "" {
		state.AppliedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := validateLastAppliedState(state); err != nil {
		return err
	}
	return writeOperationJSON(LastAppliedStatePath(dir), state)
}

func LoadLastAppliedState(dir string) (LastAppliedState, bool, error) {
	var state LastAppliedState
	found, err := readOperationJSON(LastAppliedStatePath(dir), &state)
	if err != nil || !found {
		return state, found, err
	}
	if err := validateLastAppliedState(state); err != nil {
		return LastAppliedState{}, true, err
	}
	return state, true, nil
}

func validateOperationState(state OperationState) error {
	if state.Version != OperationStateVersion || state.ID == "" || state.Kind != "deploy" || state.ModelRevision == "" || state.PlanDigest == "" || state.StartedAt == "" || state.UpdatedAt == "" {
		return errors.New("operation state is incomplete")
	}
	switch state.Phase {
	case PhasePlan, PhaseApply, PhaseVerify, PhaseCleanup, PhaseCommit, PhaseFailed:
	default:
		return fmt.Errorf("unsupported operation phase %q", state.Phase)
	}
	if _, err := time.Parse(time.RFC3339Nano, state.StartedAt); err != nil {
		return fmt.Errorf("operation start time is invalid: %w", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, state.UpdatedAt); err != nil {
		return fmt.Errorf("operation update time is invalid: %w", err)
	}
	return nil
}

func validateLastAppliedState(state LastAppliedState) error {
	if state.Version != OperationStateVersion || strings.TrimSpace(state.ModelRevision) == "" || strings.TrimSpace(state.PlanDigest) == "" || state.AppliedAt == "" {
		return errors.New("last-applied state is incomplete")
	}
	if _, err := time.Parse(time.RFC3339Nano, state.AppliedAt); err != nil {
		return fmt.Errorf("last-applied time is invalid: %w", err)
	}
	return nil
}

func writeOperationJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0600)
}

func readOperationJSON(path string, target any) (bool, error) {
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return false, err
	}
	data, err := pathguard.ReadFileLimited(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return true, err
	}
	return true, nil
}
