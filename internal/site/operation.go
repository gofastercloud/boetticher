package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
	"golang.org/x/sys/unix"
)

const (
	OperationStateVersion = 1
	operationStatePath    = "generated/operation.json"
	operationLockPath     = "generated/operation.lock"
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
	Version                int              `json:"version"`
	ID                     string           `json:"id"`
	Kind                   string           `json:"kind"`
	Phase                  OperationPhase   `json:"phase"`
	ModelRevision          string           `json:"model_revision"`
	PlanDigest             string           `json:"plan_digest"`
	BundleDigest           string           `json:"bundle_digest,omitempty"`
	StartedAt              string           `json:"started_at"`
	UpdatedAt              string           `json:"updated_at"`
	Error                  string           `json:"error,omitempty"`
	TemporaryPublicKey     string           `json:"temporary_public_key,omitempty"`
	TemporaryHostAddress   string           `json:"temporary_host_address,omitempty"`
	TemporaryCleanupGuests []OperationGuest `json:"temporary_cleanup_guests,omitempty"`
}

// OperationGuest is the bounded public identity needed to remove a temporary
// deployment key after a controller interruption. It is not desired state;
// it records only the exact guest targets that may have received the key.
type OperationGuest struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	VMID    int    `json:"vmid"`
	Address string `json:"address"`
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

// OperationLock is an advisory per-site lock held for the complete deploy
// lifecycle. The kernel releases it if the controller exits, so an
// interrupted deployment can still be recovered on the next invocation.
type OperationLock struct {
	file *os.File
}

func AcquireOperationLock(dir string) (*OperationLock, error) {
	path := filepath.Join(dir, operationLockPath)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return nil, fmt.Errorf("validate deployment lock path: %w", err)
	}
	if err := pathguard.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create deployment lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open deployment lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("deployment is already in progress for this site")
		}
		return nil, fmt.Errorf("acquire deployment lock: %w", err)
	}
	return &OperationLock{file: file}, nil
}

func (lock *OperationLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		_ = file.Close()
		return fmt.Errorf("release deployment lock: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close deployment lock: %w", err)
	}
	return nil
}

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
	if state.Version != OperationStateVersion || state.ID == "" || state.Kind != "deploy" || state.ModelRevision == "" || state.StartedAt == "" || state.UpdatedAt == "" {
		return errors.New("operation state is incomplete")
	}
	if state.TemporaryPublicKey == "" && len(state.TemporaryCleanupGuests) > 0 {
		return errors.New("operation state has cleanup guests without a temporary public key")
	}
	if state.TemporaryPublicKey == "" && state.TemporaryHostAddress != "" {
		return errors.New("operation state has a temporary host address without a temporary public key")
	}
	if state.TemporaryPublicKey != "" && state.TemporaryHostAddress == "" {
		return errors.New("operation state has a temporary public key without a host address")
	}
	if strings.ContainsAny(state.TemporaryPublicKey, "\r\n\x00") {
		return errors.New("operation state temporary public key contains control characters")
	}
	if state.TemporaryHostAddress != "" {
		address := net.ParseIP(state.TemporaryHostAddress)
		if address == nil || address.To4() == nil || address.To4().String() != state.TemporaryHostAddress {
			return fmt.Errorf("operation state temporary host address %q is not a canonical IPv4 address", state.TemporaryHostAddress)
		}
	}
	seenGuests := make(map[int]struct{}, len(state.TemporaryCleanupGuests))
	for _, guest := range state.TemporaryCleanupGuests {
		if guest.Name == "" || guest.VMID <= 0 || guest.Address == "" {
			return errors.New("operation state has an incomplete temporary cleanup guest")
		}
		if guest.Kind != "qemu" && guest.Kind != "lxc" {
			return fmt.Errorf("operation state has unsupported temporary cleanup guest kind %q", guest.Kind)
		}
		if strings.ContainsAny(guest.Name+guest.Address, "\r\n\x00") {
			return errors.New("operation state temporary cleanup guest contains control characters")
		}
		address := net.ParseIP(guest.Address)
		if address == nil || address.To4() == nil || address.To4().String() != guest.Address {
			return fmt.Errorf("operation state temporary cleanup guest address %q is not a canonical IPv4 address", guest.Address)
		}
		if _, ok := seenGuests[guest.VMID]; ok {
			return fmt.Errorf("operation state contains duplicate temporary cleanup guest VMID %d", guest.VMID)
		}
		seenGuests[guest.VMID] = struct{}{}
	}
	switch state.Phase {
	case PhasePlan:
		// PLAN is written before live reads and therefore may not have a
		// digest yet. APPLY and later phases must bind to one.
	case PhaseApply, PhaseVerify, PhaseCleanup, PhaseCommit:
		if strings.TrimSpace(state.PlanDigest) == "" {
			return errors.New("operation state has no plan digest after PLAN")
		}
	case PhaseFailed:
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
