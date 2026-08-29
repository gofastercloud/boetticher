package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const (
	purgeIntentVersion = 1
	purgeIntentPath    = "generated/purge-intent.json"
)

// PurgeIntent records the exact module and guest identities selected before a
// destructive purge. It is deliberately controller-local recovery state, not
// desired configuration or a second ownership authority.
type PurgeIntent struct {
	Version       int          `json:"version"`
	Module        string       `json:"module"`
	ModelRevision string       `json:"model_revision"`
	CreatedAt     string       `json:"created_at"`
	Guests        []PurgeGuest `json:"guests"`
}

type PurgeGuest struct {
	VMID  int    `json:"vmid"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Owner string `json:"owner"`
}

func PurgeIntentPath(dir string) string {
	return filepath.Join(dir, purgeIntentPath)
}

func SavePurgeIntent(dir string, intent PurgeIntent) error {
	if intent.Version == 0 {
		intent.Version = purgeIntentVersion
	}
	if intent.CreatedAt == "" {
		intent.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := validatePurgeIntent(intent); err != nil {
		return err
	}
	data, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return fmt.Errorf("encode purge intent: %w", err)
	}
	return atomicWrite(PurgeIntentPath(dir), append(data, '\n'), 0600)
}

func LoadPurgeIntent(dir string) (PurgeIntent, bool, error) {
	path := PurgeIntentPath(dir)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return PurgeIntent{}, false, fmt.Errorf("validate purge intent path: %w", err)
	}
	data, err := pathguard.ReadFileLimited(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return PurgeIntent{}, false, nil
	}
	if err != nil {
		return PurgeIntent{}, false, fmt.Errorf("read purge intent: %w", err)
	}
	var intent PurgeIntent
	if err := json.Unmarshal(data, &intent); err != nil {
		return PurgeIntent{}, false, fmt.Errorf("decode purge intent: %w", err)
	}
	if err := validatePurgeIntent(intent); err != nil {
		return PurgeIntent{}, false, err
	}
	return intent, true, nil
}

func ClearPurgeIntent(dir string) error {
	path := PurgeIntentPath(dir)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return fmt.Errorf("validate purge intent path: %w", err)
	}
	if err := pathguard.RemoveAll(path); err != nil {
		return fmt.Errorf("remove purge intent: %w", err)
	}
	return nil
}

func validatePurgeIntent(intent PurgeIntent) error {
	if intent.Version != purgeIntentVersion {
		return fmt.Errorf("unsupported purge intent version %d", intent.Version)
	}
	if intent.Module == "" || model.ModuleOwnershipTag(intent.Module) == "" {
		return fmt.Errorf("purge intent has invalid module %q", intent.Module)
	}
	if strings.TrimSpace(intent.ModelRevision) == "" {
		return errors.New("purge intent model revision is required")
	}
	if _, err := time.Parse(time.RFC3339Nano, intent.CreatedAt); err != nil {
		return fmt.Errorf("purge intent timestamp is invalid: %w", err)
	}
	if len(intent.Guests) == 0 {
		return errors.New("purge intent has no guests")
	}
	owner := "boetticher/module/" + intent.Module
	seen := make(map[int]bool, len(intent.Guests))
	for _, guest := range intent.Guests {
		if guest.VMID <= 0 || guest.Name == "" || (guest.Kind != "qemu" && guest.Kind != "lxc") || guest.Owner != owner {
			return fmt.Errorf("purge intent has an invalid guest identity: %#v", guest)
		}
		if seen[guest.VMID] {
			return fmt.Errorf("purge intent repeats VMID %d", guest.VMID)
		}
		seen[guest.VMID] = true
	}
	return nil
}

func SortPurgeGuests(guests []PurgeGuest) {
	sort.Slice(guests, func(i, j int) bool {
		if guests[i].VMID != guests[j].VMID {
			return guests[i].VMID < guests[j].VMID
		}
		return guests[i].Name < guests[j].Name
	})
}
