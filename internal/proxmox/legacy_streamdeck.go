package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

const LegacyStreamDeckName = "lab-streamdeck-01"

// InspectLegacyStreamDeck proves the exact 0.4 StreamDeck LXC identity. A
// matching VMID alone is never enough because 220 is reusable after migration.
func InspectLegacyStreamDeck(ctx context.Context, client *Client, node string) (bool, error) {
	if client == nil {
		return false, errors.New("Proxmox client is required")
	}
	kind, current, err := client.GuestConfig(ctx, node, model.LegacyStreamDeckVMID)
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect legacy StreamDeck guest %d: %w", model.LegacyStreamDeckVMID, err)
	}
	if err := ValidateLegacyStreamDeckIdentity(kind, current); err != nil {
		return false, err
	}
	return true, nil
}

// ValidateLegacyStreamDeckIdentity accepts only the exact product-owned 0.4
// LXC, including its canonical name, hostname, and ownership tag set.
func ValidateLegacyStreamDeckIdentity(kind GuestKind, current map[string]any) error {
	if kind != KindLXC {
		return fmt.Errorf("refusing legacy StreamDeck migration at VMID %d: occupant is %s, expected an LXC", model.LegacyStreamDeckVMID, kind)
	}
	if name, _ := current["name"].(string); name != LegacyStreamDeckName {
		return fmt.Errorf("refusing legacy StreamDeck migration: VMID %d name is %q, expected %q", model.LegacyStreamDeckVMID, name, LegacyStreamDeckName)
	}
	if hostname, _ := current["hostname"].(string); hostname != LegacyStreamDeckName {
		return fmt.Errorf("refusing legacy StreamDeck migration: VMID %d hostname is %q, expected %q", model.LegacyStreamDeckVMID, hostname, LegacyStreamDeckName)
	}
	tags := map[string]bool{}
	for _, tag := range strings.Fields(strings.ReplaceAll(stringValue(current["tags"]), ";", " ")) {
		tags[tag] = true
	}
	for _, required := range []string{model.TagBoetticher, model.TagManaged, model.TagModule, model.ModuleOwnershipTag("streamdeck")} {
		if required == "" || !tags[required] {
			return fmt.Errorf("refusing legacy StreamDeck migration: VMID %d is missing canonical ownership tag %q", model.LegacyStreamDeckVMID, required)
		}
	}
	return nil
}

// RemoveLegacyStreamDeck destroys only the already-proven old LXC and verifies
// that the exact VMID is absent afterward. USB mapping cleanup is deliberately
// a separate operation so a failed cleanup blocks deletion.
func RemoveLegacyStreamDeck(ctx context.Context, client *Client, node string) error {
	present, err := InspectLegacyStreamDeck(ctx, client, node)
	if err != nil || !present {
		return err
	}
	// Re-read the complete identity immediately before the destructive request.
	// Proxmox does not provide compare-and-delete, so deletion must never rely
	// only on the earlier migration preflight observation.
	kind, current, err := client.GuestConfig(ctx, node, model.LegacyStreamDeckVMID)
	if err != nil {
		return fmt.Errorf("reinspect legacy StreamDeck guest before removal: %w", err)
	}
	if err := ValidateLegacyStreamDeckIdentity(kind, current); err != nil {
		return err
	}
	if err := ValidateNoUndeclaredLXCPersistentVolumes(current, LegacyStreamDeckName); err != nil {
		return fmt.Errorf("refusing to remove legacy StreamDeck guest with undeclared storage: %w", err)
	}
	if err := client.DestroyLXC(ctx, node, model.LegacyStreamDeckVMID); err != nil {
		return fmt.Errorf("remove legacy StreamDeck guest %s: %w", LegacyStreamDeckName, err)
	}
	kind, _, verifyErr := client.GuestConfig(ctx, node, model.LegacyStreamDeckVMID)
	if verifyErr == nil {
		return fmt.Errorf("legacy StreamDeck guest %s still exists after removal as %s", LegacyStreamDeckName, kind)
	}
	if !IsNotFound(verifyErr) {
		return fmt.Errorf("verify legacy StreamDeck guest %s was removed: %w", LegacyStreamDeckName, verifyErr)
	}
	return nil
}

// LegacyStreamDeckUSBRemovalArgs is the fixed privileged helper invocation
// used by migration. Keeping the VMID constant prevents an operator-provided
// value from widening the host-side cleanup target.
func LegacyStreamDeckUSBRemovalArgs() []string {
	return []string{"/usr/lib/boetticher/boetticher-usb-export", "--remove", strconv.Itoa(model.LegacyStreamDeckVMID)}
}

func stringValue(value any) string {
	valueString, _ := value.(string)
	return valueString
}
