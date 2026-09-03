package proxmox

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

type GuestSummary struct {
	VMID   int       `json:"vmid"`
	Name   string    `json:"name"`
	Status string    `json:"status"`
	Kind   GuestKind `json:"-"`
}

// PurgeModule removes only guests whose current identity and namespaced owner
// tag still match the module plan. It never searches by a free VMID or adopts
// an object whose ownership cannot be proved.
func PurgeModule(ctx context.Context, client *Client, plan Plan, module string) error {
	if client == nil {
		return fmt.Errorf("Proxmox client is required")
	}
	owner := "boetticher/module/" + module
	for _, guest := range plan.Guests {
		if guest.Owner != owner {
			continue
		}
		kind, current, err := client.GuestConfig(ctx, plan.Node, guest.VMID)
		if err != nil {
			if IsNotFound(err) {
				continue
			}
			return fmt.Errorf("inspect module guest %d before purge: %w", guest.VMID, err)
		}
		if kind != guest.Kind {
			return fmt.Errorf("HOLD: refusing to purge %s at VMID %d because the occupant is %s, expected %s", guest.Name, guest.VMID, kind, guest.Kind)
		}
		ownerTag := model.ModuleOwnershipTag(module)
		if ownerTag == "" || !hasOwnerTag(currentTags(current), ownerTag) {
			return fmt.Errorf("refusing to purge %s: canonical owner tag %q is absent", guest.Name, ownerTag)
		}
		if err := validateExistingGuest(current, guest); err != nil {
			return fmt.Errorf("refusing to purge %s: ownership proof failed: %w", guest.Name, err)
		}
		var purgeErr error
		switch guest.Kind {
		case KindQEMU:
			purgeErr = client.DestroyQEMU(ctx, plan.Node, guest.VMID)
		case KindLXC:
			purgeErr = client.DestroyLXC(ctx, plan.Node, guest.VMID)
		default:
			return fmt.Errorf("HOLD: refusing to purge %s with unsupported guest kind %s", guest.Name, guest.Kind)
		}
		if purgeErr != nil {
			return fmt.Errorf("purge module guest %s: %w", guest.Name, purgeErr)
		}
		kind, _, verifyErr := client.GuestConfig(ctx, plan.Node, guest.VMID)
		if verifyErr == nil {
			return fmt.Errorf("HOLD: module guest %s still exists after purge as %s", guest.Name, kind)
		}
		if !IsNotFound(verifyErr) {
			return fmt.Errorf("HOLD: verify module guest %s was removed: %w", guest.Name, verifyErr)
		}
	}
	return nil
}

func hasOwnerTag(tags, owner string) bool {
	for _, tag := range strings.Split(tags, ";") {
		if tag == owner {
			return true
		}
	}
	return false
}

type GuestAudit struct {
	VMID      int       `json:"vmid"`
	Name      string    `json:"name"`
	Kind      GuestKind `json:"kind"`
	Status    string    `json:"status"`
	Ownership string    `json:"ownership"`
	Result    string    `json:"result"`
	Detail    string    `json:"detail"`
}

const (
	PlatformOwnership = "boetticher platform"
	UserOwnership     = "user-managed"
)

// ClassifyGuests is deliberately a pure ownership projection. Unknown guests
// are informational and never become part of the desired-state plan.
func ClassifyGuests(plan Plan, discovered []GuestSummary) []GuestAudit {
	owned := make(map[int]GuestPlan, len(plan.Guests))
	for _, guest := range plan.Guests {
		owned[guest.VMID] = guest
	}
	seen := make(map[int]bool, len(discovered))
	result := make([]GuestAudit, 0, len(plan.Guests)+len(discovered))
	for _, expected := range plan.Guests {
		found := false
		for _, actual := range discovered {
			if actual.VMID != expected.VMID {
				continue
			}
			found = true
			seen[actual.VMID] = true
			result = append(result, GuestAudit{
				VMID: expected.VMID, Name: actual.Name, Kind: actual.Kind, Status: actual.Status,
				Ownership: PlatformOwnership, Result: "PASS", Detail: "owned platform guest discovered",
			})
			if actual.Kind != expected.Kind {
				result[len(result)-1].Result = "DRIFT"
				result[len(result)-1].Detail = fmt.Sprintf("kind is %s; expected %s", actual.Kind, expected.Kind)
			} else if actual.Name != "" && actual.Name != expected.Name {
				result[len(result)-1].Result = "DRIFT"
				result[len(result)-1].Detail = fmt.Sprintf("name is %q; expected %q", actual.Name, expected.Name)
			}
			break
		}
		if !found {
			result = append(result, GuestAudit{
				VMID: expected.VMID, Name: expected.Name, Kind: expected.Kind,
				Ownership: PlatformOwnership, Result: "MISSING", Detail: "owned platform guest was not discovered",
			})
		}
	}
	for _, actual := range discovered {
		if seen[actual.VMID] {
			continue
		}
		if _, isOwned := owned[actual.VMID]; isOwned {
			continue
		}
		result = append(result, GuestAudit{
			VMID: actual.VMID, Name: actual.Name, Kind: actual.Kind, Status: actual.Status,
			Ownership: UserOwnership, Result: "INFO", Detail: "outside boetticher ownership; no deployment action",
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].VMID != result[j].VMID {
			return result[i].VMID < result[j].VMID
		}
		return result[i].Kind < result[j].Kind
	})
	return result
}
