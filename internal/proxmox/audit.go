package proxmox

import (
	"context"
	"fmt"
	"sort"
)

type GuestSummary struct {
	VMID   int       `json:"vmid"`
	Name   string    `json:"name"`
	Status string    `json:"status"`
	Kind   GuestKind `json:"-"`
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
	PlatformOwnership = "Lab-in-a-Box platform"
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
			Ownership: UserOwnership, Result: "INFO", Detail: "outside Lab-in-a-Box ownership; no convergence action",
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

// AuditGuests lists both Proxmox guest kinds and inspects owned guest config.
// It never imports, mutates, or deletes an unknown guest.
func AuditGuests(ctx context.Context, client *Client, plan Plan) ([]GuestAudit, error) {
	if client == nil {
		return nil, fmt.Errorf("Proxmox client is required")
	}
	vms, err := client.ListVMs(ctx, plan.Node)
	if err != nil {
		return nil, fmt.Errorf("list Proxmox VMs: %w", err)
	}
	lxcs, err := client.ListLXCs(ctx, plan.Node)
	if err != nil {
		return nil, fmt.Errorf("list Proxmox LXCs: %w", err)
	}
	discovered := append(vms, lxcs...)
	audits := ClassifyGuests(plan, discovered)
	for i := range audits {
		if audits[i].Ownership != PlatformOwnership || audits[i].Result != "PASS" {
			continue
		}
		var config map[string]any
		var configErr error
		if audits[i].Kind == KindQEMU {
			configErr = client.QEMUConfig(ctx, plan.Node, audits[i].VMID, &config)
		} else {
			configErr = client.LXCConfig(ctx, plan.Node, audits[i].VMID, &config)
		}
		if configErr != nil {
			audits[i].Result = "DRIFT"
			audits[i].Detail = fmt.Sprintf("owned guest configuration could not be inspected: %v", configErr)
			continue
		}
		for _, expected := range plan.Guests {
			if expected.VMID == audits[i].VMID && expected.Kind == audits[i].Kind {
				if err := validateExistingGuest(config, expected); err != nil {
					audits[i].Result = "DRIFT"
					audits[i].Detail = err.Error()
				}
				break
			}
		}
	}
	return audits, nil
}
