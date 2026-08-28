package usbexport

import (
	"fmt"
	"sort"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
)

type Export struct {
	Module      string `json:"module"`
	Requirement string `json:"requirement"`
	Slot        string `json:"slot"`
	Port        string `json:"port"`
	VendorID    string `json:"vendor_id"`
	ProductID   string `json:"product_id"`
	Serial      string `json:"serial,omitempty"`
	Access      string `json:"access"`
}

type GuestManifest struct {
	VMID         int      `json:"vmid"`
	Hostname     string   `json:"hostname"`
	OwnershipTag string   `json:"ownership_tag"`
	Unprivileged bool     `json:"unprivileged"`
	Exports      []Export `json:"exports"`
	StaticSlots  []string `json:"static_slots,omitempty"`
	ManagedSlots []string `json:"managed_slots"`
}

func PlanFromSite(site model.Site) ([]GuestManifest, error) {
	if err := site.Validate(); err != nil {
		return nil, err
	}
	bindings := map[string]model.USBExportBinding{}
	for _, binding := range site.USBExports {
		bindings[binding.Module+"/"+binding.Requirement] = binding
	}
	var manifests []GuestManifest
	enabled, retained := map[string]bool{}, map[string]bool{}
	for _, module := range site.Modules {
		enabled[module.Name] = module.Enabled
	}
	for _, module := range site.RetainedModules {
		retained[module.Module] = true
	}
	for _, definition := range modules.FirstPartyRegistry().Definitions() {
		if len(definition.USBRequirements) == 0 || !enabled[definition.Name] && !retained[definition.Name] {
			continue
		}
		guests := map[string]model.Component{}
		for _, guest := range definition.Guests {
			guests[guest.Name] = guest
		}
		for _, module := range site.RetainedModules {
			if module.Module == definition.Name {
				for _, guest := range module.Guests {
					guests[guest.Name] = guest
				}
			}
		}
		byGuest := map[string][]Export{}
		requirements := append([]model.USBRequirement(nil), definition.USBRequirements...)
		sort.Slice(requirements, func(i, j int) bool { return requirements[i].Name < requirements[j].Name })
		slotByRequirement, managedByGuest, nextSlot := map[string]string{}, map[string][]string{}, map[string]int{}
		for _, requirement := range requirements {
			if _, ok := nextSlot[requirement.Guest]; !ok {
				nextSlot[requirement.Guest] = definition.StaticDeviceSlots
			}
			slot := fmt.Sprintf("dev%d", nextSlot[requirement.Guest])
			nextSlot[requirement.Guest]++
			slotByRequirement[requirement.Name] = slot
			managedByGuest[requirement.Guest] = append(managedByGuest[requirement.Guest], slot)
		}
		for _, requirement := range requirements {
			if _, ok := byGuest[requirement.Guest]; !ok {
				byGuest[requirement.Guest] = []Export{}
			}
			if !enabled[definition.Name] {
				continue
			}
			binding, ok := bindings[definition.Name+"/"+requirement.Name]
			if !ok {
				if requirement.Required {
					return nil, fmt.Errorf("required USB binding missing for %s/%s", definition.Name, requirement.Name)
				}
				continue
			}
			byGuest[requirement.Guest] = append(byGuest[requirement.Guest], Export{Module: definition.Name, Requirement: requirement.Name, Slot: slotByRequirement[requirement.Name], Port: binding.Port, VendorID: binding.VendorID, ProductID: binding.ProductID, Serial: binding.Serial, Access: requirement.Access})
		}
		for guestName, exports := range byGuest {
			guest, ok := guests[guestName]
			if !ok {
				return nil, fmt.Errorf("USB requirement targets undeclared guest %s", guestName)
			}
			sort.Slice(exports, func(i, j int) bool { return exports[i].Requirement < exports[j].Requirement })
			managedSlots := managedByGuest[guestName]
			staticSlots := make([]string, 0, definition.StaticDeviceSlots)
			for index := 0; index < definition.StaticDeviceSlots; index++ {
				staticSlots = append(staticSlots, fmt.Sprintf("dev%d", index))
			}
			manifests = append(manifests, GuestManifest{VMID: guest.VMID, Hostname: guest.Hostname, OwnershipTag: model.ModuleOwnershipTag(definition.Name), Unprivileged: true, Exports: exports, StaticSlots: staticSlots, ManagedSlots: managedSlots})
		}
	}
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].VMID < manifests[j].VMID })
	return manifests, nil
}
