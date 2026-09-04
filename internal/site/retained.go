package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const (
	retainedModulesPath      = "generated/retained-modules.json"
	maxRetainedModulesBytes  = 1 << 20
	maxRetainedModuleEntries = 64
)

func LoadRetainedModules(dir string) ([]model.RetainedModule, error) {
	path := filepath.Join(dir, retainedModulesPath)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return nil, fmt.Errorf("validate retained modules path: %w", err)
	}
	data, err := pathguard.ReadFileLimited(path, maxRetainedModulesBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var retained []model.RetainedModule
	if err := json.Unmarshal(data, &retained); err != nil {
		return nil, err
	}
	if len(retained) > maxRetainedModuleEntries {
		return nil, fmt.Errorf("retained module state exceeds maximum of %d modules", maxRetainedModuleEntries)
	}
	if err := validateRetainedModules(retained); err != nil {
		return nil, err
	}
	return retained, nil
}

func SaveRetainedModules(dir string, retained []model.RetainedModule) error {
	data, err := marshalRetainedModules(retained)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, retainedModulesPath), append(data, '\n'), 0600)
}

func marshalRetainedModules(retained []model.RetainedModule) ([]byte, error) {
	if err := validateRetainedModules(retained); err != nil {
		return nil, err
	}
	return json.MarshalIndent(retained, "", "  ")
}

func validateRetainedModules(retained []model.RetainedModule) error {
	for _, item := range retained {
		if item.Module == "" || model.ModuleOwnershipTag(item.Module) == "" {
			return fmt.Errorf("retained module has invalid name %q", item.Module)
		}
		if item.Disposition != "retained" || item.Active {
			return fmt.Errorf("retained module %s has invalid inactive disposition", item.Module)
		}
		ownerTag := model.ModuleOwnershipTag(item.Module)
		for _, guest := range item.Guests {
			if err := guest.Validate(); err != nil {
				return fmt.Errorf("retained module %s contains invalid guest: %w", item.Module, err)
			}
			if !guest.ProductOwned || !guest.SSHManaged || guest.Module != item.Module {
				return fmt.Errorf("retained guest %s must remain a product-owned SSH-managed %s guest", guest.Name, item.Module)
			}
			if guest.VMID < model.PlatformGuestIDMin || guest.VMID > model.ModuleGuestIDMax {
				return fmt.Errorf("retained guest %s uses VMID %d outside the boetticher-owned range", guest.Name, guest.VMID)
			}
			hasOwnerTag := false
			for _, tag := range guest.Tags {
				if tag == ownerTag {
					hasOwnerTag = true
					break
				}
			}
			if !hasOwnerTag {
				return fmt.Errorf("retained guest %s is missing canonical ownership tag %q", guest.Name, ownerTag)
			}
		}
	}
	return nil
}
