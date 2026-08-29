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

const retainedModulesPath = "generated/retained-modules.json"

func LoadRetainedModules(dir string) ([]model.RetainedModule, error) {
	path := filepath.Join(dir, retainedModulesPath)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return nil, fmt.Errorf("validate retained modules path: %w", err)
	}
	data, err := pathguard.ReadFile(path)
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
	if err := validateRetainedModules(retained); err != nil {
		return nil, err
	}
	return retained, nil
}

func SaveRetainedModules(dir string, retained []model.RetainedModule) error {
	if err := validateRetainedModules(retained); err != nil {
		return err
	}
	data, err := json.MarshalIndent(retained, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, retainedModulesPath), append(data, '\n'), 0600)
}

func validateRetainedModules(retained []model.RetainedModule) error {
	for _, item := range retained {
		if item.Module == "" || model.ModuleOwnershipTag(item.Module) == "" {
			return fmt.Errorf("retained module has invalid name %q", item.Module)
		}
		for _, guest := range item.Guests {
			if err := guest.Validate(); err != nil {
				return fmt.Errorf("retained module %s contains invalid guest: %w", item.Module, err)
			}
		}
	}
	return nil
}
