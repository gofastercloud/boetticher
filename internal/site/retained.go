package site

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/gofastercloud/boetticher/internal/model"
)

const retainedModulesPath = "generated/retained-modules.json"

func LoadRetainedModules(dir string) ([]model.RetainedModule, error) {
	data, err := os.ReadFile(filepath.Join(dir, retainedModulesPath))
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
	return retained, nil
}

func SaveRetainedModules(dir string, retained []model.RetainedModule) error {
	data, err := json.MarshalIndent(retained, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, retainedModulesPath), append(data, '\n'), 0600)
}
