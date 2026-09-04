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

// ApplyModuleState commits the desired module configuration, retained-state
// projection, and optional pending purge operation as one controller-local
// state change. Each file replacement is atomic and a later failure restores
// every earlier file, so a rejected module operation cannot leave its desired
// and operation records disagreeing.
func ApplyModuleState(dir string, config model.SiteConfig, retained []model.RetainedModule, purge *PurgeIntent) error {
	configData, err := model.RenderSiteConfig(config)
	if err != nil {
		return err
	}
	retainedData, err := marshalRetainedModules(retained)
	if err != nil {
		return err
	}

	files := []moduleStateFile{
		{path: filepath.Join(dir, "site.yml"), data: configData, mode: 0600},
		{path: filepath.Join(dir, retainedModulesPath), data: append(retainedData, '\n'), mode: 0600},
	}
	if purge != nil {
		if purge.Version == 0 {
			purge.Version = purgeIntentVersion
		}
		if err := validatePurgeIntent(*purge); err != nil {
			return err
		}
		purgeData, marshalErr := jsonMarshalPurgeIntent(*purge)
		if marshalErr != nil {
			return marshalErr
		}
		files = append(files, moduleStateFile{path: PurgeIntentPath(dir), data: purgeData, mode: 0600})
	} else {
		files = append(files, moduleStateFile{path: PurgeIntentPath(dir), remove: true})
	}

	return applyModuleStateFiles(files)
}

// ApplyLegacyStreamDeckMigration commits the migrated desired configuration
// and retained-resource projection together. Existing purge intents are left
// untouched because the migration must not cancel an unrelated operation.
func ApplyLegacyStreamDeckMigration(dir string, config model.SiteConfig, retained []model.RetainedModule) error {
	configData, err := model.RenderSiteConfig(config)
	if err != nil {
		return err
	}
	retainedData, err := marshalRetainedModules(retained)
	if err != nil {
		return err
	}
	return applyModuleStateFiles([]moduleStateFile{
		{path: filepath.Join(dir, "site.yml"), data: configData, mode: 0600},
		{path: filepath.Join(dir, retainedModulesPath), data: append(retainedData, '\n'), mode: 0600},
	})
}

func applyModuleStateFiles(files []moduleStateFile) error {
	snapshots := make([]moduleStateSnapshot, len(files))
	for index, file := range files {
		data, present, readErr := readModuleStateFile(file.path)
		if readErr != nil {
			return fmt.Errorf("read module state %s: %w", file.path, readErr)
		}
		snapshots[index] = moduleStateSnapshot{data: data, present: present}
	}

	for index, file := range files {
		if applyErr := applyModuleStateFile(file); applyErr != nil {
			rollbackErr := rollbackModuleState(files[:index], snapshots[:index])
			if rollbackErr != nil {
				return fmt.Errorf("apply module state %s: %v; rollback failed: %w", file.path, applyErr, rollbackErr)
			}
			return fmt.Errorf("apply module state %s: %w", file.path, applyErr)
		}
	}
	return nil
}

type moduleStateFile struct {
	path   string
	data   []byte
	mode   os.FileMode
	remove bool
}

type moduleStateSnapshot struct {
	data    []byte
	present bool
}

func readModuleStateFile(path string) ([]byte, bool, error) {
	data, err := pathguard.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func applyModuleStateFile(file moduleStateFile) error {
	if file.remove {
		if err := pathguard.ValidateNoSymlinkComponents(file.path); err != nil {
			return err
		}
		return pathguard.RemoveAll(file.path)
	}
	return atomicWrite(file.path, file.data, file.mode)
}

func rollbackModuleState(files []moduleStateFile, snapshots []moduleStateSnapshot) error {
	var rollbackErr error
	for index := len(files) - 1; index >= 0; index-- {
		file := files[index]
		snapshot := snapshots[index]
		var err error
		if snapshot.present {
			err = atomicWrite(file.path, snapshot.data, file.mode)
		} else {
			err = pathguard.RemoveAll(file.path)
		}
		if err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore %s: %w", file.path, err))
		}
	}
	return rollbackErr
}

// jsonMarshalPurgeIntent keeps the operation format private to the site
// package while sharing the same validation and encoding rules as the normal
// single-file persistence path.
func jsonMarshalPurgeIntent(intent PurgeIntent) ([]byte, error) {
	data, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode purge intent: %w", err)
	}
	return append(data, '\n'), nil
}
