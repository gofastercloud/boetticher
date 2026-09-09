package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const SecretStorePath = "/etc/boetticher/observability-secrets.json"

// SecretStore holds values only in a mode-0600 Controller-local file. Values
// are deliberately accepted on stdin and are never represented in CLI argv or
// status output.
type SecretStore struct{ Path string }

func (s SecretStore) path() string {
	if s.Path == "" {
		return SecretStorePath
	}
	return s.Path
}
func (s SecretStore) Load() (map[string][]byte, error) {
	path := s.path()
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return nil, fmt.Errorf("validate observability secret store: %w", err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read observability secret store: %w", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode observability secret store: %w", err)
	}
	result := make(map[string][]byte, len(raw))
	for name, value := range raw {
		if !safeSecretName(name) || strings.TrimSpace(value) == "" {
			return nil, errors.New("observability secret store contains an invalid entry")
		}
		result[name] = []byte(value)
	}
	return result, nil
}
func (s SecretStore) Names() ([]string, error) {
	values, err := s.Load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
func (s SecretStore) Set(name string, value []byte) error {
	if !safeSecretName(name) || len(value) == 0 || len(value) > 64*1024 || bytes.IndexByte(value, 0) >= 0 {
		return errors.New("observability secret name or value is invalid")
	}
	values, err := s.Load()
	if err != nil {
		return err
	}
	values[name] = append([]byte(nil), value...)
	return s.write(values)
}
func (s SecretStore) Remove(name string) (bool, error) {
	if !safeSecretName(name) {
		return false, errors.New("observability secret name is invalid")
	}
	values, err := s.Load()
	if err != nil {
		return false, err
	}
	_, found := values[name]
	delete(values, name)
	if err := s.write(values); err != nil {
		return false, err
	}
	return found, nil
}
func (s SecretStore) write(values map[string][]byte) error {
	raw := make(map[string]string, len(values))
	for name, value := range values {
		raw[name] = string(value)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	path := s.path()
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return pathguard.WriteFileWithParentMode(path, append(data, '\n'), 0600, 0755)
}
func safeSecretName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, char := range name {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
			return false
		}
	}
	return true
}
