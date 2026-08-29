package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const pendingDNSDeletionsFile = "dns/pending-deletions.json"

// LoadPendingDNSDeletions reads controller-local DNS deletion work that is
// deliberately separate from site.yml and therefore does not affect the
// canonical model revision.
func LoadPendingDNSDeletions(dir string, s model.Site) ([]model.DNSDeletion, error) {
	path := filepath.Join(modelRuntimeDir(s), pendingDNSDeletionsFile)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return nil, fmt.Errorf("validate pending DNS deletion path: %w", err)
	}
	data, err := pathguard.ReadFileLimited(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pending DNS deletions: %w", err)
	}
	var deletions []model.DNSDeletion
	if err := json.Unmarshal(data, &deletions); err != nil {
		return nil, fmt.Errorf("decode pending DNS deletions: %w", err)
	}
	deletions, err = normalizeDNSDeletions(deletions, s)
	if err != nil {
		return nil, fmt.Errorf("validate pending DNS deletions: %w", err)
	}
	return deletions, nil
}

// SavePendingDNSDeletions atomically persists only exact user RRset deletions.
// The site directory argument is retained in the API to keep callers from
// accidentally treating this runtime state as a site-repository file.
func SavePendingDNSDeletions(dir string, s model.Site, deletions []model.DNSDeletion) error {
	_ = dir
	normalized, err := normalizeDNSDeletions(deletions, s)
	if err != nil {
		return fmt.Errorf("validate pending DNS deletions: %w", err)
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("encode pending DNS deletions: %w", err)
	}
	return atomicWrite(filepath.Join(modelRuntimeDir(s), pendingDNSDeletionsFile), append(data, '\n'), 0600)
}

func modelRuntimeDir(s model.Site) string {
	return RuntimeDir(s)
}

func normalizeDNSDeletions(input []model.DNSDeletion, s model.Site) ([]model.DNSDeletion, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.Network.Domain), "."))
	owned := map[string]struct{}{}
	for _, component := range s.PlatformComponents() {
		owned[qualifiedRuntimeDNSName(component.Hostname, domain)] = struct{}{}
		for _, alias := range component.DNSAliases {
			owned[qualifiedRuntimeDNSName(alias, domain)] = struct{}{}
		}
		if component.URL != "" {
			if parsed, err := url.Parse(component.URL); err == nil && parsed.Hostname() != "" {
				owned[qualifiedRuntimeDNSName(parsed.Hostname(), domain)] = struct{}{}
			}
		}
	}
	for _, declaration := range s.Declarations {
		for _, record := range declaration.DNSRecords {
			owned[strings.ToLower(strings.TrimSuffix(record.Name, "."))] = struct{}{}
		}
	}
	managedZones := map[string]struct{}{}
	for _, zone := range s.Network.Zones {
		if zone.Type == model.ZoneTypeServers || zone.Type == model.ZoneTypeTrusted || zone.Type == model.ZoneTypeSandbox {
			managedZones[strings.ToLower(zone.Name)+"."+domain] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	result := make([]model.DNSDeletion, 0, len(input))
	for _, deletion := range input {
		deletion.Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(deletion.Name), "."))
		deletion.Type = strings.ToUpper(strings.TrimSpace(deletion.Type))
		key := deletion.Name + "\x00" + deletion.Type
		if deletion.Name == "" || (deletion.Type != "A" && deletion.Type != "CNAME") {
			return nil, fmt.Errorf("invalid deletion %q %q", deletion.Name, deletion.Type)
		}
		if domain == "" || !strings.HasSuffix(deletion.Name, "."+domain) || deletion.Name == domain {
			return nil, fmt.Errorf("deletion name %q is outside %s", deletion.Name, domain)
		}
		for _, label := range strings.Split(deletion.Name, ".") {
			if !model.IsDNSLabel(label) {
				return nil, fmt.Errorf("deletion name %q contains an unsafe label", deletion.Name)
			}
		}
		if _, exists := owned[deletion.Name]; exists || runtimeDNSNameInManagedZone(deletion.Name, managedZones) {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, deletion)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].Type < result[j].Type
	})
	return result, nil
}

func qualifiedRuntimeDNSName(raw, domain string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if strings.HasSuffix(name, "."+domain) {
		return name
	}
	return name + "." + domain
}

func runtimeDNSNameInManagedZone(name string, zones map[string]struct{}) bool {
	for zone := range zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}
