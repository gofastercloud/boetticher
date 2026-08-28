package aiops

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
)

type EvidenceCatalog struct {
	Hosts map[string][]string `json:"hosts"`
}

func LoadEvidenceCatalog(path string) (EvidenceCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EvidenceCatalog{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var catalog EvidenceCatalog
	if err := decoder.Decode(&catalog); err != nil || len(catalog.Hosts) == 0 {
		return EvidenceCatalog{}, errors.New("evidence catalog is empty or invalid")
	}
	for host, units := range catalog.Hosts {
		if !safeToken(host) {
			return EvidenceCatalog{}, errors.New("evidence catalog contains an invalid host")
		}
		for _, unit := range units {
			if !safeToken(unit) {
				return EvidenceCatalog{}, errors.New("evidence catalog contains an invalid service unit")
			}
		}
	}
	return catalog, nil
}

func (c EvidenceCatalog) Policy(incident Incident) (EvidencePolicy, error) {
	if !safeIdentifier(incident.ID) || !safeIdentifier(incident.PulseAlertID) || !safeResourceID(incident.ResourceID) {
		return EvidencePolicy{}, errors.New("incident has invalid evidence bindings")
	}
	hosts := make(map[string]map[string]bool, len(c.Hosts))
	for host, units := range c.Hosts {
		hosts[host] = make(map[string]bool, len(units))
		for _, unit := range units {
			hosts[host][unit] = true
		}
	}
	return EvidencePolicy{IncidentID: incident.ID, PulseAlertID: incident.PulseAlertID, ResourceIDs: map[string]bool{incident.ResourceID: true}, Hosts: hosts}, nil
}
