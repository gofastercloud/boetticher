package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	snapshotSchema   = "boetticher/lab-snapshot/v1"
	snapshotStaleAge = 10 * time.Minute
	maxSnapshotBytes = 512 * 1024
	maxDocumentation = 128
	maxDocumentBytes = 256 * 1024
)

type labSnapshot struct {
	Schema       string                `json:"schema"`
	Generation   string                `json:"generation"`
	GeneratedAt  time.Time             `json:"generated_at"`
	StaleAfter   time.Time             `json:"stale_after"`
	Stale        bool                  `json:"stale"`
	Source       snapshotSource        `json:"source"`
	Summary      map[string]string     `json:"summary"`
	Desired      any                   `json:"desired"`
	Observations []snapshotObservation `json:"observations"`
	Links        []endpoint            `json:"links"`
	Documents    []snapshotDocument    `json:"documents"`
}

type snapshotSource struct {
	Path      string `json:"path"`
	Revision  string `json:"revision,omitempty"`
	FactsPath string `json:"facts_path,omitempty"`
}

type snapshotObservation struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Desired    string    `json:"desired"`
	State      string    `json:"state"`
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`
	Detail     string    `json:"detail,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type snapshotDocument struct {
	Path       string    `json:"path"`
	Title      string    `json:"title"`
	Historical bool      `json:"historical,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type snapshotFacts struct {
	Observations []snapshotObservation `json:"observations"`
}

func buildSnapshot(labPath, factsPath, docsRoot string, now time.Time) (labSnapshot, error) {
	b, err := os.ReadFile(labPath)
	if err != nil {
		return labSnapshot{}, fmt.Errorf("read lab configuration: %w", err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return labSnapshot{}, fmt.Errorf("parse lab configuration: %w", err)
	}
	normalizeMap(raw)
	links := publications(raw)
	sort.SliceStable(links, func(i, j int) bool { return links[i].Group+links[i].Name < links[j].Group+links[j].Name })
	observations := configuredObservations(raw, now)
	if factsPath != "" {
		if data, readErr := os.ReadFile(factsPath); readErr == nil && len(data) <= maxSnapshotBytes {
			var facts snapshotFacts
			if json.Unmarshal(data, &facts) == nil {
				observations = mergeObservations(observations, facts.Observations)
			}
		}
	}
	documents := documentation(docsRoot)
	generation := now.UTC().Format("20060102T150405Z")
	snapshot := labSnapshot{
		Schema: snapshotSchema, Generation: generation, GeneratedAt: now.UTC(), StaleAfter: now.UTC().Add(snapshotStaleAge),
		Source: snapshotSource{Path: labPath, FactsPath: factsPath}, Summary: summary(raw), Desired: redact(raw),
		Observations: observations, Links: links, Documents: documents,
	}
	return snapshot, nil
}

func configuredObservations(raw map[string]any, now time.Time) []snapshotObservation {
	observations := []snapshotObservation{{Name: "lab-intent", Kind: "desired", Desired: "configured", State: "observed", Source: "lab.yml", ObservedAt: now.UTC(), Detail: "Typed lab intent was read and redacted."}}
	modules, _ := raw["modules"].(map[string]any)
	keys := make([]string, 0, len(modules))
	for key := range modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		state := "unknown"
		desired := "configured"
		if item, ok := modules[key].(map[string]any); ok {
			if enabled, exists := item["enabled"].(bool); exists {
				if enabled {
					state = "unknown"
				} else {
					state, desired = "off", "disabled"
				}
			}
		}
		observations = append(observations, snapshotObservation{Name: "module." + key, Kind: "module", Desired: desired, State: state, Source: "lab.yml", ObservedAt: now.UTC(), Detail: "Live provider state is not inferred from desired intent."})
	}
	return observations
}

func mergeObservations(base, facts []snapshotObservation) []snapshotObservation {
	byName := make(map[string]snapshotObservation, len(base)+len(facts))
	for _, item := range base {
		byName[item.Name] = item
	}
	for _, item := range facts {
		if item.Name == "" || item.ObservedAt.IsZero() {
			continue
		}
		byName[item.Name] = item
	}
	keys := make([]string, 0, len(byName))
	for key := range byName {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]snapshotObservation, 0, len(keys))
	for _, key := range keys {
		out = append(out, byName[key])
	}
	return out
}

func documentation(root string) []snapshotDocument {
	if root == "" {
		return nil
	}
	var docs []snapshotDocument
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || len(docs) >= maxDocumentation {
			return nil
		}
		if filepath.Ext(path) != ".md" || info.Size() > maxDocumentBytes {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
		title := strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))
		docs = append(docs, snapshotDocument{Path: filepath.ToSlash(rel), Title: strings.ReplaceAll(title, "-", " "), UpdatedAt: info.ModTime().UTC()})
		return nil
	})
	sort.Slice(docs, func(i, j int) bool { return docs[i].Path < docs[j].Path })
	return docs
}

func writeSnapshotAtomic(dir string, snapshot labSnapshot) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxSnapshotBytes {
		return errors.New("lab snapshot exceeds its bound")
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".snapshot-*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0640); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(dir, "snapshot.json"))
}

func readSnapshot(path string) (labSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return labSnapshot{}, err
	}
	if len(data) > maxSnapshotBytes {
		return labSnapshot{}, errors.New("snapshot exceeds its bound")
	}
	var snapshot labSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return labSnapshot{}, err
	}
	snapshot.Stale = time.Now().UTC().After(snapshot.StaleAfter)
	return snapshot, nil
}
