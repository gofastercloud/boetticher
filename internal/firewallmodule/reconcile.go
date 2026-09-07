package firewallmodule

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/gofastercloud/boetticher/internal/openwrt"
)

type MutationKind string

const (
	MutationCreate MutationKind = "create"
	MutationUpdate MutationKind = "update"
	MutationDelete MutationKind = "delete"
)

type Mutation struct {
	Kind    MutationKind
	Section Section
}

// DiffOwned computes the minimal mutations for one UCI package. Only named
// boetticher sections are considered; unrelated provider-native sections are
// deliberately absent from the result.
func DiffOwned(current map[string]openwrt.UCISection, desired []Section) []Mutation {
	wanted := make(map[string]Section, len(desired))
	for _, section := range desired {
		wanted[section.Name] = section
	}
	mutations := make([]Mutation, 0)
	for _, name := range sortedSectionNames(desired) {
		section := wanted[name]
		observed, exists := current[name]
		if !exists {
			mutations = append(mutations, Mutation{Kind: MutationCreate, Section: section})
			continue
		}
		if !sameSection(observed, section) {
			mutations = append(mutations, Mutation{Kind: MutationUpdate, Section: section})
		}
	}
	stale := make([]string, 0)
	for name := range current {
		if len(name) >= len("boetticher_") && name[:len("boetticher_")] == "boetticher_" {
			if _, exists := wanted[name]; !exists {
				stale = append(stale, name)
			}
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		mutations = append(mutations, Mutation{Kind: MutationDelete, Section: Section{Name: name}})
	}
	return mutations
}

func sameSection(observed openwrt.UCISection, desired Section) bool {
	if observed.Type != desired.Type || len(observed.Options) != len(desired.Options) || len(observed.Lists) != len(desired.Lists) {
		return false
	}
	for key, value := range desired.Options {
		if observed.Options[key] != value {
			return false
		}
	}
	for key, values := range desired.Lists {
		if len(observed.Lists[key]) != len(values) {
			return false
		}
		for index := range values {
			if observed.Lists[key][index] != values[index] {
				return false
			}
		}
	}
	return true
}

type uciWriter interface {
	UCIAddNamed(context.Context, string, string, string) (string, error)
	UCISet(context.Context, string, string, string, string) error
	UCISetList(context.Context, string, string, string, []string) error
	UCIDelete(context.Context, string, string, string) error
	UCICommit(context.Context, string) error
	UCIApply(context.Context, int) error
}

// ReconcileOwned applies one package's named sections and returns the number
// of semantic changes. It does not touch any unowned section.
func ReconcileOwned(ctx context.Context, client uciWriter, packageName string, current map[string]openwrt.UCISection, desired []Section) (int, error) {
	if client == nil {
		return 0, errors.New("provider UCI client is required")
	}
	mutations := DiffOwned(current, desired)
	for _, mutation := range mutations {
		section := mutation.Section
		switch mutation.Kind {
		case MutationCreate:
			created, err := client.UCIAddNamed(ctx, packageName, section.Type, section.Name)
			if err != nil {
				return 0, fmt.Errorf("create provider section %s: %w", section.Name, err)
			}
			if created != section.Name {
				return 0, fmt.Errorf("create provider section %s returned unexpected name %q", section.Name, created)
			}
			if err := writeSection(ctx, client, packageName, section, nil); err != nil {
				return 0, err
			}
		case MutationUpdate:
			observed := current[section.Name]
			if err := writeSection(ctx, client, packageName, section, &observed); err != nil {
				return 0, err
			}
		case MutationDelete:
			if err := client.UCIDelete(ctx, packageName, section.Name, ""); err != nil {
				return 0, fmt.Errorf("delete stale provider section %s: %w", section.Name, err)
			}
		default:
			return 0, fmt.Errorf("unsupported provider mutation %q", mutation.Kind)
		}
	}
	if len(mutations) == 0 {
		return 0, nil
	}
	if err := client.UCICommit(ctx, packageName); err != nil {
		return 0, err
	}
	if err := client.UCIApply(ctx, 30); err != nil {
		return 0, err
	}
	return len(mutations), nil
}

func writeSection(ctx context.Context, client uciWriter, packageName string, desired Section, observed *openwrt.UCISection) error {
	if observed != nil && observed.Type != desired.Type {
		return fmt.Errorf("provider section %s has type %q, expected %q", desired.Name, observed.Type, desired.Type)
	}
	if observed != nil {
		for option := range observed.Options {
			if _, keep := desired.Options[option]; !keep {
				if err := client.UCIDelete(ctx, packageName, desired.Name, option); err != nil {
					return fmt.Errorf("remove stale provider option %s.%s: %w", desired.Name, option, err)
				}
			}
		}
		for list := range observed.Lists {
			if _, keep := desired.Lists[list]; !keep {
				if err := client.UCIDelete(ctx, packageName, desired.Name, list); err != nil {
					return fmt.Errorf("remove stale provider list %s.%s: %w", desired.Name, list, err)
				}
			}
		}
	}
	optionNames := make([]string, 0, len(desired.Options))
	for option := range desired.Options {
		optionNames = append(optionNames, option)
	}
	sort.Strings(optionNames)
	for _, option := range optionNames {
		if observed != nil && observed.Options[option] == desired.Options[option] {
			continue
		}
		if err := client.UCISet(ctx, packageName, desired.Name, option, desired.Options[option]); err != nil {
			return fmt.Errorf("set provider option %s.%s: %w", desired.Name, option, err)
		}
	}
	listNames := make([]string, 0, len(desired.Lists))
	for list := range desired.Lists {
		listNames = append(listNames, list)
	}
	sort.Strings(listNames)
	for _, list := range listNames {
		values := desired.Lists[list]
		if observed != nil && sameStringSlice(observed.Lists[list], values) {
			continue
		}
		if observed != nil && len(observed.Lists[list]) > 0 {
			if err := client.UCIDelete(ctx, packageName, desired.Name, list); err != nil {
				return fmt.Errorf("reset provider list %s.%s: %w", desired.Name, list, err)
			}
		}
		if err := client.UCISetList(ctx, packageName, desired.Name, list, values); err != nil {
			return fmt.Errorf("set provider list %s.%s: %w", desired.Name, list, err)
		}
	}
	return nil
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
