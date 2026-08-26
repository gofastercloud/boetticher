package dns

import (
	"fmt"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"gopkg.in/yaml.v3"
)

// BlockyConfig is the bounded client-facing resolver contract. Authoritative
// zones are mapped explicitly so a negative answer cannot fall through to a
// public upstream.
type BlockyConfig struct {
	Upstream    BlockyUpstream    `yaml:"upstream"`
	Conditional BlockyConditional `yaml:"conditional"`
	Blocking    BlockyBlocking    `yaml:"blocking"`
	Ports       BlockyPorts       `yaml:"ports"`
	Caching     BlockyCaching     `yaml:"caching"`
	ConnectIP   string            `yaml:"connectIP,omitempty"`
}

type BlockyUpstream struct {
	Defaults []string `yaml:"default"`
}

type BlockyConditional struct {
	Mapping map[string][]string `yaml:"mapping"`
}

type BlockyBlocking struct {
	Denylists    map[string][]string `yaml:"denylists,omitempty"`
	ClientGroups map[string][]string `yaml:"clientGroups,omitempty"`
}

type BlockyPorts struct {
	DNS int `yaml:"dns"`
}

type BlockyCaching struct {
	MinTime string `yaml:"minTime,omitempty"`
}

// RenderBlockyConfig renders only provider configuration. It contains no
// credentials or mutable site secrets and is regenerated from the canonical
// DNS plan for every deployment.
func RenderBlockyConfig(plan Plan) ([]byte, error) {
	if plan.RecursiveProvider != string(model.DNSProviderBlocky) {
		return nil, fmt.Errorf("Blocky renderer cannot render provider %q", plan.RecursiveProvider)
	}
	if !plan.AuthoritativeNXDOMAINNoLeak {
		return nil, fmt.Errorf("Blocky authoritative mappings must reject public fallback")
	}
	if len(plan.RecursiveUpstreams) == 0 || len(plan.AuthoritativeForwardZones) == 0 {
		return nil, fmt.Errorf("Blocky renderer requires public upstreams and authoritative zones")
	}
	mapping := make(map[string][]string, len(plan.AuthoritativeForwardZones)+len(plan.AuthoritativeReverseZones))
	for _, zone := range append(append([]string(nil), plan.AuthoritativeForwardZones...), plan.AuthoritativeReverseZones...) {
		zone = strings.TrimSuffix(strings.ToLower(zone), ".")
		if zone == "" {
			return nil, fmt.Errorf("Blocky authoritative zone cannot be empty")
		}
		mapping[zone] = []string{plan.AuthoritativeForwardTarget}
	}
	config, err := yaml.Marshal(BlockyConfig{
		Upstream:    BlockyUpstream{Defaults: append([]string(nil), plan.RecursiveUpstreams...)},
		Conditional: BlockyConditional{Mapping: mapping},
		Ports:       BlockyPorts{DNS: 53},
		Caching:     BlockyCaching{MinTime: "5m"},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal Blocky configuration: %w", err)
	}
	return config, nil
}
