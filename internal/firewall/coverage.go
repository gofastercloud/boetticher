package firewall

import (
	"fmt"
	"reflect"

	"github.com/gofastercloud/boetticher/internal/model"
)

// ValidateNetworkIntentCoverage proves that every composed module intent has
// a corresponding generated rule before managed policy can be applied. In
// external mode the owned assertion is deliberately narrower: only contract
// generation is validated because the external firewall is not inspectable.
func ValidateNetworkIntentCoverage(s model.Site, plan Plan) error {
	if s.Gateway.Mode == model.GatewayModeExternal {
		if _, err := RenderExternalContract(s, plan); err != nil {
			return fmt.Errorf("generate external firewall contract: %w", err)
		}
		return nil
	}

	for _, declaration := range s.Declarations {
		for _, intent := range declaration.NetworkIntents {
			// This declaration names the Core-owned journal-upload source set.
			// The fixed policy has an explicit Proxmox member, which is the
			// inspectable representative used to prove that the path exists.
			// It avoids inventing a second source selector for the Core set.
			source := intent.Source
			if source == "boetticher-managed-endpoints" {
				source = model.LogicalProxmoxIdentity
			}
			if intent.Direction != "egress" {
				return fmt.Errorf("module %s network intent %q uses unsupported managed direction %q", declaration.Module, intent.Purpose, intent.Direction)
			}
			intent.Source = source
			want := policyRuleForIntent(s, declaration.Module, intent)
			if want.Name == "" {
				return fmt.Errorf("module %s network intent %q cannot be rendered", declaration.Module, intent.Purpose)
			}
			covered := false
			for _, rule := range plan.Rules {
				if rule.Action == "allow" && ruleEquivalent(rule, want) {
					covered = true
					break
				}
			}
			if !covered {
				return fmt.Errorf("module %s network intent %q is missing from generated managed firewall policy", declaration.Module, intent.Purpose)
			}
		}
	}
	return nil
}

func ruleEquivalent(left, right PolicyRule) bool {
	return left.From == right.From && left.To == right.To &&
		left.Protocol == right.Protocol &&
		reflect.DeepEqual(left.Ports, right.Ports) &&
		left.SourceCIDR == right.SourceCIDR &&
		left.DestinationCIDR == right.DestinationCIDR &&
		left.DestinationHost == right.DestinationHost
}
