package cli

import (
	"fmt"

	statusmodel "github.com/gofastercloud/boetticher/internal/status"
)

// checkDefinition is the single operator-facing check contract. IDs are
// stable machine keys; labels are presentation only and must never be used
// for filtering or evidence-tier assignment.
type checkDefinition struct {
	ID            string
	Label         string
	EvidenceTier  statusmodel.EvidenceTier
	HealthVisible bool
}

const (
	checkDesiredPlatformModel       = "desired_platform_model"
	checkCanonicalPlatformModel     = "canonical_platform_model_validates"
	checkFirewallPolicyProjection   = "firewall_policy_projection"
	checkDNSDDNSProjection          = "dns_ddns_projection"
	checkPulseMonitoringProjection  = "pulse_monitoring_projection"
	checkPlatformBackupProjection   = "platform_backup_projection"
	checkStorageProjection          = "storage_projection"
	checkQualifiedApplianceEvidence = "qualified_appliance_evidence"
	checkDeploymentOperationState   = "deployment_operation_state"
	checkSSHBastionAllowList        = "ssh_bastion_allow_list"
	checkGeneratedSSHConfiguration  = "generated_ssh_configuration"
	checkAuthenticatedSSHJourney    = "authenticated_ssh_journey"
	checkManagedGatewayDHCPDDNS     = "managed_gateway_dhcp_ddns"
	checkManagedGatewayUpstreamDHCP = "managed_gateway_upstream_dhcp"
	checkPublishedServiceMapping    = "published_service_mapping"
	checkManagedGatewayServices     = "managed_gateway_services"
	checkSmallstepCAService         = "smallstep_ca_service"
	checkPulseLeafCertificate       = "pulse_leaf_certificate"
	checkExternalGatewayContract    = "external_gateway_contract"
)

var checkDefinitions = []checkDefinition{
	{ID: checkDesiredPlatformModel, Label: "desired platform model", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkCanonicalPlatformModel, Label: "canonical platform model validates", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkFirewallPolicyProjection, Label: "firewall policy projection", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkDNSDDNSProjection, Label: "DNS/DDNS projection", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkPulseMonitoringProjection, Label: "Pulse monitoring projection", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkPlatformBackupProjection, Label: "platform backup projection", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkStorageProjection, Label: "storage projection", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkQualifiedApplianceEvidence, Label: "qualified appliance evidence", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkDeploymentOperationState, Label: "deployment operation state", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkSSHBastionAllowList, Label: "SSH bastion allow-list", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkGeneratedSSHConfiguration, Label: "generated SSH configuration", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
	{ID: checkAuthenticatedSSHJourney, Label: "authenticated SSH journey via Proxmox bastion", EvidenceTier: statusmodel.TierJourney, HealthVisible: true},
	{ID: checkManagedGatewayDHCPDDNS, Label: "managed gateway DHCP/DDNS", EvidenceTier: statusmodel.TierJourney, HealthVisible: true},
	{ID: checkManagedGatewayUpstreamDHCP, Label: "managed gateway upstream DHCP", EvidenceTier: statusmodel.TierDeployed, HealthVisible: true},
	{ID: checkPublishedServiceMapping, Label: "published service mapping", EvidenceTier: statusmodel.TierDeployed, HealthVisible: true},
	{ID: checkManagedGatewayServices, Label: "managed gateway services", EvidenceTier: statusmodel.TierDeployed, HealthVisible: true},
	{ID: checkSmallstepCAService, Label: "Smallstep CA service", EvidenceTier: statusmodel.TierDeployed, HealthVisible: true},
	{ID: checkPulseLeafCertificate, Label: "Pulse leaf certificate", EvidenceTier: statusmodel.TierDeployed, HealthVisible: true},
	{ID: checkExternalGatewayContract, Label: "external gateway contract", EvidenceTier: statusmodel.TierLocal, HealthVisible: true},
}

func checkDefinitionByID(id string) (checkDefinition, bool) {
	for _, definition := range checkDefinitions {
		if definition.ID == id {
			return definition, true
		}
	}
	return checkDefinition{}, false
}

func checkDefinitionByLabel(label string) (checkDefinition, bool) {
	for _, definition := range checkDefinitions {
		if definition.Label == label {
			return definition, true
		}
	}
	return checkDefinition{}, false
}

func checkResult(id, status, detail string) statusmodel.CheckResult {
	definition, _ := checkDefinitionByID(id)
	return statusmodel.CheckResult{ID: id, Name: definition.Label, Status: status, Detail: detail}
}

func normalizeCheckResult(result *statusmodel.CheckResult) (checkDefinition, error) {
	definition, ok := checkDefinitionByID(result.ID)
	if !ok && result.ID == "" {
		definition, ok = checkDefinitionByLabel(result.Name)
		if ok {
			result.ID = definition.ID
		}
	}
	if !ok {
		key := result.ID
		if key == "" {
			key = result.Name
		}
		return checkDefinition{}, fmt.Errorf("verification result %q is not in the evidence contract", key)
	}
	result.Name = definition.Label
	result.Tier = definition.EvidenceTier
	return definition, nil
}
