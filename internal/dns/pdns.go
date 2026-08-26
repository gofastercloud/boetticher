package dns

// PowerDNSCommand is the reviewable, deterministic command contract used by
// the DNS role. Secret arguments are represented by a placeholder so this
// plan can safely be included in generated variables and tests.
type PowerDNSCommand struct {
	Args        []string `json:"args"`
	SecretIndex int      `json:"secret_index,omitempty"`
}

const DDNSSecretPlaceholder = "<ddns-tsig-secret>"

// PrimaryCommandPlan returns the PowerDNS 4.9 command forms used to create
// the platform zones, static records, and authenticated DDNS metadata. The
// Ansible role supplies the same values with the secret inserted only in the
// no_log TSIG import task.
func PrimaryCommandPlan(plan Plan) []PowerDNSCommand {
	commands := make([]PowerDNSCommand, 0)
	for _, zone := range allZones(plan) {
		commands = append(commands,
			PowerDNSCommand{Args: []string{"pdnsutil", "zone", "create", zone}},
			PowerDNSCommand{Args: []string{"pdnsutil", "rrset", "replace", zone, zone, "NS", "300", "lab-dns-01." + plan.StaticZone + ".", "lab-dns-02." + plan.StaticZone + "."}},
		)
	}
	for _, zone := range plan.DDNS.Zones {
		commands = append(commands,
			PowerDNSCommand{Args: []string{"pdnsutil", "tsigkey", "import", zone.TSIGKeyName, plan.DDNS.TSIGAlgorithm, DDNSSecretPlaceholder}, SecretIndex: 6},
			PowerDNSCommand{Args: []string{"pdnsutil", "metadata", "set", zone.ForwardZone, "ALLOW-DNSUPDATE-FROM", plan.DDNS.UpdateSources[0]}},
			PowerDNSCommand{Args: []string{"pdnsutil", "metadata", "set", zone.ForwardZone, "TSIG-ALLOW-DNSUPDATE", zone.TSIGKeyName}},
			PowerDNSCommand{Args: []string{"pdnsutil", "metadata", "set", zone.ReverseZone, "ALLOW-DNSUPDATE-FROM", plan.DDNS.UpdateSources[0]}},
			PowerDNSCommand{Args: []string{"pdnsutil", "metadata", "set", zone.ReverseZone, "TSIG-ALLOW-DNSUPDATE", zone.TSIGKeyName}},
		)
	}
	for _, record := range plan.StaticRecords {
		commands = append(commands, PowerDNSCommand{Args: []string{"pdnsutil", "rrset", "replace", plan.StaticZone, record.Name + ".", record.Type, "300", record.Address}})
	}
	return commands
}

func allZones(plan Plan) []string {
	result := []string{plan.StaticZone}
	for _, zone := range plan.DynamicZones {
		result = append(result, zone.Name)
	}
	for _, zone := range plan.ReverseZones {
		result = append(result, zone.Name)
	}
	return result
}
