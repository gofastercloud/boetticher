package dns

// PowerDNSCommand is the reviewable, deterministic command contract used by
// the DNS role. TSIG material is supplied to sqlite3 through protected stdin,
// never as a process argument.
type PowerDNSCommand struct {
	Args        []string `json:"args"`
	Stdin       string   `json:"stdin,omitempty"`
	SecretStdin bool     `json:"secret_stdin,omitempty"`
}

const DDNSSecretPlaceholder = "<ddns-tsig-secret>"

// PrimaryCommandPlan returns the PowerDNS 4.9 command forms used to create
// the platform zones, static records, and authenticated DDNS metadata. The
// The Ansible role supplies the TSIG value only through command stdin while
// the PowerDNS daemon is stopped. The database schema is the supported
// PowerDNS 4.9 gsqlite3 TSIG store; the following metadata commands remain
// reviewable pdnsutil invocations.
func PrimaryCommandPlan(plan Plan) []PowerDNSCommand {
	commands := make([]PowerDNSCommand, 0)
	for _, zone := range allZones(plan) {
		commands = append(commands,
			PowerDNSCommand{Args: []string{"pdnsutil", "zone", "create", zone}},
			PowerDNSCommand{Args: []string{"pdnsutil", "rrset", "replace", zone, zone, "NS", "300", "lab-dns-01." + plan.StaticZone + ".", "lab-dns-02." + plan.StaticZone + "."}},
		)
	}
	if plan.DDNS.Enabled {
		for _, zone := range plan.DDNS.Zones {
			if len(plan.DDNS.UpdateSources) == 0 {
				break
			}
			commands = append(commands,
				PowerDNSCommand{Args: []string{"sqlite3", "/var/lib/powerdns/pdns.sqlite3"}, Stdin: "INSERT OR REPLACE INTO tsigkeys (name, algorithm, secret) VALUES ('" + zone.TSIGKeyName + "', '" + plan.DDNS.TSIGAlgorithm + "', '" + DDNSSecretPlaceholder + "');", SecretStdin: true},
				PowerDNSCommand{Args: []string{"pdnsutil", "metadata", "set", zone.ForwardZone, "ALLOW-DNSUPDATE-FROM", plan.DDNS.UpdateSources[0]}},
				PowerDNSCommand{Args: []string{"pdnsutil", "metadata", "set", zone.ForwardZone, "TSIG-ALLOW-DNSUPDATE", zone.TSIGKeyName}},
				PowerDNSCommand{Args: []string{"pdnsutil", "metadata", "set", zone.ReverseZone, "ALLOW-DNSUPDATE-FROM", plan.DDNS.UpdateSources[0]}},
				PowerDNSCommand{Args: []string{"pdnsutil", "metadata", "set", zone.ReverseZone, "TSIG-ALLOW-DNSUPDATE", zone.TSIGKeyName}},
			)
		}
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
