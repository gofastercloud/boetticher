package cli

// commandSpec is the single source for the public top-level command reference
// printed by the CLI. Detailed flag help remains owned by each command's
// standard-library flag set.
type commandSpec struct {
	Usage string
}

var commandSpecs = []commandSpec{
	{Usage: "boetticher init [--site-dir DIR] [--age-identity PATH] [--external-firewall]"},
	{Usage: "boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--initial-user USER] [--known-hosts PATH] [--trunk-interface IFACE]"},
	{Usage: "boetticher bootstrap [--site DIR] [--age-identity PATH] [--recovery-confirmed] [--storage-confirmed] [--operator-key PATH] [--initial-user USER] [--known-hosts PATH] [--proxmox-ca PATH] [--insecure] [--trunk-interface IFACE] [--dry-run]"},
	{Usage: "boetticher deploy [--site DIR] [--age-identity PATH] [--proxmox-ca PATH] [--zabbix-url URL] [--insecure] [--ansible-playbook PATH] [--debian-template TEMPLATE] [--dry-run]"},
	{Usage: "boetticher verify [--site DIR] [--ssh-config PATH] [--ssh-journey]"},
	{Usage: "boetticher doctor [--site DIR] [--ssh-config PATH] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher upgrade [--site DIR] [--age-identity PATH] [--recovery-confirmed]"},
	{Usage: "boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--identity-file PATH] [--install-include]"},
	{Usage: "boetticher access [--site DIR]"},
	{Usage: "boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]"},
	{Usage: "boetticher network trunk status|attach|detach [INTERFACE] [--site DIR] [--confirm] [--live] [--age-identity PATH] [--proxmox-ca PATH] [--insecure]"},
	{Usage: "boetticher pki client create|export|revoke NAME [--site DIR] [--output PATH] [--age-identity PATH]"},
	{Usage: "boetticher pki trust export [--site DIR] [--output PATH| -] [--age-identity PATH]"},
	{Usage: "boetticher firewall status|show|diff|counters|logs|verify [--site DIR] [--live] [--json]"},
	{Usage: "boetticher dhcp status|leases [--site DIR] [--live] [--json]"},
	{Usage: "boetticher storage status|initialize [--site DIR] [--live] [--confirmed]"},
	{Usage: "boetticher portal build [--site DIR] [--output DIR] [--docs DIR]"},
}
