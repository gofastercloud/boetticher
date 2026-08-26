package cli

// commandSpec is the single source for the public top-level command reference
// printed by the CLI. Detailed flag help remains owned by each command's
// standard-library flag set.
type commandSpec struct {
	Usage string
}

var commandSpecs = []commandSpec{
	{Usage: "boetticher init [--site-dir DIR] [--age-identity PATH]"},
	{Usage: "boetticher preflight [--site DIR] [--live] [--bootstrap-address ADDRESS] [--trunk-interface IFACE]"},
	{Usage: "boetticher bootstrap [--site DIR] [--opnsense-iso PATH] [--recovery-confirmed] [--trunk-interface IFACE] [--dry-run]"},
	{Usage: "boetticher provision [--site DIR] [--debian-template TEMPLATE] [--dry-run]"},
	{Usage: "boetticher converge [--site DIR] [--opnsense-url URL] [--dry-run]"},
	{Usage: "boetticher verify | doctor | upgrade [--site DIR]"},
	{Usage: "boetticher ssh-config [--site DIR] [--output PATH| -] [--force] [--check] [--install-include]"},
	{Usage: "boetticher access [--site DIR]"},
	{Usage: "boetticher bootstrap-endpoint show|set ADDRESS [--site DIR]"},
	{Usage: "boetticher network trunk status|attach|detach [INTERFACE] [--site DIR]"},
	{Usage: "boetticher pki client create|export|revoke NAME [--site DIR]"},
	{Usage: "boetticher pki trust export [--site DIR]"},
	{Usage: "boetticher opnsense credentials import [--site DIR] < credentials.json"},
	{Usage: "boetticher portal build [--site DIR] [--output DIR] [--docs DIR]"},
}
