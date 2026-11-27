package agentbroker

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Decision is the policy evaluation result for a parsed command.
type Decision struct {
	Allowed bool
	Tier    string
	Reason  string
}

var (
	statusCapabilities = map[string]struct{}{
		"firewall": {}, "dns": {}, "dhcp": {}, "observability": {},
		"logging": {}, "monitoring": {}, "statuspage": {},
		"vpn": {}, "tailnet": {}, "media": {},
	}
	planCapabilities = map[string]struct{}{
		"firewall": {}, "dns": {}, "dhcp": {}, "observability": {},
		"vpn": {}, "tailnet": {}, "media": {},
	}
	applyCapabilities = map[string]struct{}{
		"firewall": {}, "dns": {}, "dhcp": {}, "observability": {},
		"vpn": {}, "tailnet": {}, "media": {},
	}
	loggingLevels = map[string]struct{}{
		"trace": {}, "debug": {}, "info": {}, "notice": {}, "warn": {}, "warning": {},
		"error": {}, "err": {}, "critical": {}, "crit": {}, "alert": {},
		"emergency": {}, "emerg": {}, "fatal": {},
	}
	hardDeniedFlags = []string{
		"--data-disk",
		"--api-key-stdin",
		"--auth-key-file",
		"--cloudflare-token-file",
		"--credentials-file",
	}
)

func allowTier1() Decision {
	return Decision{Allowed: true, Tier: "tier1"}
}

func allowTier2(rule string) Decision {
	return Decision{Allowed: true, Tier: "tier2", Reason: rule}
}

func deny(reason string) Decision {
	return Decision{Allowed: false, Tier: "deny", Reason: reason}
}

// Evaluate checks a parsed argv (starting with "boetticher") against hard-deny
// rules, Tier 1 read-only rules, and opt-in Tier 2 policy rules.
func Evaluate(argv []string, policy Policy) Decision {
	if len(argv) < 2 || argv[0] != "boetticher" {
		return deny("invalid command prefix or missing subcommand")
	}
	args := argv[1:]

	if reason, denied := checkHardDeny(args); denied {
		return deny(reason)
	}

	switch args[0] {
	case "controller":
		return evaluateController(args[1:])
	case "host":
		return evaluateHost(args[1:], policy)
	case "module":
		return evaluateModule(args[1:], policy)
	default:
		return deny(fmt.Sprintf("unrecognised top-level command %q", args[0]))
	}
}

func checkHardDeny(args []string) (string, bool) {
	for _, arg := range args {
		if arg == "teardown" {
			return "hard-denied: teardown is never permitted", true
		}
		if arg == "secrets" {
			return "hard-denied: secrets commands are never permitted", true
		}
		if strings.Contains(arg, "install.sh") {
			return "hard-denied: install.sh is never permitted", true
		}
		for _, flagName := range hardDeniedFlags {
			if arg == flagName || strings.HasPrefix(arg, flagName+"=") {
				return fmt.Sprintf("hard-denied: flag %s is never permitted", flagName), true
			}
		}
	}

	if len(args) >= 2 && args[0] == "controller" {
		switch args[1] {
		case "reboot", "bootstrap", "agent-access":
			return fmt.Sprintf("hard-denied: controller %s is never permitted", args[1]), true
		}
	}

	if len(args) >= 2 && args[0] == "host" && args[1] == "reboot" {
		for _, arg := range args[2:] {
			if arg == "--yes" || strings.HasPrefix(arg, "--yes=") {
				return "hard-denied: host reboot --yes is never permitted", true
			}
		}
	}

	return "", false
}

func evaluateController(args []string) Decision {
	if len(args) == 0 || args[0] != "status" {
		return deny("controller action not permitted")
	}
	rest := args[1:]
	if len(rest) == 0 {
		return allowTier1()
	}
	if val, ok := parseSingleStringFlag(rest, "--operator"); ok && isSafeValue(val) {
		return allowTier1()
	}
	return deny("controller status flags not permitted")
}

func evaluateHost(args []string, policy Policy) Decision {
	if len(args) == 0 {
		return deny("missing host subcommand")
	}
	action, rest := args[0], args[1:]
	switch action {
	case "status":
		if len(rest) == 0 || (len(rest) == 1 && rest[0] == "--details") {
			return allowTier1()
		}
		return deny("host status flags not permitted")
	case "plan-storage", "list-systems":
		if len(rest) == 0 {
			return allowTier1()
		}
		return deny(fmt.Sprintf("host %s accepts no arguments", action))
	case "system-status":
		if len(rest) == 1 && isSafePositional(rest[0]) {
			return allowTier1()
		}
		return deny("host system-status requires exactly one system name")
	case "upgrade":
		if len(rest) == 1 && rest[0] == "--plan" {
			return allowTier1()
		}
		return deny("host upgrade only allows --plan")
	case "reboot":
		return evaluateHostRebootPlan(rest)
	case "start-system", "stop-system":
		if len(rest) != 2 || !isSafePositional(rest[0]) || (rest[1] != "--plan" && rest[1] != "--yes") {
			return deny(fmt.Sprintf("host %s requires <name> and strictly --plan or --yes", action))
		}
		if !policy.Tier2.SystemPower {
			return deny("tier2 system_power is not enabled")
		}
		return allowTier2("system_power")
	default:
		return deny(fmt.Sprintf("host subcommand %q is not permitted", action))
	}
}

func evaluateHostRebootPlan(rest []string) Decision {
	hasPlan := false
	hasWithGuests := false
	for _, arg := range rest {
		switch arg {
		case "--plan":
			if hasPlan {
				return deny("duplicate --plan flag")
			}
			hasPlan = true
		case "--with-guests":
			if hasWithGuests {
				return deny("duplicate --with-guests flag")
			}
			hasWithGuests = true
		default:
			return deny(fmt.Sprintf("host reboot flag %q is not permitted", arg))
		}
	}
	if !hasPlan {
		return deny("host reboot requires --plan")
	}
	return allowTier1()
}

func evaluateModule(args []string, policy Policy) Decision {
	if len(args) < 2 {
		return deny("module command requires <capability> <action>")
	}
	capability, action, rest := args[0], args[1], args[2:]

	if action == "status" {
		if _, ok := statusCapabilities[capability]; !ok {
			return deny(fmt.Sprintf("unknown module capability %q", capability))
		}
		if len(rest) == 0 {
			return allowTier1()
		}
		if capability == "vpn" && len(rest) == 1 && rest[0] == "--details" {
			return allowTier1()
		}
		return deny(fmt.Sprintf("module %s status flags not permitted", capability))
	}

	if action == "plan" {
		if _, ok := planCapabilities[capability]; !ok {
			return deny(fmt.Sprintf("module %s plan is not permitted", capability))
		}
		if len(rest) == 0 {
			return allowTier1()
		}
		return deny(fmt.Sprintf("module %s plan accepts no flags", capability))
	}

	if action == "apply" {
		if _, ok := applyCapabilities[capability]; !ok {
			return deny(fmt.Sprintf("module %s apply is not permitted", capability))
		}
		if len(rest) > 1 || (len(rest) == 1 && rest[0] != "--yes") {
			return deny(fmt.Sprintf("module %s apply only allows optional --yes", capability))
		}
		if !slices.Contains(policy.Tier2.ModuleApply, capability) {
			return deny(fmt.Sprintf("tier2 module_apply does not allow %q", capability))
		}
		return allowTier2("module_apply:" + capability)
	}

	switch capability {
	case "firewall":
		if action == "test" {
			if len(rest) != 1 || (rest[0] != "--plan" && rest[0] != "--yes") {
				return deny("module firewall test requires strictly --plan or --yes")
			}
			if !policy.Tier2.FirewallTest {
				return deny("tier2 firewall_test is not enabled")
			}
			return allowTier2("firewall_test")
		}
	case "dns":
		return evaluateModuleDNS(action, rest, policy)
	case "dhcp":
		return evaluateModuleDHCP(action, rest, policy)
	case "logging":
		if action == "query" {
			return evaluateLoggingQuery(rest)
		}
	case "monitoring":
		if action == "incidents" {
			return evaluateMonitoringIncidents(rest)
		}
	}

	return deny(fmt.Sprintf("module %s %s is not permitted", capability, action))
}

func evaluateModuleDNS(action string, rest []string, policy Policy) Decision {
	switch action {
	case "list-records":
		if len(rest) == 0 {
			return allowTier1()
		}
		return deny("module dns list-records accepts no arguments")
	case "add-record":
		if !policy.Tier2.DNSRecords {
			return deny("tier2 dns_records is not enabled")
		}
		if len(rest) < 1 || !isSafePositional(rest[0]) {
			return deny("module dns add-record requires record name")
		}
		flags, ok := parseFlagMap(rest[1:], map[string]bool{"--type": true, "--value": true}, map[string]bool{"--yes": true})
		if !ok {
			return deny("module dns add-record flags not permitted")
		}
		recordType := flags["--type"]
		if recordType != "A" && recordType != "CNAME" {
			return deny("module dns add-record requires --type A or CNAME")
		}
		if !isSafeValue(flags["--value"]) {
			return deny("module dns add-record requires --value")
		}
		return allowTier2("dns_records")
	case "remove-record":
		if !policy.Tier2.DNSRecords {
			return deny("tier2 dns_records is not enabled")
		}
		if len(rest) < 1 || !isSafePositional(rest[0]) {
			return deny("module dns remove-record requires record name")
		}
		if len(rest) == 1 || (len(rest) == 2 && rest[1] == "--yes") {
			return allowTier2("dns_records")
		}
		return deny("module dns remove-record flags not permitted")
	default:
		return deny(fmt.Sprintf("module dns %s is not permitted", action))
	}
}

func evaluateModuleDHCP(action string, rest []string, policy Policy) Decision {
	switch action {
	case "list-reservations":
		if len(rest) == 0 {
			return allowTier1()
		}
		return deny("module dhcp list-reservations accepts no arguments")
	case "list-leases":
		if len(rest) == 0 || (len(rest) == 1 && rest[0] == "--details") {
			return allowTier1()
		}
		return deny("module dhcp list-leases flags not permitted")
	case "add-reservation":
		if !policy.Tier2.DHCPReservations {
			return deny("tier2 dhcp_reservations is not enabled")
		}
		if len(rest) < 1 || !isSafePositional(rest[0]) {
			return deny("module dhcp add-reservation requires reservation name")
		}
		flags, ok := parseFlagMap(
			rest[1:],
			map[string]bool{"--zone": true, "--mac": true, "--address": true},
			map[string]bool{"--yes": true},
		)
		if !ok {
			return deny("module dhcp add-reservation flags not permitted")
		}
		if !isSafeValue(flags["--zone"]) || !isSafeValue(flags["--mac"]) || !isSafeValue(flags["--address"]) {
			return deny("module dhcp add-reservation requires --zone, --mac, and --address")
		}
		return allowTier2("dhcp_reservations")
	case "remove-reservation":
		if !policy.Tier2.DHCPReservations {
			return deny("tier2 dhcp_reservations is not enabled")
		}
		if len(rest) < 1 || !isSafePositional(rest[0]) {
			return deny("module dhcp remove-reservation requires reservation name")
		}
		if len(rest) == 1 || (len(rest) == 2 && rest[1] == "--yes") {
			return allowTier2("dhcp_reservations")
		}
		return deny("module dhcp remove-reservation flags not permitted")
	default:
		return deny(fmt.Sprintf("module dhcp %s is not permitted", action))
	}
}

func evaluateLoggingQuery(rest []string) Decision {
	flags, ok := parseFlagMap(
		rest,
		map[string]bool{
			"--host":  true,
			"--unit":  true,
			"--level": true,
			"--since": true,
			"--limit": true,
		},
		nil,
	)
	if !ok {
		return deny("module logging query only accepts bounded flags")
	}
	for _, key := range []string{"--host", "--unit"} {
		if val, exists := flags[key]; exists && (!isSafeValue(val) || len(val) > 128) {
			return deny(fmt.Sprintf("invalid %s value", key))
		}
	}
	if level, exists := flags["--level"]; exists {
		if _, valid := loggingLevels[strings.ToLower(level)]; !valid {
			return deny(fmt.Sprintf("invalid --level %q", level))
		}
	}
	if sinceVal, exists := flags["--since"]; exists {
		d, err := time.ParseDuration(sinceVal)
		if err != nil || d <= 0 || d > 168*time.Hour {
			return deny("invalid --since duration (must be >0 and <=168h)")
		}
	}
	if limitVal, exists := flags["--limit"]; exists {
		n, err := strconv.Atoi(limitVal)
		if err != nil || n < 1 || n > 500 {
			return deny("invalid --limit (must be 1-500)")
		}
	}
	return allowTier1()
}

func evaluateMonitoringIncidents(rest []string) Decision {
	var pos []string
	seenJSON := false
	for _, arg := range rest {
		if arg == "--json" {
			if seenJSON {
				return deny("duplicate --json flag")
			}
			seenJSON = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return deny(fmt.Sprintf("monitoring incidents flag %q is not permitted", arg))
		}
		pos = append(pos, arg)
	}
	if len(pos) == 1 && pos[0] == "list" {
		return allowTier1()
	}
	if len(pos) == 2 && pos[0] == "show" && isSafePositional(pos[1]) {
		return allowTier1()
	}
	return deny("module monitoring incidents only allows list or show <id> [--json]")
}

func parseSingleStringFlag(args []string, flagName string) (string, bool) {
	if len(args) == 1 && strings.HasPrefix(args[0], flagName+"=") {
		return strings.TrimPrefix(args[0], flagName+"="), true
	}
	if len(args) == 2 && args[0] == flagName {
		return args[1], true
	}
	return "", false
}

func parseFlagMap(args []string, valueFlags, boolFlags map[string]bool) (map[string]string, bool) {
	out := make(map[string]string)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			return nil, false
		}
		if boolFlags[arg] {
			if _, dup := out[arg]; dup {
				return nil, false
			}
			out[arg] = "true"
			continue
		}
		name := arg
		var val string
		if eq := strings.IndexByte(arg, '='); eq >= 0 {
			name = arg[:eq]
			val = arg[eq+1:]
			if !valueFlags[name] {
				return nil, false
			}
		} else {
			if !valueFlags[name] || i+1 >= len(args) {
				return nil, false
			}
			i++
			val = args[i]
		}
		if _, dup := out[name]; dup {
			return nil, false
		}
		out[name] = val
	}
	return out, true
}

func isSafePositional(arg string) bool {
	return arg != "" && !strings.HasPrefix(arg, "-")
}

func isSafeValue(val string) bool {
	return val != "" && !strings.HasPrefix(val, "-")
}
