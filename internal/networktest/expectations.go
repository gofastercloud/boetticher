package networktest

// ExpectedPlatformAccess is the independent baseline for probes aimed at
// first-party platform endpoints. It is intentionally separate from the
// firewall renderer so a renderer regression cannot redefine the expected
// result. Module-specific guest paths are exercised by their own source-bound
// rules and remain outside this fixed probe matrix.
func ExpectedPlatformAccess(sourceZone, targetZone, protocol string, port int) bool {
	if sourceZone == "SANDBOX" {
		return false
	}
	if sourceZone == targetZone {
		return true
	}
	switch sourceZone {
	case "TRUSTED":
		if targetZone == "SERVERS" || targetZone == "INFRA" {
			return (protocol == "tcp" && (port == 53 || port == 443)) || (protocol == "udp" && (port == 53 || port == 123))
		}
		if targetZone == "MGMT" {
			return protocol == "tcp" && (port == 22 || port == 443 || port == 8006)
		}
	case "SERVERS":
		if targetZone == "INFRA" {
			return (protocol == "tcp" && port == 53) || (protocol == "udp" && (port == 53 || port == 123))
		}
	case "MGMT":
		if targetZone == "INFRA" || targetZone == "SERVERS" {
			return (protocol == "tcp" && (port == 22 || port == 53 || port == 80 || port == 443)) || (protocol == "udp" && (port == 53 || port == 123))
		}
	}
	return false
}
