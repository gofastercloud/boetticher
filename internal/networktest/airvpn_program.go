package networktest

import _ "embed"

// AirVPNProbeProgram performs bounded TCP, DNS and NTP measurements without
// installing tools in a deployed selected module. Only public test inputs are
// supplied on stdin; transport failure is separate from a denied connection.
//
//go:embed airvpn_probe.py
var AirVPNProbeProgram string
