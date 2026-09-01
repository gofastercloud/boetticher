// Package buildbundle carries the public appliance build contract in release
// binaries. It contains no site state, credentials, or private authority.
package buildbundle

import "embed"

// FS is the release's public build input bundle. The artifact builder uses it
// when the CLI is not running from a source checkout.
//
//go:embed buildbundle.go go.mod go.sum cmd/artifact-identity cmd/boetticher-aiops cmd/boetticher-bifrost cmd/boetticher-firewall-telemetry cmd/boetticher-log-query cmd/boetticher-network-probe cmd/boetticher-streamdeck cmd/qualify-artifact cmd/render-blocky-config internal/airvpn internal/aiops internal/artifacts internal/bifrost internal/dns internal/firewall internal/firewalltelemetry internal/gatus internal/logging internal/model internal/modules internal/networktest internal/pathguard internal/streamdeck internal/usbexport images scripts/benchmark-artifact-compression.sh scripts/build-images.sh scripts/scan-images.sh scripts/smoke-appliance.sh scripts/smoke-firewall-image.sh
var FS embed.FS
