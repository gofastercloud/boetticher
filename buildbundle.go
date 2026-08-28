// Package buildbundle carries the public appliance build contract in release
// binaries. It contains no site state, credentials, or private authority.
package buildbundle

import "embed"

// FS is the release's public build input bundle. The artifact builder uses it
// when the CLI is not running from a source checkout.
//
//go:embed buildbundle.go go.mod go.sum cmd/artifact-identity cmd/boetticher-firewall-telemetry cmd/qualify-artifact cmd/render-blocky-config internal/artifacts internal/dns internal/firewall internal/firewalltelemetry internal/logging internal/model internal/modules internal/usbexport images scripts/build-images.sh scripts/scan-images.sh scripts/smoke-appliance.sh scripts/smoke-firewall-image.sh
var FS embed.FS
