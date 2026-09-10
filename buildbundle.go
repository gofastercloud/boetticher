// Package buildbundle gathers appliance-build inputs into release binaries. It
// contains no site settings, credentials, or private keys.
package buildbundle

import "embed"

// FS is the release build-input bundle. The artifact builder uses it when the
// CLI is not running from a source checkout.
//
//go:embed buildbundle.go go.mod go.sum ansible/site.yml ansible/companion.yml ansible/tasks ansible/roles ansible/callback_plugins cmd/artifact-identity cmd/boetticher-aiops cmd/boetticher-bifrost cmd/boetticher-firewall-telemetry cmd/boetticher-firewall-test-host cmd/boetticher-host-speedtest cmd/boetticher-log-query cmd/boetticher-network-probe cmd/boetticher-status cmd/boetticher-streamdeck cmd/qualify-artifact cmd/render-blocky-config internal/airvpn internal/aiops internal/artifacts internal/bifrost internal/controllerstatus internal/dns internal/firewall internal/firewallmodule internal/firewalltelemetry internal/firewalltest internal/gatus internal/logging internal/model internal/modules internal/network internal/openwrt internal/observability internal/pathguard internal/pushover internal/streamdeck internal/usbexport images pi/kiosk scripts/benchmark-artifact-compression.sh scripts/build-images.sh scripts/build-openwrt-firewall.sh scripts/install-observability-collection.sh scripts/install-observability-providers.sh scripts/scan-images.sh scripts/smoke-appliance.sh scripts/smoke-firewall-image.sh
var FS embed.FS
