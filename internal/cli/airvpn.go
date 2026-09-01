package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofastercloud/boetticher/internal/airvpn"
	"github.com/gofastercloud/boetticher/internal/firewall"
	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/site"
)

const airVPNAPIKeyRelativePath = ".secrets/btcr-airvpn.key"

type preparedAirVPNProfile struct {
	Metadata firewall.AirVPNProfile
	Created  bool
}

// prepareAirVPNProfile loads the retained encrypted profile and only calls the
// provider generator when the profile is absent or the operator explicitly
// requests rotation. Dry-run intentionally checks local readiness without
// reading the API key or writing encrypted state.
func prepareAirVPNProfile(ctx context.Context, siteDir string, s model.Site, ageIdentity string, dryRun, rotate bool) (*preparedAirVPNProfile, error) {
	if !modules.IsEnabled(s, "airvpn") {
		return nil, nil
	}
	config, ok := s.ModuleConfig["airvpn"]
	if !ok || strings.TrimSpace(config.Servers) == "" {
		return nil, errors.New("HOLD: AirVPN is enabled but its server selector is missing")
	}
	stored, loadErr := site.LoadPlatformSecret(siteDir, s, ageIdentity, "airvpn_wireguard_config")
	if loadErr == nil && !rotate {
		profile, parseErr := airvpn.ParseProfile([]byte(stored))
		if parseErr != nil {
			return nil, fmt.Errorf("HOLD: retained AirVPN WireGuard profile is invalid: %w", parseErr)
		}
		return &preparedAirVPNProfile{Metadata: firewallAirVPNMetadata(profile.Metadata)}, nil
	}
	if loadErr != nil && !errors.Is(loadErr, site.ErrPlatformSecretMissing) {
		return nil, fmt.Errorf("HOLD: load retained AirVPN WireGuard profile: %w", loadErr)
	}
	if dryRun {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return nil, errors.New("HOLD: controller home directory is unavailable for the AirVPN API key")
		}
		keyPath := filepath.Join(home, airVPNAPIKeyRelativePath)
		if statErr := validateAirVPNAPIKeyFile(keyPath); statErr != nil {
			return nil, errors.New("HOLD: encrypted AirVPN profile is missing and the controller API key is unavailable")
		}
		return nil, errors.New("HOLD: encrypted AirVPN profile is missing; a confirmed deploy is required to generate it")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("HOLD: controller home directory is unavailable for the AirVPN API key")
	}
	keyPath := filepath.Join(home, airVPNAPIKeyRelativePath)
	if err := validateAirVPNAPIKeyFile(keyPath); err != nil {
		return nil, errors.New("HOLD: controller AirVPN API key is unavailable")
	}
	apiKey, err := readAirVPNAPIKey(keyPath)
	if err != nil {
		return nil, errors.New("HOLD: read controller AirVPN API key")
	}
	profile, err := (airvpn.Client{}).Generate(ctx, strings.TrimSpace(string(apiKey)), config.Servers)
	if err != nil {
		return nil, fmt.Errorf("HOLD: generate AirVPN WireGuard profile: %w", err)
	}
	if err := site.StorePlatformSecret(siteDir, s, ageIdentity, "airvpn_wireguard_config", profile.Config); err != nil {
		return nil, fmt.Errorf("store encrypted AirVPN WireGuard profile: %w", err)
	}
	return &preparedAirVPNProfile{Metadata: firewallAirVPNMetadata(profile.Metadata), Created: true}, nil
}

func validateAirVPNAPIKeyFile(path string) error {
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("AirVPN API key path is not a private regular file")
	}
	return nil
}

func readAirVPNAPIKey(path string) ([]byte, error) {
	if err := validateAirVPNAPIKeyFile(path); err != nil {
		return nil, err
	}
	return pathguard.ReadFileLimited(path, 4096)
}

func firewallAirVPNMetadata(metadata airvpn.Metadata) firewall.AirVPNProfile {
	return firewall.AirVPNProfile{
		EndpointHost:  metadata.EndpointHost,
		EndpointPort:  metadata.EndpointPort,
		TunnelAddress: strings.Split(metadata.TunnelAddress, "/")[0],
		SHA256:        metadata.SHA256,
	}
}
