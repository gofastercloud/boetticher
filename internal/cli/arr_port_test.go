package cli

import (
	"testing"

	"github.com/gofastercloud/boetticher/internal/model"
)

func TestAirVPNPeerPortConfigureRoundTripAndToggle(t *testing.T) {
	config := model.ConfigFromSite(model.NewSite("arr-port", "age1test", model.GatewayModeManaged))
	yes, no := true, false
	config.Modules.AirVPN = &model.AirVPNModuleConfig{Enabled: &yes, Servers: "europe"}
	field := model.ModuleConfigField{Key: "qbittorrent_port", Type: model.ModuleConfigString}
	if err := applyConfigurationField(&config, "airvpn", field, "45678"); err != nil {
		t.Fatal(err)
	}
	copy := model.ModulesConfigFromMap(config.Modules.Map())
	if copy.AirVPN.QBittorrentPort != 45678 {
		t.Fatal("port was lost during normalization")
	}
	if err := config.Modules.Set("airvpn", model.ModuleConfig{Enabled: &no}); err != nil {
		t.Fatal(err)
	}
	if config.Modules.AirVPN.QBittorrentPort != 45678 {
		t.Fatal("disabling AirVPN lost its retained reservation")
	}
	if err := applyConfigurationField(&config, "airvpn", field, "0"); err != nil {
		t.Fatal(err)
	}
	if config.Modules.AirVPN.QBittorrentPort != 0 {
		t.Fatal("explicit forwarding removal was ignored")
	}
	for _, value := range []string{"8080", "65536", "22", "not-a-port"} {
		if err := applyConfigurationField(&config, "airvpn", field, value); err == nil {
			t.Fatalf("accepted invalid peer port %q", value)
		}
	}
}
