package host

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
)

var ErrNoControllerLABBinding = errors.New("no Controller LAB binding")

type ControllerLABBinding struct{ Address, MAC string }

func LocalControllerLABBinding(config LabConfig) (ControllerLABBinding, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ControllerLABBinding{}, err
	}
	return ResolveControllerLABBinding(config, interfaces)
}

func ResolveControllerLABBinding(config LabConfig, interfaces []net.Interface) (ControllerLABBinding, error) {
	if config.Modules.DHCP == nil {
		return ControllerLABBinding{}, ErrNoControllerLABBinding
	}
	var zone model.Zone
	for _, candidate := range model.NewSite(config.Name, "local", model.GatewayModeManaged).Network.Zones {
		if candidate.Type == model.ZoneTypeServers {
			zone = candidate
			break
		}
	}
	if zone.Network == "" {
		return ControllerLABBinding{}, fmt.Errorf("SERVERS zone unavailable")
	}
	prefix, _ := netip.ParsePrefix(zone.Network)
	var found *ControllerLABBinding
	for _, iface := range interfaces {
		mac := iface.HardwareAddr
		if len(mac) != 6 || (mac[0]&1) != 0 {
			continue
		}
		for _, r := range config.Modules.DHCP.Reservations {
			if r.Zone != "SERVERS" || !strings.EqualFold(r.MAC, mac.String()) {
				continue
			}
			ip, err := netip.ParseAddr(r.Address)
			if err != nil || !ip.Is4() || !prefix.Contains(ip) || ip == prefix.Masked().Addr() {
				return ControllerLABBinding{}, fmt.Errorf("invalid Controller LAB reservation")
			}
			b := ControllerLABBinding{Address: ip.String(), MAC: strings.ToLower(mac.String())}
			if found != nil {
				return ControllerLABBinding{}, fmt.Errorf("ambiguous Controller LAB binding")
			}
			found = &b
		}
	}
	if found == nil {
		return ControllerLABBinding{}, ErrNoControllerLABBinding
	}
	return *found, nil
}
