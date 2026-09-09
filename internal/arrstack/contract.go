// Package arrstack contains the fixed identity and bounded service contract
// for the modern upstream Compose appliance.
package arrstack

import "github.com/gofastercloud/boetticher/internal/clientservices"

const (
	GuestName       = "lab-arrstack-01"
	ReservationName = GuestName
	GuestVMID       = 290
	GuestAddress    = "10.10.20.230"
	GuestMAC        = "02:00:00:00:20:e6"
	QBitTorrentPort = 35796
	StorageID       = "boetticher-data"
	RootDiskGiB     = 32
	MediaDiskGiB    = 256
	CPUs            = 4
	MemoryMiB       = 8192
)

// ServiceAliases are the internal application names projected to the
// configured application domain. Values are intentionally service labels;
// the module-owned DNS projection supplies the target guest name.
var ServiceAliases = []string{
	"oscar", "emmy", "tony", "peabody", "clio", "qbittorrent", "jellyfin", "jellyseerr",
}

var AwardAliases = map[string]string{
	"radarr": "oscar", "sonarr": "emmy", "bazarr": "tony", "prowlarr": "peabody", "trailarr": "clio",
}

func Reservation() clientservices.Reservation {
	return clientservices.Reservation{
		Name: GuestName, Zone: "SERVERS", MAC: GuestMAC, Address: GuestAddress,
	}
}

func VPNForward() clientservices.VPNForward {
	return clientservices.VPNForward{
		Name: "arrstack-qbittorrent", Reservation: ReservationName,
		Protocols: []string{"tcp", "udp"}, Port: QBitTorrentPort,
	}
}
