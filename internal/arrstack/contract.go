// Package arrstack contains the fixed identity and bounded service contract
// for the modern upstream Compose appliance.
package arrstack

import "github.com/gofastercloud/boetticher/internal/clientservices"

const (
	GuestName       = "lab-media-01"
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

func Reservation() clientservices.Reservation {
	return clientservices.Reservation{
		Name: GuestName, Zone: "SERVERS", MAC: GuestMAC, Address: GuestAddress,
	}
}

func VPNForward() clientservices.VPNForward {
	return clientservices.VPNForward{
		Name: "media-qbittorrent", Reservation: ReservationName,
		Protocols: []string{"tcp", "udp"}, Port: QBitTorrentPort,
	}
}
