package network

import "fmt"

// ManagedModuleMAC returns the stable locally administered identity used for
// module guests that need a Proxmox MAC/IP-filter boundary. The VMID is
// encoded in the final two octets, keeping these identities separate from the
// gateway and upstream NIC reservations without changing the model contract.
func ManagedModuleMAC(vmid int) string {
	if vmid <= 0 || vmid > 0xffff {
		return ""
	}
	return fmt.Sprintf("02:00:00:03:%02x:%02x", (vmid>>8)&0xff, vmid&0xff)
}
