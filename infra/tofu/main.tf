locals {
  desired = jsondecode(file(var.model_file))
  guests = {
    for guest in local.desired.guests : tostring(guest.vmid) => guest
  }
  containers = {
    for vmid, guest in local.guests : vmid => guest if guest.kind == "lxc"
  }
  firewall = {
    for vmid, guest in local.guests : vmid => guest if guest.kind == "qemu"
  }
}

resource "proxmox_virtual_environment_vm" "firewall" {
  for_each = local.firewall

  node_name       = local.desired.node
  vm_id           = each.value.vmid
  name            = each.value.name
  description     = "boetticher OPNsense firewall"
  on_boot         = true
  started         = true
  bios            = "seabios"
  boot_order      = ["scsi0", "ide2"]
  stop_on_destroy = false

  agent {
    enabled = false
  }

  cpu {
    cores = each.value.cores
    type  = "host"
  }

  memory {
    dedicated = each.value.memory_mib
  }

  disk {
    datastore_id = var.guest_datastore_id
    interface    = "scsi0"
    size         = each.value.disk_gib
  }

  cdrom {
    file_id   = var.opnsense_iso_file_id
    interface = "ide2"
  }

  network_device {
    bridge   = "vmbr0"
    firewall = true
  }

  # OPNsense owns the 802.1Q trunk. Do not put a VLAN tag on this device.
  network_device {
    bridge   = "vmbr1"
    firewall = true
  }

  operating_system {
    type = "other"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "proxmox_virtual_environment_container" "managed" {
  for_each = local.containers

  node_name     = local.desired.node
  vm_id         = each.value.vmid
  description   = "boetticher ${each.value.role}"
  start_on_boot = true
  started       = true
  unprivileged  = true
  protection    = true

  cpu {
    cores = each.value.cores
  }

  memory {
    dedicated = each.value.memory_mib
  }

  initialization {
    hostname = each.value.hostname

    dns {
      domain  = "lab.home.arpa"
      servers = ["10.10.20.10", "10.10.20.11"]
    }

    ip_config {
      ipv4 {
        address = "${each.value.address}/24"
        gateway = each.value.gateway
      }
    }

    user_account {
      keys = var.operator_ssh_public_keys
    }
  }

  network_interface {
    bridge   = "vmbr1"
    firewall = true
    name     = "eth0"
    vlan_id  = each.value.vlan
  }

  disk {
    datastore_id = var.guest_datastore_id
    size         = each.value.disk_gib
  }

  operating_system {
    template_file_id = var.debian_template_file_id
    type             = "debian"
  }

  lifecycle {
    prevent_destroy = true
  }
}

output "model_revision" {
  value = local.desired.model_revision
}
