locals {
  desired = jsondecode(file(var.model_file))
  # This is an ownership boundary, not a guest-discovery mechanism. Only
  # resources already present in the generated platform model are managed.
  platform_vmids = toset([for guest in local.desired.guests : guest.vmid if guest.vmid >= 100 && guest.vmid <= 499])
  guests = {
    for guest in local.desired.guests : tostring(guest.vmid) => guest
    if contains(local.platform_vmids, guest.vmid)
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
  description     = "boetticher managed Debian gateway"
  tags            = each.value.tags
  on_boot         = true
  started         = true
  bios            = "seabios"
  boot_order      = ["scsi0"]
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

  dynamic "network_device" {
    for_each = each.value.nics
    content {
      bridge      = network_device.value.bridge
      firewall    = true
      vlan_id     = network_device.value.vlan == 0 ? null : network_device.value.vlan
      mac_address = network_device.value.mac
    }
  }

  operating_system {
    type = "l26"
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
  tags          = each.value.tags
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
