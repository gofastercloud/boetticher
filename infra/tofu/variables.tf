variable "proxmox_endpoint" {
  description = "Proxmox API endpoint, for example https://192.0.2.10:8006/"
  type        = string
}

variable "proxmox_api_token" {
  description = "Short-lived or SOPS-decoded Proxmox API token value"
  type        = string
  sensitive   = true
}

variable "proxmox_insecure" {
  description = "Allow the initial self-signed Proxmox certificate only when explicitly enabled"
  type        = bool
  default     = false
}

variable "model_file" {
  description = "Generated Proxmox desired-state.json from the private site repository"
  type        = string
}

variable "debian_template_file_id" {
  description = "Verified Debian LXC template file ID already present in Proxmox storage"
  type        = string
}

variable "guest_datastore_id" {
  description = "Generated storage target: local for single-disk or boetticher-thin for dedicated-data-disk"
  type        = string
}

variable "operator_ssh_public_keys" {
  description = "Operator public keys installed in managed Debian guests"
  type        = list(string)
  default     = []
}
