# Security model

OPNsense is the enforced inter-zone boundary with default-deny policy. SANDBOX has Internet access but no route-level access to TRUSTED, SERVERS, or MGMT. MGMT is restricted and uses reservation-only DHCP. Physical SANDBOX peer isolation requires switch/client isolation; virtual SANDBOX peer isolation uses the Proxmox firewall policy.

The platform is IPv4-only in V1. Internal services use the installation’s private CA. Sensitive web interfaces use TLS and mTLS. SOPS encrypts secrets to an Age public recipient; the Age private identity stays outside Git. SSH host-key validation remains enabled.
