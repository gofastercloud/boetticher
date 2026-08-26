# Client certificates

Use `homelab pki client create NAME`, `export NAME`, `revoke NAME`, and `homelab pki trust export`. CA keys remain in encrypted SOPS material. Endpoint private keys are stored outside Git under the runtime directory. Certificates and fingerprints are non-secret generated metadata.
