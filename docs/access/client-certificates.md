# Client certificates

The installation creates a private Root CA and Issuing CA. CA private keys stay in encrypted SOPS material. Endpoint private keys are generated and stored outside Git under the operator runtime directory; certificate metadata and fingerprints may be committed as generated evidence.

```sh
homelab pki client create macbook --site my-homelab
homelab pki client export macbook --site my-homelab --output macbook.pem
homelab pki client revoke macbook --site my-homelab
homelab pki trust export --site my-homelab --output homelab-ca.pem
```

The export command refuses private-key output to stdout. Revoke records are generated evidence; applying revocation to every endpoint is a separate convergence responsibility and must be verified at the protected service.
