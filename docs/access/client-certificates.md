# Client certificates

The installation creates a private Root CA and Issuing CA. CA private keys stay in encrypted SOPS material. Endpoint private keys are generated and stored outside Git under the operator runtime directory; certificate metadata and fingerprints may be committed as generated evidence.

```sh
boetticher pki client create operator-device --site my-boetticher
boetticher pki client export operator-device --site my-boetticher --output operator-device.pem
boetticher pki client revoke operator-device --site my-boetticher
boetticher pki trust export --site my-boetticher --output boetticher-ca.pem
```

The export command refuses private-key output to stdout. Revoke records are generated evidence; applying revocation to every endpoint is a separate convergence responsibility and must be verified at the protected service.
