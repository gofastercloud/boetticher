# Command reference

```text
init
preflight [--live] [--bootstrap-address ADDRESS] [--trunk-interface IFACE]
bootstrap-endpoint show|set ADDRESS
bootstrap
provision
converge
verify [--ssh-journey]
doctor [--live]
ssh-config [--check] [--install-include]
access
portal build
network trunk status|attach|detach [INTERFACE]
pki client create|export|revoke
pki trust export
opnsense credentials import < credentials.json
upgrade
```

`bootstrap`, `provision`, and `converge` are core capabilities. The current build contains the source and offline contracts for each, but the OPNsense unattended-install/API/interface gate and physical network journeys remain explicit live qualification gates.

Sensitive input is read from protected files or stdin where necessary. Do not place passwords, API secrets, private keys, or SOPS plaintext in arguments, persistent environment variables, logs, generated files, or Git.
