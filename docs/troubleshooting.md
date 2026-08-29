# Troubleshooting

Start with:

```sh
boetticher access --site my-boetticher
boetticher doctor --site my-boetticher
boetticher verify --site my-boetticher
```

If the HOME-side address may have changed, use only the known address with `boetticher bootstrap-endpoint set ADDRESS`; do not scan. Use `boetticher ssh-config --check` to check an operator file without rewriting it. Use `boetticher verify --ssh-journey` only when you want a real authenticated command through the bastion.

Interpretation matters: human-facing checks and operations are binary. `PASS`
means the asserted condition succeeded; `FAIL` means it did not. Use the
`--verbose` reason and next action, `doctor --live`, or the JSON/evidence
projection for the distinction between a missing, stale, malformed, or
unavailable input. A passing local plan, formatter, or API fixture does not
prove deployment, authenticated journeys, or physical client isolation.

For a dedicated data disk, check the configured stable identity in `site.yml`
and review `boetticher doctor --site my-boetticher`. Bootstrap refuses the
system disk, populated disks, unexpected existing volume groups, and
conflicting Proxmox storage definitions. It will not guess a replacement
device; update the site configuration deliberately and repeat the guarded
bootstrap step.
