# Troubleshooting

Start with the current platform view:

```sh
boetticher status --site my-boetticher --live
boetticher doctor --site my-boetticher --live
```

If a deploy just failed, read its final summary first. It names the failed
phase, says whether infrastructure changed, reports temporary-authority
cleanup, and gives one `Next action`. Follow that action instead of guessing.

If the HOME-side address may have changed, use only the known address with `boetticher bootstrap-endpoint set ADDRESS`; do not scan. Use `boetticher ssh-config --check` to check an operator file without rewriting it. Use `boetticher verify --ssh-journey` only when you want a real authenticated command through the bastion.

`PASS` means the check succeeded; `FAIL` means it did not. A local pass does
not prove that the host is reachable or that a real authenticated journey
works. Use `--verbose` for the reason, and use `doctor --live` when the next
step is not obvious. `verify --ssh-journey` checks a real authenticated command
through the bastion.

The commands have different jobs:

- `config validate` checks local configuration.
- `preflight --live` checks prerequisites that already exist, without applying
  deployment changes.
- `deploy --dry-run` checks the deployment plan and selected artifacts without
  changing infrastructure.
- `status --live` is the quick health view.
- `doctor --live` points at a current problem and its next diagnostic.
- `verify --live` checks supported generated and live paths.

For a dedicated data disk, check the configured stable identity in `site.yml`
and review `boetticher doctor --site my-boetticher`. Bootstrap refuses the
system disk, populated disks, unexpected existing volume groups, and
conflicting Proxmox storage definitions. It will not guess a replacement
device; update the site configuration deliberately and repeat the guarded
bootstrap step.
