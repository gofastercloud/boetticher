# Troubleshooting

Start with the current platform view:

```sh
boetticher status --site my-boetticher --live
boetticher doctor --site my-boetticher --live
```

If a deploy just failed, read its final summary first. It names the failed
phase, says whether infrastructure changed, reports temporary-authority
cleanup, gives one `Next action`, and points to a private timing report.
Follow that action instead of guessing. The timing report is especially
useful when a run is slow: compare the phase durations first, then look at
the recorded artifact or Ansible suboperations.

Bootstrap prints the same timing information and stores a timestamped report
below the site's private runtime directory. Do not paste the whole report into
a public issue; share it only after checking that the surrounding diagnostic
bundle is safe to disclose.

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

When the question is “can this zone reach that platform path?”, use
`boetticher network test --site my-boetticher`. It runs from temporary probes,
does not change firewall policy, and does not replace application health
checks. Start with `--zones` when only one path matters. If the command reports
a cleanup failure, use `--cleanup-only` only for exact-owned probes and follow
the ownership error if it refuses to continue.

For a dedicated data disk, check the configured stable identity in `site.yml`
and review `boetticher doctor --site my-boetticher`. Bootstrap refuses the
system disk, populated disks, unexpected existing volume groups, and
conflicting Proxmox storage definitions. It will not guess a replacement
device; update the site configuration deliberately and repeat the guarded
bootstrap step.
