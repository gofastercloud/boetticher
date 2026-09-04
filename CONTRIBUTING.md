# Contributing to Boetticher

Thanks for being here. Boetticher is a small passion project for people who
think a homelab should feel powerful without becoming a second full-time job.
Good contributions make the lab more useful, more understandable, or simply
more fun to run.

Start with [the lab guide](https://gofastercloud.github.io/boetticher/lab.html),
then skim [Modules](https://gofastercloud.github.io/boetticher/modules.html) if
your change touches an appliance, image, network, or companion.

## Keep the shape small

Boetticher is a fixed-shape homelab appliance, not a generic VM manager or
infrastructure framework. Prefer a concrete Go change and a focused module
over a new platform for arbitrary plugins or workload management. Proxmox
continues to own the user's VMs and LXCs.

The project deliberately keeps a few things strict: host identity checks,
encrypted secrets, explicit confirmations before data-changing work, and a
clear distinction between your saved settings and the running lab. Do not make
those less clear just to shorten a code path.

## A good development loop

```sh
gofmt -w cmd internal
make ci
```

Use the Go version in `go.mod`. Add a focused regression test for a behavioural
or security fix. The public guide source lives in `docs/` and is published as a
GitHub Pages site. Keep generated files generated: the command page comes from
`internal/cli/commands.go`, so run `make command-docs` rather than editing
`docs/commands.md` by hand.

Never commit a secret, age identity, cache, bootstrap credential, or live site
directory. If you think one slipped into a change, stop and deal with that
before opening a pull request.

## Pull requests

- Keep the change focused and explain what someone running a lab will notice.
- Add the test and documentation that make the new behaviour easy to keep.
- Keep the guide small; fold a topic into an existing page unless there is a
  compelling reason to grow it.
- Describe any effect on bootstrap, storage, routing, firewall rules, USB, or
  recovery in plain language.
- Do not add a broad guest lifecycle manager or silently take over user guests.
- Keep application software in pinned appliance images; Ansible supplies
  site-specific configuration rather than becoming another application platform.

If you are unsure whether an idea belongs here, open an issue or draft pull
request early. A small conversation is cheaper than a heroic rebase.

## Rehearse the release workflow

The first supported platform and base release is `0.1.0`; module appliances
retain their independent `1.0.0` versions. Keep `boetticher/v3`, schema 3, and
the bundle and artifact ABIs separate from that release label.

After a release change reaches `main`, run the complete hosted build without
publishing:

```sh
gh workflow run release.yml --ref main -f release_version=0.1.0
gh run list --workflow release.yml --event workflow_dispatch --limit 1
gh run watch RUN_ID --exit-status
```

The repository must have `BOETTICHER_RELEASE_KEY_ID`,
`BOETTICHER_RELEASE_SIGNING_KEY`, and `BOETTICHER_RELEASE_TRUSTED_KEYS`
configured as Actions secrets. A manual rehearsal uses those values only on
the ephemeral runner, builds and qualifies all 13 artifacts, assembles and
imports the signed bundle with its matching controller, then uploads a
short-lived rehearsal artifact containing only the controller and bundle. It
must not create a GitHub Release.

Only a pushed, exact `v0.1.x` tag uploads the validated outputs and enters the
approval-protected `release` environment. Run the manual rehearsal before
creating a tag. While the tagged publish job waits, download and inspect that
run's exact controller and bundle, complete the clean-install acceptance, and
approve publication only if those bytes pass.

## Reporting security issues

Please do not put credentials, private keys, live addresses, private site
configuration, or exploit steps in a public issue. [SECURITY.md](SECURITY.md)
explains the private reporting route.
