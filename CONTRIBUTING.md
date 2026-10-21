# Contributing to Boetticher

Thanks for being here. Boetticher is a small passion project for people who
think a homelab should feel powerful without becoming a second full-time job.
Good contributions make the lab more useful, more understandable, or simply
more fun to run.

Start with [the lab guide](https://lab.davebarton.cc/lab.html), then skim
[Modules](https://lab.davebarton.cc/modules.html) if your change touches a
capability, appliance image, network, or Controller peripheral.

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

Work on a feature branch and run the full local gate on Linux before opening a
pull request:

```sh
git switch -c my-change
gofmt -w cmd internal
make ci
```

Use the Go version in `go.mod`. Some tests are Linux-only, so a cross-build on
another OS is not a substitute for `make ci` on Linux. GitHub Actions only
publishes the documentation site; there is no hosted test or release workflow.

Add a focused regression test for a behavioural or security fix. The public
guide source lives in `docs/` and is published as a GitHub Pages site. Keep
generated files generated: the command page comes from
`internal/cli/commands.go`, so run `make command-docs` rather than editing
`docs/commands.md` by hand, and update the help text and the guide together.

Never commit a secret, API key, auth key, private key, cache, bootstrap
credential, or a copy of `/etc/boetticher/`. If you think one slipped into a
change, stop and deal with that before opening a pull request.

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

## Trying a change on a Controller

There is no signed release bundle or tagged release ceremony. After the pull
request is reviewed, build the Controller payload from the branch and install
it on the Controller with the local installer:

```sh
ARRSTACK_SOURCE_ARCHIVE=/path/to/arrstack-source.tar.gz \
  sh scripts/package-controller.sh BUILD_ID
# copy dist/controller/ to the Pi, then on the Pi:
sudo sh /home/pi/controller-release/install.sh \
  --from-dir /home/pi/controller-release --operator pi --confirm-key-login
```

The [Controller guide](https://lab.davebarton.cc/controller.html#install-from-a-local-payload)
describes the payload and installer. Exercise the change through the installed
CLI, not a checkout, and report source checks, deployment, packet journeys, and
physical checks separately; an untested gate stays `NOT TESTED`.

## Reporting security issues

Please do not put credentials, private keys, live addresses, private lab
configuration, or exploit steps in a public issue. [SECURITY.md](SECURITY.md)
explains the private reporting route.
