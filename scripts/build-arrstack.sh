#!/bin/sh
set -eu

archive=${ARRSTACK_SOURCE_ARCHIVE:?ARRSTACK_SOURCE_ARCHIVE must point to the reviewed upstream tarball}
expected_sha=cf11ea4396f603dcbec6eb11edb78e3ba90c2223953ad55628cdeec95b214509
target=${ARRSTACK_BUN_TARGET:-bun-linux-x64}
output=${1:-dist/arrstack-linux-x64}
[ -r "$archive" ] || { echo "arrstack source archive is missing: $archive" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual_sha=$(sha256sum "$archive" | awk '{print $1}')
else
  actual_sha=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
[ "$actual_sha" = "$expected_sha" ] || { echo "arrstack source checksum mismatch" >&2; exit 1; }
stage=$(mktemp -d /tmp/boetticher-arrstack-build.XXXXXX)
if [ -z "${ARRSTACK_KEEP_STAGE:-}" ]; then trap 'rm -rf "$stage"' EXIT HUP INT TERM; fi
tar -xzf "$archive" -C "$stage"
root=$(find "$stage" -mindepth 1 -maxdepth 1 -type d -print -quit)
[ -n "$root" ] || { echo "arrstack archive has no root" >&2; exit 1; }
[ -n "${ARRSTACK_KEEP_STAGE:-}" ] && printf '%s\n' "arrstack stage: $root" >&2
lock=${ARRSTACK_LOCKFILE:-internal/arrstack/bun.lock}
[ -r "$lock" ] || { echo "arrstack lockfile is missing: $lock" >&2; exit 1; }
cp "$lock" "$root/bun.lock"

# Apply the adapter patches to the extracted, checksum-verified upstream.
python3 - "$root/src/cli.ts" "$root/src/renderer/caddy.ts" "$root/src/renderer/compose.ts" "$root/src/catalog/services.yaml" "$root/templates/compose.yml.hbs" internal/arrstack/manifest.json <<'PY'
from pathlib import Path
import sys
import json
cli, caddy, compose, catalog, template, manifest = map(Path, sys.argv[1:])
root = cli.parent.parent
headless = Path("internal/arrstack/headless.ts").read_text()
headless = headless.replace('"./upstream/src/', '"./')
(cli.parent / "headless.ts").write_text(headless)
s = cli.read_text()
needle = '    const installDir = opts.installDir ?? `${process.env.HOME}/arrstack`;'
replacement = needle + '''
    if (program.opts().nonInteractive) {
      const { runHeadlessInstall } = await import("./headless.js");
      await runHeadlessInstall(installDir, process.env.ARRSTACK_STORAGE_ROOT ?? "/var/lib/arrstack/media", undefined, (u) => console.log(`${u.status}: ${u.step}`));
      return;
    }'''
if needle not in s: raise SystemExit("install action anchor missing")
cli.write_text(s.replace(needle, replacement, 1))
s = (root / "src/usecase/install.ts").read_text()
# Headless Controller installs provide a bounded remaining operation budget for
# image pulls; interactive upstream installs retain their 10-minute default.
needle = '''        "docker", "compose", "-f", join(installDir, "docker-compose.yml"),
        "pull", "--ignore-buildable",
      ],
      { timeoutMs: 600_000 },'''
replacement = '''        "docker", "compose", "-f", join(installDir, "docker-compose.yml"),
        "pull", "--ignore-buildable",
      ],
      { timeoutMs: Number(process.env.ARRSTACK_HEADLESS_PULL_TIMEOUT_MS ?? "600000") },'''
if needle not in s: raise SystemExit("headless compose pull timeout anchor missing")
s = s.replace(needle, replacement, 1)
(root / "src/usecase/install.ts").write_text(s)
s = (root / "src/usecase/install.ts").read_text()
# Keep the Cloudflare credential outside state.json and the generic .env.
# Only the Caddy service consumes the private env file below.
s = s.replace('state.remote_access.mode === "cloudflare"\n          ? state.remote_access.token', 'state.remote_access.mode === "cloudflare"\n          ? undefined')
s = s.replace(
    '    writeFileSync(join(installDir, ".env"), content, { mode: 0o600 });',
    '    writeFileSync(join(installDir, ".env"), content, { mode: 0o600 });\n    if (state.remote_access.mode === "cloudflare" && process.env.CF_API_TOKEN) {\n      const caddyDir = join(installDir, "caddy");\n      mkdirSync(caddyDir, { recursive: true });\n      writeFileSync(join(caddyDir, "caddy.env"), `CF_API_TOKEN=${process.env.CF_API_TOKEN}\\n`, { mode: 0o600 });\n    }',
    1,
)
(root / "src/usecase/install.ts").write_text(s)
s = (root / "src/usecase/install.ts").read_text()
needle = '''      const conf = renderQbitConfig({
        username: state.admin.username,
        pbkdf2Hash,
      });'''
replacement = '''      const peerPort = Number(process.env.ARRSTACK_PEER_PORT ?? "35796");
      if (!Number.isInteger(peerPort) || peerPort < 1 || peerPort > 65535) throw new Error("ARRSTACK_PEER_PORT must be 1..65535");
      const conf = renderQbitConfig({
        username: state.admin.username,
        pbkdf2Hash,
      }) + `\\nConnection\\\\PortRangeMin=${peerPort}\\nConnection\\\\PortRangeMax=${peerPort}\\n`;'''
if needle not in s: raise SystemExit("qBittorrent config anchor missing")
(root / "src/usecase/install.ts").write_text(s.replace(needle, replacement, 1))
# qBittorrent may rewrite its config on first start, so enforce the forwarded
# listener through its supported preferences API as part of normal wiring too.
qbit = root / "src/wiring/qbittorrent.ts"
s = qbit.read_text()
needle = '  // 4. Apply TRaSH-recommended preferences\n  const prefs = {'
replacement = '''  // 4. Apply TRaSH-recommended preferences and keep the listener equal to
  // the firewall-published VPN-forwarded port. UPnP and random selection must
  // stay off so they cannot silently diverge from the Host rule.
  const listenPort = Number(process.env.ARRSTACK_PEER_PORT ?? "35796");
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) throw new Error("ARRSTACK_PEER_PORT must be 1..65535");
  const prefs = {
    listen_port: listenPort,
    random_port: false,
    upnp: false,'''
if needle not in s: raise SystemExit("qBittorrent preferences anchor missing")
qbit.write_text(s.replace(needle, replacement, 1))
s = (root / "src/renderer/compose.ts").read_text()
s = s.replace('  extraEnv: EnvEntry[];\n', '  extraEnv: EnvEntry[];\n  envFile?: string;\n', 1)
s = s.replace('      extraEnv,\n      dataMounts,', '      extraEnv,\n      envFile: svc.id === "caddy" && opts.remoteMode === "cloudflare" ? `${opts.installDir}/caddy/caddy.env` : undefined,\n      dataMounts,', 1)
(root / "src/renderer/compose.ts").write_text(s)
s = template.read_text().replace('{{#if apiKeyEnv}}\n      - {{apiKeyEnv}}={{apiKey}}\n{{/if}}', '{{#if apiKeyEnv}}\n      - {{apiKeyEnv}}={{apiKey}}\n{{/if}}\n{{#if envFile}}\n    env_file:\n      - {{envFile}}\n{{/if}}', 1)
template.write_text(s)
# Do not fetch an unpinned prebuilt Caddy image or retain a local build
# fallback. The checked-in digest is the only Caddy input accepted here.
import re
s = (root / "src/usecase/install.ts").read_text()
s = re.sub(r'\n  // Step 9a: Prepare custom Caddy image.*?\n  // Step 9b:', '\n  // Step 9b:', s, count=1, flags=re.S)
(root / "src/usecase/install.ts").write_text(s)
s = caddy.read_text()
s = s.replace('.filter((svc) => svc.adminPort !== undefined)', '.filter((svc) => svc.adminPort !== undefined && new Set(["radarr", "sonarr", "bazarr", "prowlarr", "trailarr", "qbittorrent", "jellyfin", "jellyseerr"]).has(svc.id))')
import re
s = re.sub(r'id: svc\.id,\s*port:', lambda _: 'id: ({radarr: process.env.ARRSTACK_ALIAS_RADARR, sonarr: process.env.ARRSTACK_ALIAS_SONARR, bazarr: process.env.ARRSTACK_ALIAS_BAZARR, prowlarr: process.env.ARRSTACK_ALIAS_PROWLARR, trailarr: process.env.ARRSTACK_ALIAS_TRAILARR} as Record<string, string | undefined>)[svc.id] ?? svc.id,' + chr(10) + '      port:', s, count=1)
caddy.write_text(s)
s = compose.read_text().replace('`0.0.0.0:${p}:${p}`', '`${svc.id === "caddy" ? "10.10.20.230" : "127.0.0.1"}:${p}:${p}`')
s = s.replace('return {\n    image: CADDY_PREBUILT_IMAGE,\n    tag: CADDY_PREBUILT_TAG,\n    build: svc.build,\n  };', 'return { image: svc.image, tag: svc.tag, build: svc.build };')
s = s.replace('const CADDY_PREBUILT_IMAGE = "ghcr.io/lavx/arrstack-caddy";\nconst CADDY_PREBUILT_TAG = "latest";\n', '')
s = s.replace('    return { image: "caddy", tag: "latest", build: undefined };', '    return { image: svc.image, tag: svc.tag, build: svc.build };')
needle = '    const ports: PortBinding[] = ownPorts.map((p) => ({ binding: `${svc.id === "caddy" ? "10.10.20.230" : "127.0.0.1"}:${p}:${p}` }));'
replacement = needle + '''
    if (svc.id === "qbittorrent") {
      const peerPort = Number(process.env.ARRSTACK_PEER_PORT ?? "35796");
      if (!Number.isInteger(peerPort) || peerPort < 1 || peerPort > 65535) throw new Error("ARRSTACK_PEER_PORT must be 1..65535");
      const peerBindAddress = process.env.ARRSTACK_BIND_ADDRESS ?? "10.10.20.230";
      if (!/^10\\.10\\.20\\.230$/.test(peerBindAddress)) throw new Error("ARRSTACK_BIND_ADDRESS must be 10.10.20.230");
      ports.push({ binding: `${peerBindAddress}:${peerPort}:${peerPort}/tcp` }, { binding: `${peerBindAddress}:${peerPort}:${peerPort}/udp` });
    }'''
if needle not in s: raise SystemExit("compose port anchor missing")
s = s.replace(needle, replacement, 1)
# All services use the template's `arrstack` network. Its fixed Linux bridge
# name lets the guest firewall distinguish this stack from other Docker nets.
template.write_text(template.read_text().replace('networks:\n  arrstack:\n    driver: bridge', '''networks:
  arrstack:
    name: btcr-arrstack0
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: btcr-arrstack0
    ipam:
      config:
        - subnet: 172.30.20.0/24''', 1))
# Render service images from the checked-in digest manifest. The template is
# changed to omit the tag when image already contains an immutable digest.
data = json.loads(manifest.read_text())
images = data["services"]
text = catalog.read_text()
for service, image in images.items():
    start = text.find("  - id: " + service)
    if start < 0: continue
    end = text.find("\n  - id:", start + 1)
    if end < 0: end = len(text)
    block = text[start:end]
    import re
    block = re.sub(r"(?m)^    image:.*$", "    image: " + image, block)
    block = re.sub(r'(?m)^    tag:.*$', '    tag: ""', block)
    text = text[:start] + block + text[end:]
catalog.write_text(text)
# Pin Caddy to its reviewed amd64 manifests as well as the application images.
text = catalog.read_text()
caddy_image = data["caddy"]["base"]
start = text.find("  - id: caddy")
if start < 0: raise SystemExit("caddy catalog entry missing")
end = text.find("\n  - id:", start + 1)
if end < 0: end = len(text)
block = text[start:end]
block = re.sub(r"(?m)^    image:.*$", "    image: " + caddy_image, block)
block = re.sub(r"(?m)^    tag:.*$", "    tag: \"\"", block)
block = re.sub(r"(?m)^    build:\n(?:      .*\n)+", "", block)
block = re.sub(r"(?m)^    ports: \[80, 443\]$", "    ports: [443]", block)
block = re.sub(r"(?m)^      port: 80$", "      port: 443", block)
block = block.replace("The stock caddy:latest image ships neither.", "The pinned Caddy image ships neither.")
text = text[:start] + block + text[end:]
catalog.write_text(text)
compose.write_text(s)
s = template.read_text().replace('    image: {{image}}:{{tag}}', '    image: {{image}}{{#if tag}}:{{tag}}{{/if}}')
template.write_text(s)
s = catalog.read_text()
for service in ("tdarr", "gluetun", "dnsmasq", "duckdns-updater", "cloudflare-ddns", "deunhealth"):
    start = s.find("  - id: " + service)
    if start < 0: continue
    end = s.find("\n  - id:", start + 1)
    if end < 0: end = len(s)
    s = s[:start] + s[end + 1:]
catalog.write_text(s)
pkg = root / "package.json"
data = json.loads(pkg.read_text())
target = __import__("os").environ.get("ARRSTACK_BUN_TARGET", "bun-linux-x64")
data["scripts"]["build"] = f"bun run prepare && bun build --compile --minify --target={target} src/cli.ts --outfile dist/arrstack-{target.removeprefix('bun-linux-')}"
pkg.write_text(json.dumps(data, indent=2) + "\n")
PY

mkdir -p "$(dirname "$output")"
(cd "$root" && bun install --save-text-lockfile --frozen-lockfile)
cp internal/arrstack/adapter-contract.test.ts "$root/src/boetticher-adapter-contract.test.ts"
(cd "$root" && bun test src/boetticher-adapter-contract.test.ts && bun run typecheck && bun run build)
if [ -n "${ARRSTACK_LOCK_OUTPUT:-}" ]; then lock=$(find "$root" -maxdepth 1 -name 'bun.lock*' -print -quit); [ -n "$lock" ] && cp "$lock" "$ARRSTACK_LOCK_OUTPUT"; fi
cp "$root/dist/arrstack-${target#bun-linux-}" "$output"
chmod 0755 "$output"
printf '%s\n' "arrstack binary: $output upstream_sha256=$actual_sha"
