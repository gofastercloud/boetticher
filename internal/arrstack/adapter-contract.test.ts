import { expect, test } from "bun:test";
import { loadCatalog } from "./catalog/index.js";
import { renderCaddyfile } from "./renderer/caddy.js";
import { renderCompose } from "./renderer/compose.js";

const services = loadCatalog().filter((service) => service.default);

test("Boetticher adapter renders the owned network and pinned public surfaces", () => {
  expect(services.map((service) => service.id).sort()).toEqual([
    "ai-subtitle-translator", "bazarr", "caddy", "flaresolverr", "jellyfin",
    "jellyseerr", "prowlarr", "qbittorrent", "radarr", "recyclarr", "sonarr", "trailarr",
  ]);
  const compose = renderCompose(services, {
    installDir: "/opt/arrstack", storageRoot: "/var/lib/arrstack/media", extraPaths: [],
    puid: 1000, pgid: 1000, timezone: "UTC", apiKeys: {}, gpu: { vendor: "none" },
    vpn: { enabled: false }, remoteMode: "cloudflare",
  });
  expect(compose).toContain("name: btcr-arrstack0");
  expect(compose).toContain("com.docker.network.bridge.name: btcr-arrstack0");
  expect(compose).toContain("subnet: 172.30.20.0/24");
  expect(compose).toContain('"10.10.20.230:443:443"');
  expect(compose).toContain('"10.10.20.230:35796:35796/tcp"');
  expect(compose).toContain('"10.10.20.230:35796:35796/udp"');
  expect(compose).not.toContain("build:");
  expect(compose).not.toContain(":latest");
  expect(compose).toContain("ghcr.io/lavx/arrstack-caddy@sha256:d1c594877aa8f9f79f8fc10bb13c854a1f2219e54422fb3abc4dc3f845aaadd7");
  const caddy = renderCaddyfile(services, { mode: "cloudflare", domain: "davebarton.cc" });
  expect(caddy).toContain("*.davebarton.cc");
  expect(caddy).toMatch(/handle\s*\{\s*respond 404\s*\}/);
  expect(caddy).not.toContain("ai-subtitle-translator.davebarton.cc");
  expect(caddy).not.toContain("recyclarr.davebarton.cc");
});
