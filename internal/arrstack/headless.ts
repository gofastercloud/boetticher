import os from "node:os";
import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { VERSION } from "./upstream/src/version.js";
import { generateApiKey, generatePassword } from "./upstream/src/lib/random.js";
import { runInstall, type StepUpdate } from "./upstream/src/usecase/install.js";
import type { State } from "./upstream/src/state/schema.js";
import { readState } from "./upstream/src/state/store.js";

// The Controller invokes this entrypoint with fixed appliance identity and no
// interactive wizard. Credentials are generated in memory and persisted only
// by the upstream installer in its root-private state/config files.
function readAdminPassword(installDir: string): string | undefined {
  const path = join(installDir, "admin.txt");
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error("admin.txt must be a private regular file");
    const match = readFileSync(path, "utf8").match(/^password: ([^\n]+)$/m);
    if (!match?.[1]) throw new Error("admin.txt has no password");
    return match[1];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

export function buildHeadlessState(installDir: string, storageRoot: string): State {
  const existing = readState(installDir);
  const enabled = [
    "caddy", "qbittorrent", "prowlarr", "sonarr", "radarr", "bazarr",
    "flaresolverr", "ai-subtitle-translator", "jellyfin", "jellyseerr", "trailarr", "recyclarr",
  ];
  const apiKeys: Record<string, string> = { ...(existing?.api_keys ?? {}) };
  for (const id of ["prowlarr", "sonarr", "radarr"]) if (!apiKeys[id]) apiKeys[id] = generateApiKey();
  const domain = process.env.ARRSTACK_APPLICATION_DOMAIN;
  if (typeof domain !== "string" || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) throw new Error("ARRSTACK_APPLICATION_DOMAIN must be a valid DNS domain");
  const gpuVendor = process.env.ARRSTACK_GPU_VENDOR ?? "none";
  if (gpuVendor !== "intel" && gpuVendor !== "none") throw new Error("ARRSTACK_GPU_VENDOR must be intel or none");
  const renderGid = process.env.ARRSTACK_GPU_RENDER_GID ? Number(process.env.ARRSTACK_GPU_RENDER_GID) : undefined;
  const videoGid = process.env.ARRSTACK_GPU_VIDEO_GID ? Number(process.env.ARRSTACK_GPU_VIDEO_GID) : undefined;
  if (renderGid !== undefined && (!Number.isInteger(renderGid) || renderGid < 0)) throw new Error("ARRSTACK_GPU_RENDER_GID must be a non-negative integer");
  if (videoGid !== undefined && (!Number.isInteger(videoGid) || videoGid < 0)) throw new Error("ARRSTACK_GPU_VIDEO_GID must be a non-negative integer");
  return {
    schema_version: 1,
    installer_version: VERSION,
    install_dir: installDir,
    storage_root: storageRoot,
    extra_paths: [],
    admin: { username: existing?.admin.username ?? process.env.ARRSTACK_ADMIN_USER ?? os.userInfo().username },
    services_enabled: enabled,
    gpu: { vendor: gpuVendor, ...(renderGid === undefined ? {} : { render_gid: renderGid }), ...(videoGid === undefined ? {} : { video_gid: videoGid }) },
    remote_access: { mode: "cloudflare", domain },
    local_dns: { enabled: false, tld: domain, install_dnsmasq: false },
    vpn: { enabled: false },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    puid: existing?.puid ?? 1000,
    pgid: existing?.pgid ?? 1000,
    subtitle_languages: ["en"],
    api_keys: apiKeys,
    secrets: existing?.secrets ?? {},
  };
}

export async function runHeadlessInstall(
  installDir: string,
  storageRoot: string,
  adminPassword = readAdminPassword(installDir) ?? generatePassword(),
  onStep: (update: StepUpdate) => void = () => {},
) {
  if (readState(installDir) && !readAdminPassword(installDir)) throw new Error("existing arrstack state has no readable private admin.txt; refusing credential rotation");
  return runInstall(buildHeadlessState(installDir, storageRoot), adminPassword, onStep);
}
