import { expect, test } from "bun:test";
import { mkdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createStorageLayout } from "./storage/layout.js";

test("storage layout owns parents without changing unrelated descendants", () => {
  const root = join(tmpdir(), `boetticher-layout-${process.pid}`);
  const unrelated = join(root, "torrents", "unrelated", "keep");
  mkdirSync(unrelated, { recursive: true });
  writeFileSync(join(unrelated, "marker"), "keep");
  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;
  createStorageLayout(root, uid, gid);
  for (const path of [root, join(root, "torrents"), join(root, "media")]) {
    const info = statSync(path);
    expect(info.uid).toBe(uid);
    expect(info.gid).toBe(gid);
  }
  const marker = statSync(join(unrelated, "marker"));
  expect(marker.uid).toBe(uid);
  expect(marker.gid).toBe(gid);
});
