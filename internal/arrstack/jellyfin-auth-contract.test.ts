import { expect, test } from "bun:test";
import { setupJellyfin } from "./wiring/jellyfin.js";

test("Jellyfin authentication sends standard and legacy authorization headers", async () => {
  const original = globalThis.fetch;
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  globalThis.fetch = (async (input, init) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith("/System/Info/Public")) return Response.json({ StartupWizardCompleted: true });
    if (url.endsWith("/Users/AuthenticateByName")) return Response.json({ AccessToken: "token", User: { Id: "user", Policy: { IsAdministrator: true } } });
    if (url.endsWith("/Library/VirtualFolders")) return Response.json([]);
    throw new Error(`unexpected Jellyfin request ${url}`);
  }) as typeof fetch;
  try {
    await setupJellyfin("alice", "pass", [], "http://jellyfin");
  } finally {
    globalThis.fetch = original;
  }
  const auth = calls.find((call) => call.url.endsWith("/Users/AuthenticateByName"));
  expect(auth).toBeDefined();
  expect(auth?.init?.method).toBe("POST");
  expect(JSON.parse(String(auth?.init?.body))).toEqual({ Username: "alice", Pw: "pass" });
  const headers = new Headers(auth?.init?.headers);
  expect(headers.get("Authorization")).toBe(headers.get("X-Emby-Authorization"));
});
