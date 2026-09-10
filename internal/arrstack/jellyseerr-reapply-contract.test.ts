import { linkJellyseerr } from "./wiring/jellyseerr.js";

type Call = { url: string; init?: RequestInit };
const endpoint = "http://mock:5055";
function response(status: number, body = "", headers: Record<string, string> = {}) { return new Response(body, { status, headers }); }
function session() { return response(200, "{}", { "set-cookie": "connect.sid=mock-session; Path=/" }); }
function finish() { return [response(200, "{}"), response(200, "[]"), response(200, "{}")]; }
function body(call: Call) { return call.init?.body ? JSON.parse(String(call.init.body)) : {}; }
function publicReady(initialized?: boolean) { return response(200, JSON.stringify(initialized === undefined ? {} : { initialized })); }

async function scenario(name: string, replies: Array<Response | (() => Response)>, expected?: string) {
  const calls: Call[] = []; let index = 0; const previous = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init }); const reply = replies[index++];
    if (!reply) throw new Error(`${name}: unexpected fetch`); return typeof reply === "function" ? reply() : reply;
  }) as typeof fetch;
  try { await linkJellyseerr("admin@example.test", "secret", endpoint); if (expected) throw new Error(`${name}: unexpectedly succeeded`); }
  catch (error) { const message = error instanceof Error ? error.message : String(error); if (expected && !message.includes(expected)) throw new Error(`${name}: expected ${expected}, got ${message}`); if (!expected) throw error; }
  finally { globalThis.fetch = previous; }
  return calls;
}

const retained = await scenario("retained login", [publicReady(), session(), ...finish()]);
if (retained.length !== 5 || "hostname" in body(retained[1])) throw new Error("retained login attempted bootstrap");
const initialized = await scenario("initialized true", [publicReady(), response(401, "bad"), publicReady(true)], "existing-admin authentication failed");
if (initialized.some((call) => "hostname" in body(call))) throw new Error("initialized admin attempted bootstrap");
const fresh = await scenario("fresh bootstrap", [publicReady(), response(401, "bad"), publicReady(false), session(), session(), ...finish()]);
if (!fresh.some((call) => "hostname" in body(call))) throw new Error("fresh install did not bootstrap");
await scenario("malformed public settings", [publicReady(), response(401, "bad"), response(200, "not-json")], "not valid JSON");
await scenario("public HTTP failure", [publicReady(), response(401, "bad"), response(500, "NO_ADMIN_USER")], "HTTP 500");
console.log("Jellyseerr adapter mocked behavior: PASS (5 cases)");
