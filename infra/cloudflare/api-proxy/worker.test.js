// 027 T002 - Worker proxy tests (FR-008). Run: node --test infra/cloudflare/api-proxy/
//
// Contract the implementation must satisfy:
//   - default export { fetch(request, env) }, env.UPSTREAM = Cloud Run origin (https://host, no slash).
//   - the upstream call goes through globalThis.fetch(Request) with redirect "manual".
//   - /internal and /internal/* (also encoded, dot-segment and double-slash spellings) answer 404 and
//     never reach upstream.
//   - X-Forwarded-For is replaced by CF-Connecting-IP; client supplied value never survives.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import worker from "./worker.js";

const UPSTREAM = "https://swastik-api-staging-abc123-el.a.run.app";
const ENV = { UPSTREAM, PROXY_KEY: "k" };
const realFetch = globalThis.fetch;
let calls;
let reply;

beforeEach(() => {
  calls = [];
  reply = () => new Response("ok", { status: 200 });
  globalThis.fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(input, init);
    calls.push({ req, body: req.body ? await req.clone().text() : "" });
    return reply(req);
  };
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

const call = (url, init) => worker.fetch(new Request(url, init), ENV);

test("FR-008 forwards method path query and body to upstream", async () => {
  const res = await call("https://api-staging.swastikapp.co.in/v1/orgs?x=1&y=a%20b", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"a":1}',
  });
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  const { req, body } = calls[0];
  assert.equal(req.method, "POST");
  assert.equal(req.url, `${UPSTREAM}/v1/orgs?x=1&y=a%20b`);
  assert.equal(body, '{"a":1}');
  assert.equal(req.headers.get("content-type"), "application/json");
});

test("FR-008 upstream URL host is the run.app host, not the public host", async () => {
  await call("https://api-staging.swastikapp.co.in/healthz");
  assert.equal(new URL(calls[0].req.url).host, "swastik-api-staging-abc123-el.a.run.app");
});

test("FR-008 does not follow redirects (passes them to the browser)", async () => {
  reply = () => new Response(null, { status: 302, headers: { location: "https://x.example/" } });
  const res = await call("https://api-staging.swastikapp.co.in/x");
  assert.equal(calls[0].req.redirect, "manual");
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), "https://x.example/");
});

for (const path of [
  "/internal/tick",
  "/internal/",
  "/internal",
  "/internal/anything/else",
  "/%69nternal/tick",
  "/x/../internal/tick",
  "//internal/tick",
  "/internal%2Ftick",
]) {
  test(`FR-008 blocks ${path} with 404 and no upstream call`, async () => {
    for (const method of ["GET", "POST", "PUT", "DELETE"]) {
      const init = method === "GET" ? undefined : { method, body: "x" };
      const res = await call(`https://api-staging.swastikapp.co.in${path}`, init);
      assert.equal(res.status, 404, `${method} ${path}`);
    }
    assert.equal(calls.length, 0);
  });
}

test("FR-008 does not block look-alike paths", async () => {
  for (const path of ["/internals", "/v1/internal/x", "/internal-x"]) {
    const res = await call(`https://api-staging.swastikapp.co.in${path}`);
    assert.equal(res.status, 200, path);
  }
  assert.equal(calls.length, 3);
});

test("FR-008 overwrites X-Forwarded-For with CF-Connecting-IP", async () => {
  await call("https://api-staging.swastikapp.co.in/v1/me", {
    headers: { "x-forwarded-for": "6.6.6.6, 7.7.7.7", "cf-connecting-ip": "203.0.113.9" },
  });
  assert.equal(calls[0].req.headers.get("x-forwarded-for"), "203.0.113.9");
});

test("FR-008 drops a spoofed X-Forwarded-For when CF-Connecting-IP is absent", async () => {
  await call("https://api-staging.swastikapp.co.in/v1/me", {
    headers: { "x-forwarded-for": "6.6.6.6" },
  });
  const xff = calls[0].req.headers.get("x-forwarded-for");
  assert.ok(xff === null || !xff.includes("6.6.6.6"), `spoofed value survived: ${xff}`);
});

test("FR-008 passes the Cookie request header through unchanged", async () => {
  await call("https://api-staging.swastikapp.co.in/v1/me", {
    headers: { cookie: "sid=abc; theme=dark" },
  });
  assert.equal(calls[0].req.headers.get("cookie"), "sid=abc; theme=dark");
});

test("FR-008 passes status, headers and every Set-Cookie back unchanged", async () => {
  reply = () => {
    const h = new Headers({ "x-request-id": "r1", "content-type": "application/json" });
    h.append("set-cookie", "a=1; Path=/; HttpOnly; Secure; SameSite=Lax");
    h.append("set-cookie", "b=2; Path=/; HttpOnly; Secure; SameSite=Lax");
    return new Response('{"e":1}', { status: 409, headers: h });
  };
  const res = await call("https://api-staging.swastikapp.co.in/v1/x");
  assert.equal(res.status, 409);
  assert.equal(res.headers.get("x-request-id"), "r1");
  assert.deepEqual(res.headers.getSetCookie(), [
    "a=1; Path=/; HttpOnly; Secure; SameSite=Lax",
    "b=2; Path=/; HttpOnly; Secure; SameSite=Lax",
  ]);
  assert.equal(await res.text(), '{"e":1}');
});

test("FR-008 forwards the Authorization header untouched", async () => {
  await call("https://api-staging.swastikapp.co.in/v1/me", {
    headers: { authorization: "Bearer t0k" },
  });
  assert.equal(calls[0].req.headers.get("authorization"), "Bearer t0k");
});

const callEnv = (env, url, init) => worker.fetch(new Request(url, init), env);

test("FR-008 sets X-Swastik-Client-IP from CF-Connecting-IP and X-Swastik-Proxy-Key from env", async () => {
  await callEnv({ ...ENV, PROXY_KEY: "k3y" }, "https://api-staging.swastikapp.co.in/v1/me", {
    headers: { "cf-connecting-ip": "203.0.113.9" },
  });
  assert.equal(calls[0].req.headers.get("x-swastik-client-ip"), "203.0.113.9");
  assert.equal(calls[0].req.headers.get("x-swastik-proxy-key"), "k3y");
});

test("FR-008 strips incoming X-Swastik-* copies in any case", async () => {
  const h = new Headers();
  h.set("X-SWASTIK-CLIENT-IP", "6.6.6.6");
  h.set("x-Swastik-Proxy-Key", "evil");
  await callEnv({ ...ENV, PROXY_KEY: "k3y" }, "https://api-staging.swastikapp.co.in/v1/me", {
    headers: { ...Object.fromEntries(h), "cf-connecting-ip": "203.0.113.9" },
  });
  assert.equal(calls[0].req.headers.get("x-swastik-client-ip"), "203.0.113.9");
  assert.equal(calls[0].req.headers.get("x-swastik-proxy-key"), "k3y");
});

test("FR-008 a spoofed client-ip header does not survive without CF-Connecting-IP", async () => {
  await callEnv({ ...ENV, PROXY_KEY: "k3y" }, "https://api-staging.swastikapp.co.in/v1/me", {
    headers: { "X-Swastik-Client-IP": "6.6.6.6" },
  });
  assert.notEqual(calls[0]?.req.headers.get("x-swastik-client-ip"), "6.6.6.6");
});

for (const env of [{ UPSTREAM }, { UPSTREAM, PROXY_KEY: "" }]) {
  test(`FR-008 fails closed with 500 and no forward when PROXY_KEY is ${JSON.stringify(env.PROXY_KEY)}`, async () => {
    const res = await callEnv(env, "https://api-staging.swastikapp.co.in/v1/me", {
      headers: { "x-swastik-proxy-key": "evil", "cf-connecting-ip": "203.0.113.9" },
    });
    assert.equal(res.status, 500);
    assert.equal(calls.length, 0);
  });
}
