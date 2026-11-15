// Reverse proxy from the public API host to the Cloud Run origin (env.UPSTREAM).
// - /internal and everything below it is never forwarded (404), in any encoded spelling (FR-008).
// - X-Forwarded-For is replaced by CF-Connecting-IP so clients cannot spoof their address.
// - X-Swastik-Client-IP (from CF-Connecting-IP) and X-Swastik-Proxy-Key (Worker secret PROXY_KEY) are set
//   here and any incoming copies are removed.
// - Redirects and Set-Cookie headers pass through untouched.

function isInternal(pathname) {
  let p = pathname;
  // Decode repeatedly (bounded) so %69nternal, %2F and double encodings cannot slip through.
  for (let i = 0; i < 3; i++) {
    try {
      const d = decodeURIComponent(p);
      if (d === p) break;
      p = d;
    } catch {
      return true; // undecodable path: refuse rather than guess
    }
  }
  p = p.replaceAll("\\", "/").replace(/\/{2,}/g, "/");
  const segments = [];
  for (const s of p.split("/")) {
    if (s === "..") segments.pop();
    else if (s !== "." && s !== "") segments.push(s);
  }
  return segments[0] === "internal";
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (isInternal(url.pathname)) {
      return new Response("not found", { status: 404 });
    }

    const upstream = new URL(env.UPSTREAM);
    upstream.pathname = url.pathname;
    upstream.search = url.search;

    const headers = new Headers(request.headers);
    headers.delete("x-forwarded-for");
    const clientIp = request.headers.get("cf-connecting-ip");
    if (clientIp) headers.set("x-forwarded-for", clientIp);
    // Never trust client-supplied copies; the API only believes values set here.
    headers.delete("x-swastik-client-ip");
    headers.delete("x-swastik-proxy-key");
    if (clientIp) headers.set("x-swastik-client-ip", clientIp);
    if (env.PROXY_KEY) headers.set("x-swastik-proxy-key", env.PROXY_KEY);
    headers.delete("host");

    const hasBody = request.method !== "GET" && request.method !== "HEAD";
    return fetch(
      new Request(upstream.toString(), {
        method: request.method,
        headers,
        body: hasBody ? request.body : undefined,
        redirect: "manual",
        duplex: "half", // required by Node/undici when streaming a body; ignored by Workers
      }),
    );
  },
};
