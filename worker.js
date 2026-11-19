const COOKIE = "anjezha_owner";
const SESSION_SECONDS = 8 * 60 * 60;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra }
  });
}
function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(value) {
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
async function digest(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}
async function sameSecret(a, b) {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
async function signingKey(env) {
  const material = new TextEncoder().encode(env.OWNER_PASSWORD + "|anjezha-owner-session-v1");
  return crypto.subtle.importKey("raw", material, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function issueSession(env) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({
    sub: env.OWNER_USERNAME,
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS,
    nonce: crypto.randomUUID()
  })));
  const key = await signingKey(env);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
  return payload + "." + b64url(sig);
}
function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";
  const part = cookies.split(";").map(x => x.trim()).find(x => x.startsWith(COOKIE + "="));
  return part ? part.slice(COOKIE.length + 1) : "";
}
async function validSession(request, env) {
  try {
    const token = getCookie(request);
    const [payload, signature, extra] = token.split(".");
    if (!payload || !signature || extra) return false;
    const key = await signingKey(env);
    const valid = await crypto.subtle.verify("HMAC", key, fromB64url(signature), new TextEncoder().encode(payload));
    if (!valid) return false;
    const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    return data.sub === env.OWNER_USERNAME && Number(data.exp) > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
function cookie(value, maxAge) {
  return COOKIE + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + maxAge;
}
async function api(request, env) {
  const url = new URL(request.url);
  if (url.pathname === "/api/owner/login" && request.method === "POST") {
    if (request.headers.get("Origin") !== url.origin) return json({ error: "طلب غير مسموح" }, 403);
    if (Number(request.headers.get("Content-Length") || 0) > 2048) return json({ error: "طلب كبير جدًا" }, 413);
    let body;
    try { body = await request.json(); } catch { return json({ error: "بيانات غير صحيحة" }, 400); }
    const username = String(body?.username || "");
    const password = String(body?.password || "");
    const [userOk, passOk] = await Promise.all([
      sameSecret(username, env.OWNER_USERNAME),
      sameSecret(password, env.OWNER_PASSWORD)
    ]);
    if (!userOk || !passOk) return json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة" }, 401);
    const token = await issueSession(env);
    return json({ ok: true }, 200, { "Set-Cookie": cookie(token, SESSION_SECONDS) });
  }
  if (url.pathname === "/api/owner/me" && request.method === "GET") {
    const ok = await validSession(request, env);
    return json({ authenticated: ok }, ok ? 200 : 401);
  }
  if (url.pathname === "/api/owner/logout" && request.method === "POST") {
    return json({ ok: true }, 200, { "Set-Cookie": cookie("", 0) });
  }
  return json({ error: "غير موجود" }, 404);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/owner/")) return api(request, env);
    if (url.pathname === "/admin" || url.pathname === "/admin/") {
      const target = new URL("/admin.html", request.url);
      return env.ASSETS.fetch(new Request(target, request));
    }
    const response = await env.ASSETS.fetch(request);
    const headers = new Headers(response.headers);
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    headers.set("X-Frame-Options", "DENY");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }
};