// Family gate: every request needs a valid ryuji_session cookie (signed by the
// ryuji.co.uk gate with the shared SECRET) or the visitor is redirected there
// to sign in. /.well-known/* stays open for Cloudflare TLS challenges.
const COOKIE = "ryuji_session";
const enc = new TextEncoder();
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const b64urlToBytes = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function sessionEmail(token, secret) {
  if (!token || !token.includes(".") || !secret) return null;
  const [body, sig] = token.split(".");
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify("HMAC", key, b64urlToBytes(sig), enc.encode(body));
    if (!ok) return null;
    const claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(body)));
    if (typeof claims.e !== "string" || claims.x < Math.floor(Date.now() / 1000)) return null;
    return claims.e.toLowerCase();
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const cookie = (request.headers.get("cookie") || "")
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith(name + "="));
  return cookie ? cookie.slice(name.length + 1) : null;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  if (url.pathname.startsWith("/.well-known/")) return next();
  const email = await sessionEmail(getCookie(request, COOKIE), env.SECRET);
  if (!email) return Response.redirect("https://ryuji.co.uk/", 302);
  return next();
}
