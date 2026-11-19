const COOKIE = "anjezha_owner";
const SESSION_SECONDS = 8 * 60 * 60;
const OWNER_ENTRY = "/owner-entry-7f3a91c8d2";

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra } });
}
function b64url(bytes) {
  let binary = ""; for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(value) {
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
async function digest(value) { return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))); }
async function sameSecret(a, b) {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let diff = 0; for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i]; return diff === 0;
}
async function signingKey(env) {
  const material = new TextEncoder().encode(env.OWNER_SESSION_SECRET || (env.OWNER_PASSWORD + "|anjezha-owner-session-v2"));
  return crypto.subtle.importKey("raw", material, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function issueSession(env) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ sub: "owner", exp: Math.floor(Date.now()/1000)+SESSION_SECONDS, nonce: crypto.randomUUID() })));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await signingKey(env), new TextEncoder().encode(payload)));
  return payload + "." + b64url(sig);
}
function getCookie(request) {
  const part = (request.headers.get("Cookie") || "").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="));
  return part ? part.slice(COOKIE.length+1) : "";
}
async function validSession(request, env) {
  try {
    const token=getCookie(request), [payload,signature,extra]=token.split(".");
    if(!payload||!signature||extra) return false;
    if(!await crypto.subtle.verify("HMAC",await signingKey(env),fromB64url(signature),new TextEncoder().encode(payload))) return false;
    const data=JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    return data.sub==="owner" && Number(data.exp)>Math.floor(Date.now()/1000);
  } catch { return false; }
}
function cookie(value,maxAge) { return COOKIE+"="+value+"; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age="+maxAge; }
const loginPage = `<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>دخول المالك | أنجزها</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f7fb;font-family:system-ui,'Arial';color:#17243a}.box{width:min(390px,calc(100% - 32px));background:white;border:1px solid #e5ebf4;border-radius:22px;padding:28px;box-shadow:0 20px 70px #102b5214}.logo{width:48px;height:48px;border-radius:15px;background:#2864dc;color:#fff;display:grid;place-items:center;font-size:24px;font-weight:800}.box h1{font-size:22px;color:#102b52;margin:18px 0 6px}.box p{color:#718096;font-size:13px;margin:0 0 22px}label{display:block;font-size:13px;font-weight:700;margin:0 0 8px}input{width:100%;padding:14px;border:1px solid #dce4ef;border-radius:11px;font:inherit;outline:none}input:focus{border-color:#2864dc}button{width:100%;border:0;background:#2864dc;color:white;border-radius:11px;padding:13px;font:inherit;font-weight:700;margin-top:14px;cursor:pointer}#msg{font-size:12px;color:#c0392b;min-height:18px;margin-top:12px}</style><main class="box"><div class="logo">أ</div><h1>دخول المالك</h1><p>هذه الصفحة مخصصة لإدارة موقع أنجزها.</p><form id="f"><label for="p">كلمة المرور</label><input id="p" type="password" autocomplete="current-password" required autofocus><button>دخول لوحة التحكم</button><div id="msg" role="alert"></div></form></main><script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const b=e.target.querySelector('button'),m=document.getElementById('msg');b.disabled=true;b.textContent='جارٍ التحقق…';m.textContent='';try{const r=await fetch('/api/owner/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({password:document.getElementById('p').value})});const d=await r.json();if(!r.ok)throw Error(d.error||'تعذر تسجيل الدخول');location.replace('/admin')}catch(x){m.textContent=x.message;b.disabled=false;b.textContent='دخول لوحة التحكم'}});</script></html>`;
async function api(request,env) {
 const url=new URL(request.url);
 if(url.pathname==="/api/owner/login"&&request.method==="POST"){
  if(request.headers.get("Origin")!==url.origin)return json({error:"طلب غير مسموح"},403);
  let body;try{body=await request.json()}catch{return json({error:"بيانات غير صحيحة"},400)}
  if(!await sameSecret(String(body?.password||""),env.OWNER_PASSWORD))return json({error:"كلمة المرور غير صحيحة"},401);
  return json({ok:true},200,{"Set-Cookie":cookie(await issueSession(env),SESSION_SECONDS)});
 }
 if(url.pathname==="/api/owner/me"&&request.method==="GET"){const ok=await validSession(request,env);return json({authenticated:ok},ok?200:401)}
 if(url.pathname==="/api/owner/logout"&&request.method==="POST")return json({ok:true},200,{"Set-Cookie":cookie("",0)});
 return json({error:"غير موجود"},404);
}
export default {
 async fetch(request,env){
  const url=new URL(request.url);
  if(url.pathname.startsWith("/api/owner/"))return api(request,env);
  if(url.pathname===OWNER_ENTRY&&request.method==="GET")return new Response(loginPage,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","x-robots-tag":"noindex, nofollow"}});
  if(url.pathname==="/admin"||url.pathname==="/admin/"||url.pathname==="/admin.html"){
   if(!await validSession(request,env))return new Response("Not Found",{status:404,headers:{"cache-control":"no-store"}});
   const target=new URL("/admin.html",request.url);return env.ASSETS.fetch(new Request(target,request));
  }
  const response=await env.ASSETS.fetch(request),headers=new Headers(response.headers);
  headers.set("X-Content-Type-Options","nosniff");headers.set("Referrer-Policy","strict-origin-when-cross-origin");headers.set("X-Frame-Options","DENY");
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
 }
};