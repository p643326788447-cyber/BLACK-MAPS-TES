const MAX_IMAGE = 1.5 * 1024 * 1024;
const COOKIE = "blackmaps_admin";
const LOGIN_WINDOW = 15 * 60 * 1000;
const LOGIN_MAX = 5;

const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
const fail = (message,status=400,headers={}) => json({error:message},status,headers);
const clean = (v,n=500) => String(v ?? "").trim().slice(0,n);
const id = () => crypto.randomUUID();
const enc = bytes => { let s=""; for(const b of bytes)s+=String.fromCharCode(b); return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,""); };
const dec = s => { const v=s.replaceAll("-","+").replaceAll("_","/"); const raw=atob(v+"=".repeat((4-v.length%4)%4)); return Uint8Array.from(raw,c=>c.charCodeAt(0)); };
const validLink = s => { if(!s)return ""; try { const u=new URL(s); return u.protocol==="https:"?u.href:""; } catch { return ""; } };
const cookie = (v,age=7*24*60*60) => `${COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
async function sign(payload,secret) {
 const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 return enc(new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(payload))));
}
async function session(req,env) {
 try {
  if(!env.SESSION_SECRET||!env.ADMIN_USER)return false;
  const token=(req.headers.get("cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1);
  if(!token)return false;
  const [payload,sig,...extra]=token.split(".");
  if(!payload||!sig||extra.length||await sign(payload,env.SESSION_SECRET)!==sig)return false;
  const p=JSON.parse(new TextDecoder().decode(dec(payload)));
  return p.sub===env.ADMIN_USER&&Number.isFinite(p.exp)&&p.exp>Date.now();
 } catch { return false; }
}
const db = env => env.DB;
async function getRecord(env,type,key) {
 const row=await db(env).prepare("SELECT payload FROM records WHERE type=? AND id=?").bind(type,key).first();
 return row?.payload ? JSON.parse(row.payload) : null;
}
async function putRecord(env,type,item,mapId="") {
 await db(env).prepare("INSERT INTO records(type,id,map_id,payload,created_at) VALUES(?,?,?,?,?) ON CONFLICT(type,id) DO UPDATE SET map_id=excluded.map_id,payload=excluded.payload,created_at=excluded.created_at")
  .bind(type,item.id,mapId,JSON.stringify(item),item.createdAt||new Date().toISOString()).run();
}
async function listRecords(env,type,mapId=null) {
 const q=mapId===null
  ? await db(env).prepare("SELECT payload FROM records WHERE type=? ORDER BY created_at DESC").bind(type).all()
  : await db(env).prepare("SELECT payload FROM records WHERE type=? AND map_id=? ORDER BY created_at DESC").bind(type,mapId).all();
 return (q.results||[]).map(x=>JSON.parse(x.payload));
}
async function removeRecord(env,type,key) { await db(env).prepare("DELETE FROM records WHERE type=? AND id=?").bind(type,key).run(); }
async function isAdmin(req,env) { return session(req,env); }
async function requireAdmin(req,env) {
 if(!await isAdmin(req,env))return false;
 if(["GET","HEAD","OPTIONS"].includes(req.method))return true;
 const origin=req.headers.get("origin");
 try { return !!origin && new URL(origin).origin===new URL(req.url).origin; } catch { return false; }
}
async function rateKey(req) {
 const ip=req.headers.get("cf-connecting-ip")||"unknown";
 const h=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(ip));
 return enc(new Uint8Array(h));
}
async function loginRate(env,key) {
 const row=await db(env).prepare("SELECT attempts,reset_at FROM login_attempts WHERE ip_hash=?").bind(key).first();
 if(!row||row.reset_at<=Date.now())return {attempts:0,resetAt:Date.now()+LOGIN_WINDOW,blocked:false};
 return {attempts:row.attempts,resetAt:row.reset_at,blocked:row.attempts>=LOGIN_MAX};
}
async function recordFailure(env,key,rate) {
 const attempts=rate.attempts+1;
 await db(env).prepare("INSERT INTO login_attempts(ip_hash,attempts,reset_at) VALUES(?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET attempts=excluded.attempts,reset_at=excluded.reset_at")
 .bind(key,attempts,rate.resetAt).run();
}
async function handle(req,env) {
 const u=new URL(req.url), action=u.searchParams.get("action")||"", method=req.method;
 if(!env.DB)return fail("پایگاه داده به سایت متصل نشده است.",503);
 if(action==="login"&&method==="POST") {
  const origin=req.headers.get("origin");
  try { if(!origin||new URL(origin).origin!==u.origin)return fail("درخواست ورود نامعتبر است.",403); } catch { return fail("درخواست ورود نامعتبر است.",403); }
  if(!env.ADMIN_USER||!env.ADMIN_PASSWORD||!env.SESSION_SECRET)return fail("تنظیمات ورود مدیر هنوز در Cloudflare تکمیل نشده است.",503);
  const key=await rateKey(req),rate=await loginRate(env,key);
  if(rate.blocked)return fail("تعداد تلاش‌های ورود بیش از حد مجاز است. ۱۵ دقیقه بعد دوباره تلاش کن.",429,{"retry-after":String(Math.max(1,Math.ceil((rate.resetAt-Date.now())/1000)))});
  const b=await req.json().catch(()=>({}));
  const goodUser=clean(b.username,100)===env.ADMIN_USER;
  const goodPass=clean(b.password,200)===env.ADMIN_PASSWORD;
  if(!goodUser||!goodPass){await recordFailure(env,key,rate);return fail("نام کاربری یا رمز عبور اشتباه است.",401);}
  await db(env).prepare("DELETE FROM login_attempts WHERE ip_hash=?").bind(key).run();
  const payload=enc(new TextEncoder().encode(JSON.stringify({sub:env.ADMIN_USER,exp:Date.now()+7*24*60*60*1000})));
  return json({ok:true},200,{"set-cookie":cookie(payload+"."+await sign(payload,env.SESSION_SECRET))});
 }
 if(action==="logout"&&method==="POST")return json({ok:true},200,{"set-cookie":cookie("",0)});
 if(action==="me"&&method==="GET")return await isAdmin(req,env)?json({ok:true}):fail("نیاز به ورود مدیر است.",401);

 if(action==="image"&&method==="GET") {
  const key=clean(u.searchParams.get("id"),80);
  const row=await db(env).prepare("SELECT content_type,data FROM images WHERE id=?").bind(key).first();
  if(!row)return fail("تصویر پیدا نشد.",404);
  return new Response(row.data,{headers:{"content-type":row.content_type,"cache-control":"public, max-age=3600","x-content-type-options":"nosniff"}});
 }
 if(action==="maps"&&method==="GET") {
  const maps=await listRecords(env,"map");
  return json({maps:maps.map(m=>({...m,image:m.hasImage?"/api?action=image&id="+encodeURIComponent(m.id):""}))});
 }
 if(action==="maps"&&method==="POST") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const form=await req.formData(),title=clean(form.get("title"),90),th=clean(form.get("th"),2),category=clean(form.get("category"),30),description=clean(form.get("description"),180),link=validLink(form.get("link"));
  const image=form.get("image"),validTh=["14","15","16","17","18","19"].includes(th);
  if(!title||!validTh||!["جنگی","فارمینگ","جام‌گیری","ضد سه‌ستاره"].includes(category))return fail("عنوان، تاون‌هال یا دسته‌بندی معتبر نیست.");
  const hasImage=image&&typeof image.arrayBuffer==="function"&&image.size>0;
  if(hasImage&&(image.size>MAX_IMAGE||!["image/jpeg","image/png","image/webp"].includes(image.type)))return fail("برای این نسخه آزمایشی، تصویر باید JPG، PNG یا WEBP و حداکثر ۱.۵ مگابایت باشد.");
  if(!hasImage&&!link)return fail("لطفاً تصویر یا لینک نقشه وارد کن.");
  const key=id();
  if(hasImage)await db(env).prepare("INSERT INTO images(id,content_type,data,created_at) VALUES(?,?,?,?)").bind(key,image.type,await image.arrayBuffer(),new Date().toISOString()).run();
  const item={id:key,title,th,category,description,link,hasImage:!!hasImage,createdAt:new Date().toISOString()};
  await putRecord(env,"map",item);
  return json({ok:true,map:item},201);
 }
 if(action==="maps"&&method==="PUT") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const b=await req.json().catch(()=>({})),item=await getRecord(env,"map",clean(b.id,80));
  if(!item)return fail("نقشه پیدا نشد.",404);
  const title=clean(b.title,90),th=clean(b.th,2),category=clean(b.category,30),description=clean(b.description,180),link=validLink(b.link);
  if(!title||!["14","15","16","17","18","19"].includes(th)||!["جنگی","فارمینگ","جام‌گیری","ضد سه‌ستاره"].includes(category)||(!link&&!item.hasImage))return fail("اطلاعات نقشه معتبر نیست.");
  Object.assign(item,{title,th,category,description,link,updatedAt:new Date().toISOString()});await putRecord(env,"map",item);return json({ok:true,map:item});
 }
 if(action==="maps"&&method==="DELETE") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const key=clean(u.searchParams.get("id"),80),item=await getRecord(env,"map",key);if(!item)return fail("نقشه پیدا نشد.",404);
  if(item.hasImage)await db(env).prepare("DELETE FROM images WHERE id=?").bind(key).run();
  await removeRecord(env,"map",key);return json({ok:true});
 }
 if(action==="comments"&&method==="GET") {
  const mapId=clean(u.searchParams.get("mapId"),80);
  if(mapId)return json({comments:await listRecords(env,"comment",mapId)});
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const comments=await listRecords(env,"comment"),maps=await listRecords(env,"map"),titles=Object.fromEntries(maps.map(m=>[m.id,m.title]));
  return json({comments:comments.map(c=>({...c,mapTitle:titles[c.mapId]||""}))});
 }
 if(action==="comments"&&method==="POST") {
  const b=await req.json().catch(()=>({})),mapId=clean(b.mapId,80),name=clean(b.name,40)||"کاربر",text=clean(b.text,800);
  if(!mapId||!text)return fail("متن نظر خالی است.");if(!await getRecord(env,"map",mapId))return fail("نقشه پیدا نشد.",404);
  const item={id:id(),mapId,name,text,reply:"",createdAt:new Date().toISOString()};await putRecord(env,"comment",item,mapId);return json({ok:true,comment:item},201);
 }
 if(action==="comments"&&method==="PATCH") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const b=await req.json().catch(()=>({})),item=await getRecord(env,"comment",clean(b.id,80));if(!item)return fail("نظر پیدا نشد.",404);
  item.reply=clean(b.reply,800);item.repliedAt=new Date().toISOString();await putRecord(env,"comment",item,item.mapId);return json({ok:true});
 }
 if(action==="comments"&&method==="PUT") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const b=await req.json().catch(()=>({})),item=await getRecord(env,"comment",clean(b.id,80));if(!item)return fail("نظر پیدا نشد.",404);
  const text=clean(b.text,800);if(!text)return fail("متن نظر خالی است.");
  item.name=clean(b.name,40)||"کاربر";item.text=text;item.editedAt=new Date().toISOString();await putRecord(env,"comment",item,item.mapId);return json({ok:true});
 }
 if(action==="comments"&&method==="DELETE") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  await removeRecord(env,"comment",clean(u.searchParams.get("id"),80));return json({ok:true});
 }
 if(action==="support"&&method==="POST") {
  const b=await req.json().catch(()=>({})),name=clean(b.name,40)||"کاربر",subject=clean(b.subject,90),message=clean(b.message,1500);
  if(!subject||!message)return fail("موضوع و متن پیام الزامی است.");
  const item={id:id(),name,subject,message,reply:"",createdAt:new Date().toISOString()};await putRecord(env,"support",item);return json({ok:true},201);
 }
 if(action==="support"&&method==="GET") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  return json({messages:await listRecords(env,"support")});
 }
 if(action==="support"&&method==="PUT") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const b=await req.json().catch(()=>({})),item=await getRecord(env,"support",clean(b.id,80));if(!item)return fail("پیام پیدا نشد.",404);
  const subject=clean(b.subject,90),message=clean(b.message,1500);if(!subject||!message)return fail("موضوع و متن پیام الزامی است.");
  item.subject=subject;item.message=message;item.editedAt=new Date().toISOString();await putRecord(env,"support",item);return json({ok:true,message:item});
 }
 if(action==="support"&&method==="DELETE") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  await removeRecord(env,"support",clean(u.searchParams.get("id"),80));return json({ok:true});
 }
 if(action==="support"&&method==="PATCH") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const b=await req.json().catch(()=>({})),item=await getRecord(env,"support",clean(b.id,80));if(!item)return fail("پیام پیدا نشد.",404);
  item.reply=clean(b.reply,1200);item.repliedAt=new Date().toISOString();await putRecord(env,"support",item);return json({ok:true});
 }
 if(action==="announcements"&&method==="GET")return json({announcements:await listRecords(env,"announcement")});
 if(action==="announcements"&&method==="POST") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const b=await req.json().catch(()=>({})),title=clean(b.title,90),text=clean(b.text,1200);if(!title||!text)return fail("عنوان و متن اطلاعیه الزامی است.");
  const item={id:id(),title,text,createdAt:new Date().toISOString()};await putRecord(env,"announcement",item);return json({ok:true,announcement:item},201);
 }
 if(action==="announcements"&&method==="PUT") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  const b=await req.json().catch(()=>({})),item=await getRecord(env,"announcement",clean(b.id,80));if(!item)return fail("اطلاعیه پیدا نشد.",404);
  const title=clean(b.title,90),text=clean(b.text,1200);if(!title||!text)return fail("عنوان و متن اطلاعیه الزامی است.");
  item.title=title;item.text=text;item.updatedAt=new Date().toISOString();await putRecord(env,"announcement",item);return json({ok:true,announcement:item});
 }
 if(action==="announcements"&&method==="DELETE") {
  if(!await requireAdmin(req,env))return fail("نیاز به ورود مدیر است.",401);
  await removeRecord(env,"announcement",clean(u.searchParams.get("id"),80));return json({ok:true});
 }
 return fail("مسیر درخواست پیدا نشد.",404);
}
export async function onRequest({request,env}) {
 try { return await handle(request,env); }
 catch(error) { console.error("BLACK MAPS Cloudflare API error",error);return fail("خطای داخلی سرور. لطفاً کمی بعد دوباره تلاش کن.",500); }
}
