const COOKIE="blackmaps_admin";
function decode(value){const s=value.replaceAll("-","+").replaceAll("_","/");const raw=atob(s+"=".repeat((4-s.length%4)%4));return Uint8Array.from(raw,c=>c.charCodeAt(0));}
function encode(bytes){let s="";for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,"");}
async function valid(request,env){
 try{
  if(!env.SESSION_SECRET||!env.ADMIN_USER)return false;
  const token=(request.headers.get("cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1);
  if(!token)return false;
  const [payload,sig,...extra]=token.split(".");
  if(!payload||!sig||extra.length)return false;
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.SESSION_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const expected=encode(new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(payload))));
  if(sig!==expected)return false;
  const data=JSON.parse(new TextDecoder().decode(decode(payload)));
  return data.sub===env.ADMIN_USER&&data.exp>Date.now();
 }catch{return false;}
}
export async function onRequest(context){
 const path=new URL(context.request.url).pathname;
 if(path!=="/admin.html")return context.next();
 const headers={"cache-control":"no-store, no-cache, must-revalidate, max-age=0","x-robots-tag":"noindex, nofollow","vary":"Cookie"};
 if(!await valid(context.request,context.env))return new Response(null,{status:302,headers:{...headers,location:"/admin-login.html"}});
 const response=await context.next(),out=new Headers(response.headers);
 for(const [k,v] of Object.entries(headers))out.set(k,v);
 return new Response(response.body,{status:response.status,statusText:response.statusText,headers:out});
}
