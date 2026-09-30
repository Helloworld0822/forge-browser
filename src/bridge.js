import {parse,stringify,parseNumberAndBigInt} from 'lossless-json';
import {marked} from 'marked';
import DOMPurify from 'dompurify';
const values=new Map(),nodes=new Map(),reverse=new WeakMap(),state=new Map();let next=1n;
const handle=v=>{if(v===null||v===undefined)return 0n;const h=next++;values.set(h,v);return h};
const val=h=>values.get(h)??null;
const node=h=>{const n=nodes.get(h);if(!n)throw new Error('Invalid DOM handle');return n};
const dom=n=>{if(!n)return 0n;let h=reverse.get(n);if(!h){h=next++;reverse.set(n,h);nodes.set(h,n)}return h};
function scoped(fn){const saved=new Set(values.keys());try{return fn()}finally{for(const h of values.keys())if(!saved.has(h))values.delete(h)}}
function release(n){for(const child of n.childNodes)release(child);const h=reverse.get(n);if(h){nodes.delete(h);reverse.delete(n)}}
const number=v=>typeof v==='bigint'?v:typeof v==='number'?BigInt(Math.trunc(v)):0n;
const kind=v=>v==null?0n:typeof v==='boolean'?1n:typeof v==='bigint'?2n:typeof v==='string'?3n:Array.isArray(v)?5n:typeof v==='number'?6n:4n;
const parseJSON=s=>parse(s,null,{parseNumber:parseNumberAndBigInt});
function safeUrl(value){const u=new URL(value,location.origin);if(u.protocol!=='http:'&&u.protocol!=='https:'&&u.protocol!=='mailto:')throw new Error('Unsafe URL');return value}
function checkedPath(path){const url=new URL(path,location.origin);if(url.origin!==location.origin||!url.pathname.startsWith('/api/'))throw new Error('API requests must stay on the same origin');return url}
function callback(fn,context,status,data,error=''){scoped(()=>fn(handle({context,status:BigInt(status),data,error})));}
async function readBody(response){
 const reader=response.body?.getReader();if(!reader)return '';const chunks=[];let bytes=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>4*1024*1024){await reader.cancel();throw new Error('Response exceeds 4 MiB')}chunks.push(value)}}finally{reader.releaseLock()}
 const all=new Uint8Array(bytes);let at=0;for(const chunk of chunks){all.set(chunk,at);at+=chunk.byteLength}return new TextDecoder('utf-8',{fatal:true}).decode(all);
}
async function request(path,method,body,token,fn,context){
 try{const url=checkedPath(path);const headers={'Content-Type':'application/json'};if(token)headers.Authorization=`Bearer ${token}`;
 const r=await fetch(url,{method,headers,body:method==='GET'||method==='DELETE'&&!body?undefined:body,signal:AbortSignal.timeout(15000)});
 const text=await readBody(r);let data=null;try{data=text?parseJSON(text):null}catch{data=text}callback(fn,context,r.status,data);
 }catch(e){callback(fn,context,0,null,e instanceof Error?e.message:String(e))}
 return 1n;
}
export const native={
 fw_uuid:()=>crypto.randomUUID(),fw_now:()=>BigInt(Math.floor(Date.now()/1000)),
 fb_claims:token=>{try{return handle(parseJSON(new TextDecoder().decode(Uint8Array.from(atob(token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)))))}catch{return 0n}},
 fw_scope_begin:()=>0n,fw_scope_end:()=>0n,fw_parse:s=>{try{return handle(parseJSON(s))}catch{return 0n}},fw_kind:h=>kind(val(h)),
 fw_get:(h,k)=>handle(val(h)?.[k]),fw_at:(h,i)=>handle(val(h)?.[Number(i)]),fw_count:h=>BigInt(Array.isArray(val(h))?val(h).length:val(h)&&typeof val(h)==='object'?Object.keys(val(h)).length:0),
 fw_text:h=>typeof val(h)==='string'?val(h):'',fw_integer:h=>number(val(h)),fw_boolean:h=>val(h)?1n:0n,fw_dump:h=>stringify(val(h)),
 fw_object:()=>handle({}),fw_array:()=>handle([]),fw_string:s=>handle(s),fw_number:n=>handle(n),fw_bool:n=>handle(Boolean(n)),
 fw_set:(h,k,c)=>{const obj=val(h);if(!obj||Array.isArray(obj)||typeof obj!=='object'||['__proto__','constructor','prototype'].includes(k))return 0n;obj[k]=val(c);return 1n},
 fw_push:(h,c)=>{const a=val(h);if(!Array.isArray(a))return 0n;a.push(val(c));return 1n},fw_keys:h=>handle(Object.keys(val(h)??{})),fw_has:(h,k)=>Object.hasOwn(val(h)??{},k)?1n:0n,
 fw_urlencode:s=>encodeURIComponent(s),fw_trim:s=>s.trim(),fw_chars:s=>BigInt(Array.from(s).length),fw_lower:s=>s.toLowerCase(),fw_equal:(a,b)=>a===b?1n:0n,fw_starts:(a,b)=>a.startsWith(b)?1n:0n,
 fb_root:()=>dom(document.getElementById('app')),fb_el:(parent,tag,text,classes)=>{if(!/^(div|section|article|header|footer|nav|main|h[1-6]|p|span|a|button|label|input|textarea|select|option|form|pre|code|ul|li|table|thead|tbody|tr|th|td|details|summary|img|br|hr)$/.test(tag))throw new Error('Unsupported DOM tag');const n=document.createElement(tag);n.textContent=text;n.className=classes;node(parent).append(n);return dom(n)},
 fb_attr:(h,key,value)=>{if(/^on/i.test(key)||['innerHTML','srcdoc','style'].includes(key))throw new Error('Unsafe DOM attribute');if(key==='href'||key==='src')safeUrl(value);node(h).setAttribute(key,value);if(key==='value'&&'value' in node(h))node(h).value=value;return 1n},
 fb_clear:h=>{const n=node(h);for(const child of n.childNodes)release(child);n.replaceChildren();return 1n},fb_find:id=>dom(document.getElementById(id)),fb_value:id=>{const n=document.getElementById(id);return n?.type==='checkbox'?(n.checked?'true':'false'):n?.value??''},
 fb_on:(h,event,fn,context)=>{node(h).addEventListener(event,e=>{if(event==='click'||event==='submit')e.preventDefault();scoped(()=>fn(context))});return 1n},
 fb_request:(...args)=>{void request(...args);return 1n},fb_path:()=>location.pathname,
 fb_navigate:(path,fn)=>{const u=new URL(path,location.origin);if(u.origin!==location.origin)throw new Error('Navigation origin mismatch');history.pushState({},'',u.pathname+u.search);scoped(()=>fn(''));return 1n},
 fb_start:fn=>{const token=new URLSearchParams(location.hash.slice(1)).get('token');if(token){localStorage.setItem('auth_token',token);history.replaceState({},'',location.pathname)}window.addEventListener('popstate',()=>scoped(()=>fn('')));scoped(()=>fn(''));return 1n},
 fb_state:(k,v)=>{if(v)state.set(k,v);else state.delete(k);return 1n},fb_state_get:k=>state.get(k)??'',
 fb_store:(k,v)=>{if(v)localStorage.setItem(k,v);else localStorage.removeItem(k);return 1n},fb_load:k=>localStorage.getItem(k)??'',
 fb_markdown:(h,text)=>{const n=document.createElement('div');n.className='markdown';n.innerHTML=DOMPurify.sanitize(marked.parse(text,{async:false}));node(h).append(n);return dom(n)},
 fb_upload:(id,path,token,fn,context)=>{const file=document.getElementById(id)?.files?.[0];if(!file||file.size>20*1024*1024){callback(fn,context,0,null,'Choose one file up to 20 MiB');return 0n}const data=new FormData();data.append('file',file);void fetch(checkedPath(path),{method:'POST',headers:token?{Authorization:`Bearer ${token}`}:{},body:data,signal:AbortSignal.timeout(30000)}).then(async r=>callback(fn,context,r.status,parseJSON(await readBody(r)))).catch(e=>callback(fn,context,0,null,String(e)));return 1n},
 fb_download:(name,text)=>{const url=URL.createObjectURL(new Blob([text],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return 1n},fb_reload:()=>{location.reload();return 1n},fb_origin:()=>location.origin,
};
export function install(){globalThis.ForgeNative=native;}
export function debugCounts(){return {values:values.size,nodes:nodes.size};}
install();
