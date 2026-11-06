(()=>{'use strict';
const $=id=>document.getElementById(id);
/* ---------- RPO ---------- */
function rpo(){const v=['rpo-rate','rpo-age','rpo-target'].map(id=>$(id).value);const [rate,age,tg]=v.map(Number);if(v.some(x=>x.trim()==='')||[rate,age,tg].some(x=>!Number.isFinite(x)||x<0)){$('rpo-result').textContent='请输入非负数值。';return}const loss=rate*age/60,lim=rate*tg/60;$('rpo-result').textContent=`最多丢失约 ${+loss.toFixed(2)} GB；RPO 允许上限 ${+lim.toFixed(2)} GB。\n恢复点距故障 ${age} 分钟：${age<=tg?'满足':'不满足'} ${tg} 分钟的 RPO。`}
if($('rpo-rate')){['rpo-rate','rpo-age','rpo-target'].forEach(id=>$(id).addEventListener('input',rpo));rpo()}
/* ---------- ID card ---------- */
const W=[7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2],C='10X98765432';
function idcheck(){const s=$('id-input').value.trim().toUpperCase();const out=[];if(!/^\d{17}[\dX]$/.test(s)){$('id-result').textContent='格式不对：应为 17 位数字 + 1 位数字或 X。';return}
const y=+s.slice(6,10),m=+s.slice(10,12),d=+s.slice(12,14);const dt=new Date(y,m-1,d);const okDate=dt.getFullYear()===y&&dt.getMonth()===m-1&&dt.getDate()===d;
const sum=W.reduce((a,w,i)=>a+w*+s[i],0),code=C[sum%11];
out.push(`出生日期 ${s.slice(6,14)}：${okDate?'合法':'不存在的日期'}`);out.push(`加权和 ${sum}，mod 11 = ${sum%11}，应为校验码 ${code}，实际 ${s[17]}：${code===s[17]?'正确':'错误'}`);out.push(`第 17 位 ${s[16]}：${+s[16]%2?'奇数（男）':'偶数（女）'}`);out.push(okDate&&code===s[17]?'结论：格式校验通过（不代表真实存在）':'结论：不规范号码');$('id-result').textContent=out.join('\n')}
if($('id-input')){$('id-input').addEventListener('input',idcheck);idcheck()}
/* ---------- toolbox ---------- */
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:false});
const b2s=b=>dec.decode(b);const s2b=s=>enc.encode(s);
function b64d(s){s=s.replace(/\s/g,'').replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const bin=atob(s);return b2s(Uint8Array.from(bin,c=>c.charCodeAt(0)))}
function b64e(s){let bin='';s2b(s).forEach(b=>bin+=String.fromCharCode(b));return btoa(bin)}
function b32d(s){const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';s=s.toUpperCase().replace(/=+$/,'').replace(/\s/g,'');let bits='';for(const c of s){const i=A.indexOf(c);if(i<0)throw Error('非 Base32 字符 '+c);bits+=i.toString(2).padStart(5,'0')}const out=[];for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));return b2s(new Uint8Array(out))}
function hexd(s){s=s.replace(/[\s:]|0x/gi,'');if(!/^([0-9a-f]{2})+$/i.test(s))throw Error('不是偶数长度的十六进制');return b2s(new Uint8Array(s.match(/../g).map(h=>parseInt(h,16))))}
const hexe=s=>[...s2b(s)].map(b=>b.toString(16).padStart(2,'0')).join('');
const shift=(s,k)=>s.replace(/[a-z]/gi,c=>{const b=c<='Z'?65:97;return String.fromCharCode((c.charCodeAt(0)-b+k+26*10)%26+b)});
const atbash=s=>s.replace(/[a-z]/gi,c=>{const b=c<='Z'?65:97;return String.fromCharCode(25-(c.charCodeAt(0)-b)+b)});
function vigd(s,k){k=k.toUpperCase().replace(/[^A-Z]/g,'');if(!k)throw Error('请输入字母密钥');let j=0;return s.replace(/[a-z]/gi,c=>{const b=c<='Z'?65:97;const r=String.fromCharCode((c.charCodeAt(0)-b-(k.charCodeAt(j%k.length)-65)+26)%26+b);j++;return r})}
function raild(s,n){n=Math.max(2,n|0);const L=s.length,pat=[];let r=0,d=1;for(let i=0;i<L;i++){pat.push(r);if(r===0)d=1;else if(r===n-1)d=-1;r+=d}const cnt=Array(n).fill(0);pat.forEach(x=>cnt[x]++);const rows=[];let p=0;for(let i=0;i<n;i++){rows.push(s.slice(p,p+cnt[i]).split(''));p+=cnt[i]}return pat.map(x=>rows[x].shift()).join('')}
const MO={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'};
const morse=s=>s.trim().split(/\s*\/\s*|\s{2,}/).map(w=>w.split(/\s+/).map(c=>MO[c]||'?').join('')).join(' ');
const bacon=s=>s.toUpperCase().replace(/[^AB]/g,'').match(/.{5}/g).map(g=>String.fromCharCode(65+parseInt(g.replace(/A/g,'0').replace(/B/g,'1'),2))).join('');
function ident(s){const t=s.trim(),r=[];const L=t.length;
 if(/^[01\s]+$/.test(t))r.push('只有 0/1：二进制');
 if(/^[.\-\s/]+$/.test(t))r.push('只有点和划：摩斯 → '+morse(t));
 if(/^[ABab\s]+$/.test(t)&&t.replace(/\s/g,'').length%5===0)r.push('只有 A/B 且 5 的倍数：培根 → '+bacon(t));
 if(/^[0-9a-f]+$/i.test(t)&&L%2===0){const h={32:'MD5 / NTLM / 16 字节密钥',40:'SHA-1',64:'SHA-256 或 SM3（长度相同，无法区分）/ 32 字节密钥',128:'SHA-512 / SM2 公钥 x‖y 或签名 r‖s',130:'以 04 开头则可能是 SM2 未压缩公钥'};r.push(`十六进制，${L} 字符 = ${L/2} 字节${h[L]?'：可能是 '+h[L]:''}`);try{const d=hexd(t);if(/^[\x20-\x7e一-龥\s]+$/.test(d))r.push('Hex 解码 → '+d)}catch(_){}}
 if(/%[0-9a-f]{2}/i.test(t)){try{r.push('URL 编码 → '+decodeURIComponent(t))}catch(_){}}
 if(/^[A-Z2-7]+=*$/.test(t)&&L%8===0){try{r.push('Base32 → '+b32d(t))}catch(_){}}
 if(/^[A-Za-z0-9+/_-]+={0,2}$/.test(t)&&L>=4){try{const d=b64d(t);if(!d.includes('�'))r.push((L%4===0?'Base64':'Base64（缺省 = 或 URL 安全）')+' → '+d)}catch(_){}}
 if(/^[a-z\s,.!?']+$/i.test(t)&&/[a-z]/i.test(t))r.push('只有字母：可能是凯撒/ROT13/维吉尼亚/栅栏，试试下方按钮');
 return r.length?r.join('\n'):'未识别，可能是多层编码或加密数据。'}
document.querySelectorAll('[data-op]').forEach(b=>b.addEventListener('click',()=>{const s=$('tb-input').value,n=+$('tb-n').value||3,o=$('tb-output');try{let r;switch(b.dataset.op){
 case'ident':r=ident(s);break;case'b64d':r=b64d(s.trim());break;case'b64e':r=b64e(s);break;case'b32d':r=b32d(s.trim());break;case'hexd':r=hexd(s);break;case'hexe':r=hexe(s);break;case'urld':r=decodeURIComponent(s);break;case'urle':r=encodeURIComponent(s);break;
 case'caesar':r=Array.from({length:25},(_,i)=>`左移 ${String(i+1).padStart(2)}：${shift(s,-(i+1))}`).join('\n');break;case'rot13':r=shift(s,13);break;case'atbash':r=atbash(s);break;case'vigd':r=vigd(s,$('tb-key').value);break;
 case'rail':r=Array.from({length:5},(_,i)=>`${i+2} 栏：${raild(s.replace(/\s/g,''),i+2)}`).join('\n')+`\n（当前设置 ${Math.max(2,n)} 栏：${raild(s.replace(/\s/g,''),n)}）`;break;case'morse':r=morse(s);break;case'bacon':r=bacon(s);break}o.textContent=r}catch(err){o.textContent='无法处理：'+err.message}}));
if($('tb-output'))$('tb-output').textContent='粘贴密文后点“自动识别”，或直接点对应按钮。';
})();
