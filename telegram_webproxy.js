const CFG = { dnPack: 32 * 1024, upPack: 20 * 1024, dnMs: 1 };
export default { fetch: (req, env) => route(req, env) };
const txt = new TextEncoder(), dec = new TextDecoder(), nil = new Uint8Array(0), badHead = new Set(['HEAD', 'POST', 'GET ', 'OPTI']);
const CRYPTO = globalThis.crypto, macKeys = new Map(), leases = new Map();
const reply = (body = null, status = 404) => new Response(body, { status });

function u8(v) { if (v instanceof Uint8Array && v.constructor === Uint8Array) return v; if (v instanceof ArrayBuffer) return new Uint8Array(v); if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength); throw TypeError(); }
const dup = v => u8(v).slice();
function cat(...args) { const parts = args.filter(v => v?.byteLength).map(u8); const out = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0)); let o = 0; for (const part of parts) { out.set(part, o); o += part.byteLength; } return out; }
const hex = v => Uint8Array.from({ length: v.length / 2 }, (_, i) => Number.parseInt(v.slice(i * 2, i * 2 + 2), 16));
function b64(v) { const b = v instanceof Uint8Array ? v : new Uint8Array(v); return btoa(String.fromCharCode(...b)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''); }
const un64 = v => { const s = v.replaceAll('-', '+').replaceAll('_', '/'); return Uint8Array.from(atob(s + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0)); };
const rand = n => CRYPTO.getRandomValues(new Uint8Array(n));
const wake = st => { const { wake: ok } = st; st.wake = null; ok?.(); };
const isType = t => t === 1 || t === 2 || t === 3 || t === 4 || t === 17;
function enc(type, sid, data = nil) { const body = u8(data); if (!isType(type)) throw RangeError(); if (!Number.isInteger(sid) || sid < 0 || sid > 0xffffff) { throw RangeError(); } if (body.byteLength > 1024 * 1024) throw RangeError(); const frame = new Uint8Array(8 + body.byteLength); frame[0] = type; frame[1] = sid >>> 16; frame[2] = sid >>> 8; frame[3] = sid; new DataView(frame.buffer).setUint32(4, body.byteLength, false); frame.set(body, 8); return frame; }
function getFrame(b, o) { if (b.byteLength - o < 8) return null; const type = b[o]; if (!isType(type)) throw Error(); const view = new DataView(b.buffer, b.byteOffset + o, b.byteLength - o); const sid = (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]; const n = view.getUint32(4, false); if (n > 1024 * 1024) throw Error(); const total = 8 + n; if (b.byteLength - o < total) return null; return { frame: { type, sid, payload: b.subarray(o + 8, o + total) }, consumed: total, }; }
function frames(v) { const src = u8(v), out = []; for (let o = 0; o < src.byteLength;) { const part = getFrame(src, o); if (!part) throw Error(); if (out.length >= 4096) throw Error(); out.push(part.frame); o += part.consumed; } return out; }
function win(data) { const body = u8(data); if (body.byteLength !== 4) throw Error(); const n = new DataView(body.buffer, body.byteOffset, 4).getUint32(0, false); if (!n) throw Error(); return n; }
function check(frame) { const { type, payload: data } = frame; if (type === 1 || type === 3) { if (data.byteLength) throw Error(); return 0; } if (type === 2) { if (!data.byteLength) throw Error(); return 0; } if (type === 4) return win(data); throw Error(); }
const i16 = (b, o) => (b[o] | b[o + 1] << 8) << 16 >> 16;
function headOf(head) { const tag = new DataView(head.buffer, head.byteOffset, head.byteLength).getUint32(56, true); const mode = tag === 0xefefefef ? 0xef : tag === 0xeeeeeeee ? 0xee : tag === 0xdddddddd ? 0xdd : 0; if (!mode) throw Error(); const dc = i16(head, 60); const target = Math.abs(dc) - 1; if (target < 0 || target >= 5) throw Error(); return { mode, target, media: dc < 0 }; }
function mkHead(mode, target, media) { const head = new Uint8Array(64); do { CRYPTO.getRandomValues(head); } while ( head[0] === 0xef || badHead.has(dec.decode(head.subarray(0, 4))) || head.subarray(4, 8).every(v => v === 0) ); head.fill(mode, 56, 60); new DataView(head.buffer).setInt16(60, (target + 1) * (media ? -1 : 1), true); return head; }
function getKey(v, keepTag = false) { const str = String(v || '').trim().toLowerCase(); if (!/^(?:[0-9a-f]{32}|(?:dd|ee|ef)[0-9a-f]{32})$/.test(str)) { throw Error(); } return hex(keepTag && str.length === 34 && str.startsWith('dd') ? str : str.slice(-32)); }
function hostOf(v) { const host = String(v || '').trim().toLowerCase().replace(/\.$/, ''); const labels = host.split('.'); if (!host.includes('.') || host.length > 253 || host.includes(':') || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) { throw Error(); } return host; }
const macKey = (raw, id) => { let key = macKeys.get(id); if (!key) macKeys.set(id, key = CRYPTO.subtle.importKey('raw', u8(raw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])); return key; };
const sign = async (key, v) => new Uint8Array(await CRYPTO.subtle.sign('HMAC', await key, u8(v)));
async function mac(boot, kind, body) { const prefix = txt.encode(`${kind}\n`); const msg = new Uint8Array(prefix.byteLength + body.byteLength); msg.set(prefix); msg.set(body, prefix.byteLength); return (await sign( macKey(txt.encode(boot), `token:${boot}`), msg, )).slice(0, 16); }
async function mkToken(boot, kind, expAt, nonce) { const body = new Uint8Array(4 + 12); const exp = Math.ceil(expAt / 1000); new DataView(body.buffer).setUint32(0, exp, false); body.set(nonce, 4); const token = new Uint8Array(32); token.set(body); token.set(await mac(boot, kind, body), body.byteLength); return b64(token); }
const mkBoot = async boot => mkToken(boot, 'bootstrap', Date.now() + 2 * 60 * 1000, rand(12));
async function verify(v, boot, kind) { if (typeof v !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(v)) return false; let token; try { token = un64(v); } catch { return false; } if (token.byteLength !== 32 || b64(token) !== v) return false; const body = token.slice(0, 4 + 12); const sig = token.slice(body.byteLength); const exp = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(0, false); if (exp <= Math.floor(Date.now() / 1000)) return false; const want = await mac(boot, kind, body); let diff = sig.byteLength ^ want.byteLength; for (let i = 0; i < want.length; i++) diff |= sig[i] ^ want[i]; return diff === 0; }
const mkSess = async boot => mkToken(boot, 'session', Date.now() + 5 * 60 * 1000, rand(12));
const authBoot = async (v, boot) => v === boot || verify(v, boot, 'bootstrap');
const mkLease = token => ({ expires: new DataView(un64(token).buffer).getUint32(0) * 1000, active: new Set(), used: new Set(), deleted: false, });
const bearer = v => /^Bearer ([^\s]+)$/.exec(v || '')?.[1] ?? null;
const binary = req => req.headers.get('Content-Type')?.trim().toLowerCase() === 'application/octet-stream';
function hello(body) { if (body.byteLength !== 9 || body[0] !== 0x10 || body[1] !== 0 || body[2] !== 0 || body[3] !== 0 || new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(4, false) !== 1 || body[8] !== 1) { throw Error(); } }
const protos = req => (req.headers.get('Sec-WebSocket-Protocol') ?? '').split(',').map(v => v.trim()).filter(Boolean);
const mkCfg = ({ SECRET, BOOT, ADMIN_PASSWORD }) => { const secret = String(SECRET || '').trim(), boot = String(BOOT || '').trim(), admin = String(ADMIN_PASSWORD || '').trim(); if (!secret) throw Error(); if (!boot) throw Error(); return { secret, key: getKey(secret), boot, admin: admin.length >= 8 ? admin : '' }; };
async function mkCap(secret, host) { const key = macKey( getKey(secret, true), `bridge:${String(secret).trim().toLowerCase()}`, ); const sig = await sign( key, txt.encode(`tdesktop-web-proxy-bridge-v1\n${hostOf(host)}`), ); return b64(sig); }
async function bridge(url, secret) { if (url.pathname !== '/' || url.search.length !== 51) return null; const cand = url.search.slice(8); if (url.search !== `?bridge=${cand}` || !/^[A-Za-z0-9_-]{43}$/.test(cand)) return null; const host = hostOf(url.hostname); const want = await mkCap(secret, host); if (cand.length !== want.length) return null; let diff = 0; for (let i = 0; i < want.length; i++) diff |= cand.charCodeAt(i) ^ want.charCodeAt(i); return diff === 0 ? host : null; }
const sha = async v => new Uint8Array(await CRYPTO.subtle.digest('SHA-256', u8(v)));
function step(ctr, n) { let carry = n; for (let i = ctr.length - 1; i >= 0 && carry; i--) { const next = ctr[i] + (carry & 0xff); ctr[i] = next & 0xff; carry = Math.floor(carry / 256) + Math.floor(next / 256); } if (carry) throw Error(); }
const mkCtr = (key, ctr) => { let iv = dup(ctr), tail = nil; const ready = CRYPTO.subtle.importKey('raw', u8(key), { name: 'AES-CTR' }, false, ['encrypt']);
  const crypt = async (v) => { const b = u8(v); if (!b.byteLength) return new Uint8Array(0); const key = await ready; if (!tail.byteLength && !(b.byteLength % 16)) { const raw = new Uint8Array(await CRYPTO.subtle.encrypt( { name: 'AES-CTR', counter: iv.slice(), length: 128 }, key, b, )); step(iv, b.byteLength / 16); return raw; } if (b.byteLength <= tail.byteLength) { const out = new Uint8Array(b.byteLength); for (let i = 0; i < b.byteLength; i++) out[i] = b[i] ^ tail[i]; tail = tail.slice(b.byteLength); return out; } const skip = tail.byteLength ? 16 - tail.byteLength : 0; const ctr = iv.slice(); if (skip) { for (let i = ctr.length - 1; i >= 0; i--) if (ctr[i]--) break; } const end = skip + b.byteLength; const block = new Uint8Array(Math.ceil(end / 16) * 16); block.set(b, skip); const raw = new Uint8Array(await CRYPTO.subtle.encrypt( { name: 'AES-CTR', counter: ctr, length: 128 }, key, block, )); tail = raw.slice(end); step(iv, block.byteLength / 16 - (skip ? 1 : 0)); return raw.subarray(skip, end); }; return { crypt }; };
async function cipher(head, secret, reverse) { const mat = dup(u8(head).subarray(8, 56)); if (reverse) mat.reverse(); const key = secret.byteLength ? await sha(cat(mat.subarray(0, 32), secret)) : mat.subarray(0, 32); return mkCtr(key, mat.subarray(32, 48)); }
async function wireHead(head) { const ctr = await cipher(head, nil, false); const raw = await ctr.crypt(head); raw.set(u8(head).subarray(0, 56)); return { wire: raw, cipher: ctr }; }
const hosts = (dc, media) => [ `kws${dc}${media ? '-1' : ''}.web.telegram.org`, `kws${dc}${media ? '' : '-1'}.web.telegram.org`, ];
async function dial({ target, media, signal }) { for (const host of hosts(target + 1, media)) { if (signal?.aborted) throw Error(); const url = `wss://${host}/apiws`; let kws; try { kws = mkWire(new WebSocket(url, 'binary'), 7500, signal); await kws.ready; if (signal?.aborted) throw Error(); return kws; } catch (err) { kws?.close(); if (signal?.aborted) throw err; } } throw Error(); }
const mkWire = (ws, ms, signal) => { const q = [], wait = []; let h = 0, qBytes = 0, closed = false, dead = false, up = false, fault = null; let pWake = null, pNeed, openTimer, readyOk, readyBad;
  const ready = new Promise((ok, bad) => { readyOk = ok; readyBad = bad; });
  const onAbort = () => { end(Error()); close(); };
  const onOpen = () => { if (closed) return; if (ws.protocol !== 'binary') { end(Error()); close(); return; } up = true; clearTimeout(openTimer); readyOk(api); };
  const onData = (v) => { if (closed) return; const b = v instanceof Uint8Array ? v : new Uint8Array(v); if (!b.byteLength) return; const waiter = wait.shift(); if (waiter) waiter.resolve(b); else { q.push(b); qBytes += b.byteLength; if (pWake && (qBytes >= pNeed || b.byteLength >= CFG.dnPack)) pWake(); } };
  const end = (err = null) => { if (closed) return; closed = true; fault = err; clearTimeout(openTimer); signal?.removeEventListener('abort', onAbort); if (!up) readyBad(err || Error()); pWake?.(); for (const waiter of wait.splice(0)) err ? waiter.reject(err) : waiter.resolve(null); };
  const write = async (v) => { await ready; if (closed) throw fault || Error(); ws.send(u8(v)); };
  const take = async () => { await ready; if (h < q.length) { const msg = q[h]; q[h++] = null; qBytes -= msg.byteLength; trim(); return msg; } if (fault) throw fault; if (closed) return null; return new Promise((ok, bad) => wait.push({ resolve: ok, reject: bad })); };
  const pack = async () => { const first = await take(); if (dead) return null; if (!first || first.byteLength >= CFG.dnPack) return first; if (!closed && qBytes < CFG.dnPack - first.byteLength) { await new Promise(ok => { pNeed = CFG.dnPack - first.byteLength; const timer = setTimeout(() => pWake?.(), CFG.dnMs); pWake = () => { clearTimeout(timer); pWake = null; ok(); }; }); } if (dead) return null; let n = first.byteLength, end = h; while (end < q.length && n + q[end].byteLength <= CFG.dnPack) { n += q[end++].byteLength; } if (end === h) return first; const b = new Uint8Array(n); b.set(first); let o = first.byteLength; while (h < end) { const part = q[h]; q[h++] = null; b.set(part, o); o += part.byteLength; qBytes -= part.byteLength; } trim(); return b; };
  const trim = () => { if (h === q.length) { q.length = 0; h = 0; } else if (h >= 256 && h * 2 >= q.length) { q.splice(0, h); h = 0; } };
  const close = () => { if (dead) return; dead = true; if (!closed) end(); q.length = h = qBytes = 0; try { ws.close(1000); } catch {} };
  const api = { ready, write, readPack: pack, close, get closed() { return closed; } };
  ws.binaryType = 'arraybuffer'; ws.addEventListener('open', onOpen);
  ws.addEventListener('message', e => onData(e.data)); ws.addEventListener('error', () => end(Error()));
  ws.addEventListener('close', e => end( e?.code && e.code !== 1000 ? Error() : null, ));
  openTimer = setTimeout(() => { end(Error()); close(); }, ms);
  signal?.addEventListener('abort', onAbort, { once: true }); if (signal?.aborted) onAbort(); return api; };
const mkPkt = mode => { let tail = nil;
  const push = (v) => { const b = u8(v); if (b.byteLength) tail = tail.byteLength ? cat(tail, b) : b; const pkts = []; let o = 0; for (;;) { const avail = tail.byteLength - o; let hLen; let pLen; if (mode === 0xef) { if (avail < 1) break; let words = tail[o] & 0x7f; if (words === 0x7f) { if (avail < 4) break; words = tail[o + 1] | (tail[o + 2] << 8) | (tail[o + 3] << 16); hLen = 4; } else hLen = 1; pLen = words * 4; } else { if (avail < 4) break; pLen = new DataView( tail.buffer, tail.byteOffset + o, 4, ).getUint32(0, true) & 0x7fffffff; hLen = 4; } if (!pLen || pLen > 8 * 1024 * 1024) throw Error(); const total = hLen + pLen; if (avail < total) break; pkts.push(tail.subarray(o, o + total)); o += total; } if (o) tail = o === tail.byteLength ? nil : tail.slice(o); if (tail.byteLength > 8 * 1024 * 1024 + 4) throw Error(); return pkts; }; const clear = () => { tail = nil; }; return { push, clear }; };
const mkStream = ({ secret, emit, onClose }) => { let hdr = nil, cIn = null, cOut = null, kIn = null, kOut = null, peer = null, pkt = null; let init = false, closed = false, chain = Promise.resolve(); const ac = new AbortController(), uq = new Set();
  const push = (v) => { if (closed) return Promise.reject(Error()); const job = { bytes: u8(v) }; uq.add(job); chain = chain.then(async () => { if (closed) throw Error(); if (!job.bytes) return job.result; const jobs = [job]; let n = job.bytes.byteLength; for (const next of uq) { if (next === job) continue; if (n >= CFG.upPack || n + next.bytes.byteLength > CFG.upPack) break; n += next.bytes.byteLength; jobs.push(next); } const b = jobs.length === 1 ? job.bytes : cat(...jobs.map(x => x.bytes)); for (const item of jobs) { uq.delete(item); item.bytes = null; } const out = await feed(b); for (const item of jobs) item.result = out; return out; }); return chain; };
  const feed = async (b) => { if (closed) throw Error(); if (init && peer.closed) return false; if (!b.byteLength) return; if (!init) { const need = 64 - hdr.byteLength; if (b.byteLength < need) { hdr = cat(hdr, b); return; } hdr = cat(hdr, b.subarray(0, need)); await start(); const rest = b.subarray(need); if (rest.byteLength) return write(rest); return; } return write(b); };
  const start = async () => { const raw = hdr; const cr = await cipher(raw, secret, false); const plain = await cr.crypt(raw); if (closed) return; const info = headOf(plain); const head = mkHead(info.mode, info.target, info.media); const [cw, out, kr] = await Promise.all([ cipher(raw, secret, true), wireHead(head), cipher(head, nil, true), ]); if (closed) return; const kws = await dial({ target: info.target, media: info.media, signal: ac.signal, }); if (closed) { kws.close(); return; } peer = kws; cIn = cr; cOut = cw; kOut = out.cipher; kIn = kr; pkt = mkPkt(info.mode); await kws.write(out.wire); if (closed) return; hdr = nil; init = true; pump().catch(() => close()); };
  const write = async (raw) => { if (closed || peer.closed) return false; const plain = await cIn.crypt(raw); if (closed || peer.closed) return false; const pkts = pkt.push(plain); for (let start = 0; start < pkts.length;) { let end = start + 1, n = pkts[start].byteLength; while (end < pkts.length && n + pkts[end].byteLength <= CFG.upPack) { n += pkts[end++].byteLength; } const first = pkts[start]; const b = end === start + 1 ? first : new Uint8Array(first.buffer, first.byteOffset, n); if (closed || peer.closed) return false; const wire = await kOut.crypt(b); for (let o = 0; start < end; start++) { if (closed || peer.closed) return false; const n = pkts[start].byteLength; try { await peer.write(wire.subarray(o, o + n)); } catch (err) { if (closed || peer.closed) return false; throw err; } o += n; } } };
  const pump = async () => { while (!closed) { const b = await peer.readPack(); if (closed) return; if (!b) return close(); const plain = await kIn.crypt(b); if (closed) return; const raw = await cOut.crypt(plain); if (closed) return; await emit(raw); } };
  const close = () => { if (closed) return; closed = true; ac.abort(); try { peer?.close(); } catch {} for (const job of uq) job.bytes = null; uq.clear(); hdr = nil; pkt?.clear(); cIn = cOut = kIn = kOut = peer = null; try { onClose(); } catch {} }; return { push, close }; };
const mkSession = ({ secret, sid, onClose, lease }) => { let sock = null, closed = false, tx = Promise.resolve(), cur = null;
  const attach = (ws) => { if (sock || closed) throw Error(); sock = ws; ws.accept({ allowHalfOpen: true }); ws.binaryType = 'arraybuffer'; ws.addEventListener('message', e => { if (closed) return; try { onData(e.data); } catch { close(1008); } }); ws.addEventListener('close', () => close()); ws.addEventListener('error', () => close()); };
  const onData = (v) => { if (closed) return; if (lease?.deleted) { return close(1000); } if (typeof v === 'string') throw Error(); const b = v instanceof Uint8Array ? v : new Uint8Array(v); if (!b.byteLength || b.byteLength > 2 * 1024 * 1024) { throw Error(); } for (const frame of frames(b)) { if (closed) return; const delta = check(frame); if (frame.sid !== sid) throw Error(); if (!cur && frame.type !== 1) throw Error(); if (frame.type !== 1 && cur?.closed) continue; if (frame.type === 1) open(); else if (frame.type === 2) write(frame.payload); else if (frame.type === 4) grant(delta); else if (frame.type === 3) end(false); else throw Error(); } };
  const send = (type, data = nil) => { const out = enc(type, sid, data); const st = type === 2 || type === 4 ? cur : null; tx = tx.then(() => { if (closed) throw Error(); if ((type === 2 || type === 4) && (!st || st.closed)) return; sock.send(out); }); return tx; };
  const open = () => { if (closed) return; if (cur) throw Error(); const st = { in: 4 * 1024 * 1024, out: 4 * 1024 * 1024, wake: null, closed: false, proxy: null, pItems: 0, }; st.proxy = mkStream({ secret, emit: b => emitDn(st, b), onClose: () => { if (!closed && !st.closed) end(true); }, }); cur = st; };
  const write = (data) => {
    if (closed || cur?.closed) return;
    const st = cur;
    if (!st || st.closed) throw Error();
    const n = data.byteLength;
    if (n > st.in) throw Error();
    if (st.pItems >= 16384) { throw Error(); }
    st.in -= n; st.pItems++;
    st.proxy.push(data).then(accepted => { freeUp(st); if (closed || st.closed || accepted === false) return; st.in += n; const delta = new Uint8Array(4); new DataView(delta.buffer).setUint32(0, n); send(4, delta).catch(() => close()); }, () => { freeUp(st); if (!closed && !st.closed) st.proxy.close(); }).catch(() => close());
  };
  const freeUp = (st) => { if (st.closed) return; st.pItems--; };
  const emitDn = async (st, b) => {
    for (let o = 0; o < b.byteLength; ) {
      while (!closed && !st.closed && st.out === 0) { await new Promise(ok => { st.wake = ok; }); }
      if (closed || st.closed) throw Error();
      const n = Math.min(64 * 1024, b.byteLength - o, st.out);
      st.out -= n;
      await send(2, b.subarray(o, o + n));
      o += n;
    }
  };
  const grant = (n) => { if (closed || cur?.closed) return; const st = cur; if (!st || st.closed) throw Error(); st.out = Math.min(0xffffffff, st.out + n); wake(st); };
  const stop = (st) => { st.closed = true; st.pItems = 0; wake(st); st.proxy.close(); };
  const end = (notify) => { if (closed || cur?.closed) return; const st = cur; if (!st) throw Error(); stop(st); if (notify) send(3).then(() => close(), () => close()); else close(); };
  const close = (code = 1000, reason = '') => { if (closed) return; closed = true; if (cur) stop(cur); cur = null; try { sock?.close(code, reason); } catch {} onClose?.(); onClose = null; }; return { attach, close }; };

function mkPage(host, boot) { const nonce = b64(rand(18));
  const body = `<script nonce="__NONCE__">
(()=>{'use strict'; const origin=__ORIGIN__,boot=__BOOTSTRAP__;
const aNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash)?.[1]??''; history.replaceState(null,'',location.pathname);
let init=false,closed=false,port=null,token='',started=false,delSent=false; let qBytes=0,qItems=0;
const lanes=new Map(),used=new Set(),qMax=33554432,iMax=16384,msgMax=2097152; const laneMax=8388608,laneItems=1024;
const state=st=>port&&!closed&&port.postMessage({t:'status',state:st});
const opts=(method,token,body,keepalive)=>({ method,body,keepalive:!!keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer', headers:{...(token&&{Authorization:'Bearer '+token}),...(body&&{'Content-Type':'application/octet-stream'})} });
function check(v){ if(!(v instanceof ArrayBuffer)||!v.byteLength||v.byteLength>msgMax)throw Error(); const view=new DataView(v);let o=0,frames=0; while(o<v.byteLength){ if(v.byteLength-o<8||frames++>=4096)throw Error(); const type=view.getUint8(o),n=view.getUint32(o+4),end=o+8+n; if(n>1048576||end>v.byteLength||(type===2&&!n))throw Error(); o=end; } return v; }
function split(v){ check(v);const view=new DataView(v),out=[];let o=0; while(o<v.byteLength){ const end=o+8+view.getUint32(o+4); out.push(o===0&&end===v.byteLength?v:v.slice(o,end));o=end; } return out; }
function sid(v){const b=new Uint8Array(v);return (b[1]<<16)|(b[2]<<8)|b[3];}
function hold(lane,v){ let buffered=0;for(const {ws} of lanes.values())buffered+=ws?.bufferedAmount??0; const own=lane.ws?.bufferedAmount??0; if(qBytes+buffered>qMax-v.byteLength||qItems>=iMax ||lane.bytes+own>laneMax-v.byteLength||lane.items>=laneItems)return false; qBytes+=v.byteLength;qItems++;lane.bytes+=v.byteLength;lane.items++;return true; }
function free(lane,v){qBytes-=v.byteLength;qItems--;lane.bytes-=v.byteLength;lane.items--;}
function fail(){ if(closed)return;state('failed');port?.postMessage({t:'close'});close(true); }
function drop(){ if(delSent||!token)return;delSent=true; fetch(origin+'/api/v1/session',opts('DELETE',token,null,true)).catch(()=>{}); }
function pump(lane){ const ws=lane.ws; if(closed||lane.done||!ws||ws.readyState!==WebSocket.OPEN||!lane.pending.length)return; if(ws.bufferedAmount>=msgMax){lane.timer ||= setTimeout(()=>{lane.timer=0;pump(lane);},10);return;} try{ const v=lane.pending.shift();ws.send(v);free(lane,v); port.postMessage({t:'traffic',up:v.byteLength,down:0}); if(lane.pending.length)queueMicrotask(()=>pump(lane)); }catch{fail();} }
function push(v){ try{for(const frame of split(v))pushLane(frame);} catch{fail();} }
function end(lane,notify){ if(lane.done)return;lane.done=true;if(lane.timer)clearTimeout(lane.timer); qBytes-=lane.bytes;qItems-=lane.items;lane.bytes=lane.items=0;lane.pending.length=0;lanes.delete(lane.id); try{lane.ws?.close();}catch{} if(notify&&port&&!closed){const frame=new ArrayBuffer(8),b=new Uint8Array(frame);b[0]=3;b[1]=lane.id>>>16;b[2]=lane.id>>>8;b[3]=lane.id;port.postMessage(frame,[frame]);} }
function open(lane){ const target=origin.replace(/^https:/,'wss:')+'/api/v1/ws'; const ws=lane.ws=new WebSocket(target,'tproxy-lane-v1.'+token+'.'+lane.id);ws.binaryType='arraybuffer'; ws.onopen=()=>{if(closed||lane.done){ws.close();return;}lane.opened=true;state('connected');pump(lane);}; ws.onmessage=e=>{ if(closed||lane.done)return; try{ const frames=split(e.data); if(frames.some(frame=>sid(frame)!==lane.id))throw Error(); const ended=frames.some(frame=>new Uint8Array(frame)[0]===3); if(ended)lane.rClosed=true; port.postMessage({t:'traffic',up:0,down:e.data.byteLength});port.postMessage(e.data,[e.data]);state('connected'); if(ended)end(lane,false); }catch{fail();} }; ws.onerror=()=>{}; ws.onclose=()=>{if(closed||lane.done)return;if(!lane.opened){fail();return;}end(lane,!lane.lClosed&&!lane.rClosed);}; }
function pushLane(v){ const id=sid(v),type=new Uint8Array(v)[0];let lane=lanes.get(id); if(!id)throw Error(); if(!lane&&(type===2||type===3||type===4))return; if(!lane){ if(type!==1||used.has(id)||lanes.size>=128||used.size>=4096)throw Error(); used.add(id);lane={id,ws:null,pending:[],bytes:0,items:0,timer:0,opened:false,done:false,lClosed:false,rClosed:false};lanes.set(id,lane); } if(lane.lClosed)return; if(type===3&&!lane.opened){end(lane,false);return;} if(!hold(lane,v))throw Error(); lane.pending.push(v);if(type===3)lane.lClosed=true; if(token){if(!lane.ws)open(lane);else pump(lane);} }
async function create(first){ try{ state('connecting'); const res=await fetch(origin+'/api/v1/session',opts('POST',boot,first)); if(res.status!==200||res.headers.get('X-Carrier-Mode')!=='websocket-lanes')throw Error(); token=res.headers.get('X-Session-Token')??''; if(!token)throw Error(); const welcome=await res.arrayBuffer();check(welcome); if(closed){drop();return;} port.postMessage(welcome,[welcome]);state('connected'); for(const lane of lanes.values())if(!lane.ws)open(lane); }catch{fail();} }
function close(notify){ if(closed)return;closed=true; for(const lane of [...lanes.values()])end(lane,false);used.clear(); if(notify)drop(); port?.close(); }
function start(next){ init=true;port=next; port.onmessage=msg=>{ const data=msg.data; if(data instanceof ArrayBuffer){ if(!started){ try{check(data);}catch{fail();return;} started=true;create(data); }else push(data); }else if(data&&data.t==='close')close(true); }; port.start();state('connecting'); }
addEventListener('message',e=>{ if(init||e.source!==parent||e.data===null||typeof e.data!=='object')return; const keys=Object.keys(e.data).sort(); if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||e.data.t!=='tproxy-init'||e.data.v!==1||e.ports.length!==1)return; let src;try{src=new URL(e.origin);}catch{return;} if(src.protocol!=='http:'||src.hostname!=='127.0.0.1'||!src.port||src.origin!==e.origin)return; start(e.ports[0]); }); const android=globalThis.TelegramWebProxy;
if(!init&&aNonce&&android&&typeof android.postMessage==='function'){ const aPort={onmessage:null,start(){},close(){android.onmessage=null;},postMessage(v){ if(v instanceof ArrayBuffer){for(const frame of split(v))android.postMessage(frame);} else android.postMessage(JSON.stringify(v)); }}; android.onmessage=e=>{ let data=e.data;if(typeof data==='string'){try{data=JSON.parse(data);}catch{return;}} aPort.onmessage?.({data}); }; start(aPort);android.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:aNonce})); } addEventListener('pagehide',()=>close(true),{once:true}); })();
</script>`.replaceAll('__NONCE__', nonce).replace('__ORIGIN__', JSON.stringify(`https://${host}`))
    .replace('__BOOTSTRAP__', JSON.stringify(String(boot)));
  const csp = [ "default-src 'none'", "base-uri 'none'", "child-src 'none'", `connect-src 'self' wss://${host}`, "font-src 'none'", "form-action 'none'", 'frame-ancestors http://127.0.0.1:*', "frame-src 'none'", "img-src 'none'", "manifest-src 'none'", "media-src 'none'", "object-src 'none'", `script-src 'nonce-${nonce}'`, "style-src 'none'", "worker-src 'none'", 'sandbox allow-same-origin allow-scripts', ].join('; '); return { body, csp }; }

// ======================== 一键导入与部署说明页面 ========================
function mkDashboard(host, secret, botName = 'eoops_bot') {
  const proxyUrl = `tg://webproxy?server=${host}&secret=${secret}`;
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Telegram 官方代理服务中心</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background-color: #f0f2f5;
    color: #303133;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 24px 16px;
  }
  .container {
    width: 100%;
    max-width: 540px;
    background-color: #ffffff;
    border: 1px solid #dcdfe6;
    border-radius: 6px;
    box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.05);
    overflow: hidden;
  }
  .header {
    padding: 24px 28px 16px;
    border-bottom: 1px solid #ebeef5;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .title { font-size: 18px; font-weight: 600; color: #303133; }
  .badge-success {
    background-color: #f0f9eb;
    color: #67c23a;
    border: 1px solid #e1f3d8;
    font-size: 12px;
    padding: 4px 8px;
    border-radius: 4px;
    font-weight: 500;
  }
  .content { padding: 24px 28px; }
  .card-section { margin-bottom: 22px; }
  .section-label { font-size: 13px; color: #909399; margin-bottom: 8px; font-weight: 500; }
  .proxy-card { background: #fdfdfd; border: 1px solid #ebeef5; border-radius: 4px; padding: 14px 16px; }
  .proxy-url-text {
    font-family: Consolas, Monaco, monospace;
    font-size: 13px;
    color: #409eff;
    background: #ecf5ff;
    padding: 8px 10px;
    border-radius: 4px;
    border: 1px solid #d9ecff;
    word-break: break-all;
    user-select: all;
    margin-bottom: 10px;
  }
  .proxy-details { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px; margin-bottom: 12px; }
  .detail-item { display: flex; flex-direction: column; }
  .detail-label { color: #909399; font-size: 11px; margin-bottom: 2px; }
  .detail-value { font-family: Consolas, Monaco, monospace; color: #303133; font-weight: 500; word-break: break-all; }
  .btn-group { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
  .btn {
    padding: 8px 16px;
    font-size: 13px;
    border-radius: 4px;
    cursor: pointer;
    border: 1px solid transparent;
    transition: all 0.2s;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-weight: 500;
  }
  .btn-primary { background-color: #409eff; color: #ffffff; border-color: #409eff; }
  .btn-primary:hover { background-color: #66b1ff; border-color: #66b1ff; }
  .btn-default { background-color: #ffffff; color: #606266; border-color: #dcdfe6; }
  .btn-default:hover { color: #409eff; border-color: #c6e2ff; background-color: #ecf5ff; }
  .btn-success { background-color: #67c23a; color: #ffffff; border-color: #67c23a; }
  .btn-success:hover { background-color: #85ce61; border-color: #85ce61; }
  .header-right { display: flex; align-items: center; gap: 8px; }
  .header-right form { margin: 0; }
  .btn-sm { padding: 5px 10px; font-size: 12px; flex-shrink: 0; }
  .gen-row { margin-bottom: 12px; }
  .gen-line { display: flex; gap: 8px; align-items: stretch; }
  .gen-val {
    flex: 1; min-width: 0; font-family: Consolas, Monaco, monospace; font-size: 13px; color: #409eff;
    background: #ecf5ff; border: 1px solid #d9ecff; border-radius: 4px; padding: 7px 10px;
    word-break: break-all; cursor: pointer; user-select: all;
  }
  .gen-val:hover { background: #d9ecff; }
  .gen-cmd { font-family: Consolas, Monaco, monospace; font-size: 11px; color: #909399; margin-top: 3px; word-break: break-all; }
  .steps { font-size: 13px; color: #606266; line-height: 1.7; padding-left: 18px; margin-bottom: 12px; }
  .group-box { background: #fdfdfd; border: 1px solid #ebeef5; border-radius: 4px; padding: 16px; }
  .group-text { font-size: 13px; color: #606266; line-height: 1.5; margin-bottom: 12px; }
  .toast {
    position: fixed; top: 24px; left: 50%; transform: translateX(-50%);
    background: #303133; color: #ffffff; padding: 8px 16px; border-radius: 4px;
    font-size: 13px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); display: none; z-index: 1000;
  }
  .toast.show { display: block; animation: fadeInOut 2s ease forwards; }
  @keyframes fadeInOut {
    0% { opacity: 0; transform: translate(-50%, -10px); }
    15% { opacity: 1; transform: translate(-50%, 0); }
    85% { opacity: 1; transform: translate(-50%, 0); }
    100% { opacity: 0; transform: translate(-50%, -10px); }
  }
</style>
</head>
<body>

<div id="toast" class="toast">复制成功</div>

<div class="container">
  <div class="header">
    <div class="title">Telegram 代理服务中心</div>
    <div class="header-right">
      <div class="badge-success">● 服务就绪 (Online)</div>
      <form method="POST" action="/logout"><button type="submit" class="btn btn-default btn-sm">退出登录</button></form>
    </div>
  </div>
  
  <div class="content">
    <div class="card-section">
      <div class="section-label">1. 推荐方式：Telegram WEB 代理 (官方全新通道，抗封锁)</div>
      <div class="proxy-card">
        <div class="proxy-url-text">${proxyUrl}</div>
        <div class="proxy-details">
          <div class="detail-item">
            <span class="detail-label">服务器域名</span>
            <span class="detail-value">${host}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">传输协议</span>
            <span class="detail-value">HTTPS / WebSocket</span>
          </div>
          <div class="detail-item" style="grid-column: span 2;">
            <span class="detail-label">专属密钥</span>
            <span class="detail-value">${secret}</span>
          </div>
        </div>
        <div class="btn-group">
          <a href="${proxyUrl}" class="btn btn-primary">一键导入连接</a>
          <button class="btn btn-default" onclick="copyText('${proxyUrl}', 'WEB 完整链接已复制')">复制完整连接</button>
          <button class="btn btn-default" onclick="copyText('https://t.me/webproxy?server=${host}&secret=${secret}', 't.me 分享链接已复制')">复制 t.me 分享链接</button>
        </div>
      </div>
    </div>

    <div class="card-section">
      <div class="section-label">2. 部署配置说明</div>
      <div class="group-box">
        <div class="group-text">分享给用户的链接格式（把域名和密钥换成你自己的，点击可复制）：</div>
        <div class="proxy-url-text" style="cursor: pointer;" title="点击复制" onclick="copyText(this.textContent, '链接格式已复制')">https://t.me/webproxy?server=你的域名&amp;secret=你的secret</div>
        <ol class="steps">
          <li>在 Cloudflare 控制台打开 Worker →「设置」→「变量和机密」。</li>
          <li>添加下面两个变量，类型选 <b>Secret</b>（加密），保存并重新部署。</li>
          <li>用 <b>SECRET</b> 和你的域名拼出上面的链接，发给用户即可。</li>
        </ol>
        <div class="gen-row">
          <div class="detail-label">SECRET（32 位 hex，点击数值复制）</div>
          <div class="gen-line">
            <code class="gen-val" id="gen-secret" title="点击复制" onclick="copyText(this.textContent, 'SECRET 已复制')"></code>
            <button class="btn btn-default btn-sm" onclick="regen('secret')">重新生成</button>
          </div>
          <div class="gen-cmd">等价命令：openssl rand -hex 16</div>
        </div>
        <div class="gen-row">
          <div class="detail-label">BOOT（48 位随机串，点击数值复制）</div>
          <div class="gen-line">
            <code class="gen-val" id="gen-boot" title="点击复制" onclick="copyText(this.textContent, 'BOOT 已复制')"></code>
            <button class="btn btn-default btn-sm" onclick="regen('boot')">重新生成</button>
          </div>
          <div class="gen-cmd">等价命令：openssl rand -hex 24</div>
        </div>
        <div class="btn-group" style="margin-top: 0;">
          <button class="btn btn-primary" onclick="copyEnv()">复制 SECRET=… 和 BOOT=…</button>
          <button class="btn btn-default" onclick="regen('secret'); regen('boot')">全部重新生成</button>
        </div>
        <div class="group-text" style="margin: 10px 0 0; font-size: 12px; color: #909399;">随机值在你的浏览器本地生成，不会上传。BOOT 只能填进 Worker 变量，不要发给任何人；更换 SECRET 后，旧的代理链接会失效。</div>
      </div>
    </div>

    <div class="card-section" style="margin-bottom: 0;">
      <div class="section-label">3. 交流机器人</div>
      <div class="group-box">
        <div class="group-text">欢迎联系TG私聊机器人 <b>@${botName}</b>，获取实时节点状态、测速通知与最新专属配置！</div>
        <div class="btn-group" style="margin-top: 0;">
          <a href="https://t.me/${botName}" target="_blank" class="btn btn-success">立即联系TG机器人 (@${botName})</a>
          <button class="btn btn-default" onclick="copyText('https://t.me/${botName}', '群组链接已复制')">复制机器人链接</button>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
function copyText(text, msg) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() { showToast(msg || '复制成功'); }).catch(function() { fallbackCopy(text, msg); });
  } else { fallbackCopy(text, msg); }
}
function fallbackCopy(text, msg) {
  var input = document.createElement('input');
  input.setAttribute('value', text);
  document.body.appendChild(input);
  input.select();
  document.execCommand('copy');
  document.body.removeChild(input);
  showToast(msg || '复制成功');
}
function showToast(msg) {
  var toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(function() { toast.classList.remove('show'); }, 2000);
}
function randHex(n) {
  var b = new Uint8Array(n); crypto.getRandomValues(b);
  var s = '';
  for (var i = 0; i < n; i++) s += ('0' + b[i].toString(16)).slice(-2);
  return s;
}
function regen(kind) {
  var el = document.getElementById('gen-' + kind);
  if (el) el.textContent = kind === 'secret' ? randHex(16) : randHex(24);
}
function copyEnv() {
  var nl = String.fromCharCode(10);
  copyText('SECRET=' + document.getElementById('gen-secret').textContent + nl + 'BOOT=' + document.getElementById('gen-boot').textContent, '环境变量已复制');
}
regen('secret'); regen('boot');
</script>
</body>
</html>`;
}

// ======================== 看板登录与访问控制 ========================
const AUTH_COOKIE = '__Host-tgp_auth', AUTH_TTL = 12 * 60 * 60 * 1000, MAX_FAILS = 5, LOCK_MS = 10 * 60 * 1000;
const fails = new Map(); // ip -> { n, until }（isolate 内存级限速）
// 会话密钥同时绑定 BOOT 与登录密码：任一变更，已签发的登录态立即失效
const authKey = cfg => `${cfg.boot}\nadmin\n${cfg.admin}`;
function cookieOf(req, name) { for (const part of (req.headers.get('Cookie') || '').split(';')) { const i = part.indexOf('='); if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim(); } return ''; }
const authed = async (req, cfg) => !!cfg.admin && await verify(cookieOf(req, AUTH_COOKIE), authKey(cfg), 'admin');
async function pwOk(input, want) { const a = await sha(txt.encode(input)), b = await sha(txt.encode(want)); let diff = 0; for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]; return diff === 0; }
const htmlRes = (body, status = 200, extra = {}) => new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "frame-ancestors 'none'", ...extra } });
const goHome = cookie => new Response(null, { status: 303, headers: { Location: '/', 'Cache-Control': 'no-store', 'Set-Cookie': cookie } });

function mkLogin(msg = '', locked = false) {
  const body = locked
    ? `<div class="tip">看板尚未配置访问密码。<br>请在 Worker「设置 → 变量和机密」中添加 <b>ADMIN_PASSWORD</b>（类型选 Secret，至少 8 位），保存并重新部署后刷新本页。<br><span class="cmd">生成命令：openssl rand -base64 18</span></div>`
    : `<form method="POST" action="/login" autocomplete="off">
      <input type="password" name="password" placeholder="请输入访问密码" maxlength="256" required autofocus autocomplete="current-password">
      ${msg ? `<div class="err">${msg}</div>` : ''}
      <button type="submit">登 录</button>
    </form>`;
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>登录 - Telegram 代理服务中心</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #f0f2f5; color: #303133; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 24px 16px; }
  .box { width: 100%; max-width: 380px; background: #fff; border: 1px solid #dcdfe6; border-radius: 6px; box-shadow: 0 2px 12px rgba(0,0,0,.05); padding: 28px; }
  h1 { font-size: 18px; font-weight: 600; margin-bottom: 4px; }
  .sub { font-size: 13px; color: #909399; margin-bottom: 20px; }
  input { width: 100%; padding: 10px 12px; font-size: 14px; border: 1px solid #dcdfe6; border-radius: 4px; outline: none; }
  input:focus { border-color: #409eff; }
  button { width: 100%; margin-top: 14px; padding: 10px; font-size: 14px; font-weight: 500; color: #fff; background: #409eff; border: 1px solid #409eff; border-radius: 4px; cursor: pointer; }
  button:hover { background: #66b1ff; border-color: #66b1ff; }
  .err { margin-top: 10px; font-size: 13px; color: #f56c6c; }
  .tip { font-size: 13px; color: #606266; line-height: 1.8; background: #fdf6ec; border: 1px solid #faecd8; border-radius: 4px; padding: 12px; }
  .cmd { font-family: Consolas, Monaco, monospace; font-size: 12px; color: #909399; }
</style>
</head>
<body>
<div class="box">
  <h1>Telegram 代理服务中心</h1>
  <div class="sub">请先登录后查看代理链接与部署配置</div>
  ${body}
</div>
</body>
</html>`;
}

// ======================== 核心路由 ========================
const route = async (req, env) => {
  const url = new URL(req.url), { pathname: path, origin } = url, { method, headers } = req; let cfg;
  try { cfg = mkCfg(env); } catch { return ['/', '/health', '/api/v1/session', '/api/v1/ws'].includes(path) ? reply(null, 500) : reply(); }

  // 登录 / 退出
  if (path === '/login') {
    if (method !== 'POST') return goHome('');
    if (!cfg.admin) return htmlRes(mkLogin('', true), 503);
    const o = headers.get('Origin');
    if (o) { // 兼容 CNAME / SaaS 优选：Origin 与 Worker 看到的域名不一致时，再对比 Host 与 Sec-Fetch-Site
      let ok = o === origin; try { ok = ok || new URL(o).host === headers.get('Host'); } catch {}
      if (!ok && headers.get('Sec-Fetch-Site') !== 'same-origin') return htmlRes(mkLogin('请求来源校验失败，请直接在本页面输入密码登录'), 403);
    }
    const ip = headers.get('CF-Connecting-IP') || 'unknown', now = Date.now(), rec = fails.get(ip);
    if (rec && rec.until > now) return htmlRes(mkLogin(`尝试次数过多，请 ${Math.ceil((rec.until - now) / 60000)} 分钟后再试`), 429);
    let pw = ''; try { pw = String((await req.formData()).get('password') ?? '').trim(); } catch {}
    if (!pw || pw.length > 256 || !(await pwOk(pw, cfg.admin))) {
      if (fails.size > 2000) for (const [k, v] of fails) if (v.until <= now) fails.delete(k);
      const n = (rec?.n ?? 0) + 1; fails.set(ip, n >= MAX_FAILS ? { n: 0, until: now + LOCK_MS } : { n, until: 0 });
      return htmlRes(mkLogin('密码错误'), 401);
    }
    fails.delete(ip);
    const tok = await mkToken(authKey(cfg), 'admin', now + AUTH_TTL, rand(12));
    return goHome(`${AUTH_COOKIE}=${tok}; Path=/; Max-Age=${AUTH_TTL / 1000}; HttpOnly; Secure; SameSite=Strict`);
  }
  if (path === '/logout') {
    if (method !== 'POST') return goHome('');
    return goHome(`${AUTH_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
  }

  // 2. 根路径：区分 Telegram Client 桥接 vs 普通浏览器访问
  if (path === '/' && (method === 'GET' || method === 'HEAD')) {
    let host = null;
    if (method === 'GET') {
      try { host = await bridge(url, cfg.secret); } catch {}
    }
    // 如果是 Telegram 客户端带来的带有签名的桥接请求，返回内置代理隧道脚本
    if (host) {
      const boot = await mkBoot(cfg.boot);
      const page = mkPage(host, boot);
      return new Response(page.body, {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': page.csp,
          'Cache-Control': 'no-store',
          'Referrer-Policy': 'no-referrer',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }
    // 普通浏览器访问：未登录只给登录页，登录后才下发含密钥的看板
    if (method === 'HEAD') return new Response(null, { status: 200 });
    if (!cfg.admin) return htmlRes(mkLogin('', true), 503);
    if (!(await authed(req, cfg))) return htmlRes(mkLogin());
    return htmlRes(mkDashboard(url.hostname, cfg.secret, env.TG_BOT || 'eoops_bot'));
  }

  if (path === '/health') { return new Response('{"ok":true}', { headers: { 'content-type': 'application/json; charset=utf-8' }, }); }

  // 3. 会话创建与销毁
  if (path === '/api/v1/session') {
    const auth = bearer(headers.get('Authorization'));
    if (method === 'DELETE') {
      if (!auth || !(await verify(auth, cfg.boot, 'session'))) { return reply(); }
      let lease = leases.get(auth);
      if (!lease) leases.set(auth, lease = mkLease(auth));
      lease.deleted = true;
      return reply(null, 204);
    }
    if (method !== 'POST' || !auth || !binary(req)) { return reply(); }
    if (!(await authBoot(auth, cfg.boot))) { return reply(); }
    try {
      const body = new Uint8Array(await req.arrayBuffer());
      hello(body);
      const token = await mkSess(cfg.boot);
      return new Response(enc(0x11, 0), {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Cache-Control': 'no-store',
          'X-Session-Token': token,
          'X-Carrier-Mode': 'websocket-lanes',
        },
      });
    } catch { return reply(); }
  }

  // 4. WebSocket 数据管道
  if (path !== '/api/v1/ws' || method !== 'GET' || headers.get('Upgrade')?.toLowerCase() !== 'websocket' || (headers.has('Origin') && headers.get('Origin') !== origin)) { return reply(); }
  const offers = protos(req); const proto = offers.length === 1 ? offers[0] : null;
  const parts = proto?.split('.') ?? [], [kind, token = '', id] = parts, sid = Number(id);
  if (parts.length !== 3 || kind !== 'tproxy-lane-v1' || !/^[1-9][0-9]{0,7}$/.test(id) || sid > 0xffffff || !(await verify(token, cfg.boot, 'session'))) { return reply(); } const now = Date.now();
  for (const [key, v] of leases) if (v.expires <= now && !v.active.size) leases.delete(key); let lease = leases.get(token);
  if (!lease) { if (leases.size >= 4096) return reply(null, 503); leases.set(token, lease = mkLease(token)); }
  if (lease.deleted || lease.used.has(sid) || lease.active.size >= 128 || lease.used.size >= 4096) { return reply(null, 409); }
  lease.used.add(sid); lease.active.add(sid);

  const sess = mkSession({
    secret: cfg.key,
    sid,
    lease,
    onClose: () => {
      lease.active.delete(sid);
    },
  });
  const { 0: client, 1: server } = new WebSocketPair();
  try { sess.attach(server); } catch { sess.close(); return reply(null, 409); }
  return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Protocol': proto, 'Sec-WebSocket-Extensions': '', }, });
};
