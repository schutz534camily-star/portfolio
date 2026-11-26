// Backend do portfólio (Cloudflare Worker): login, conteúdo (D1) e arquivos (KV).
// Toda rota administrativa valida a sessão AQUI; esconder botão no navegador não é segurança.
import ADMIN_UI from './admin-ui.txt';

const CHUNK = 20 * 1024 * 1024;          // pedaço máximo guardado por chave do KV (limite do KV: 25 MiB)
const QUOTA = 950 * 1024 * 1024;         // margem abaixo do 1 GB grátis do KV (arquivos antigos)
const R2_QUOTA = 9 * 1024 * 1024 * 1024; // margem abaixo dos 10 GB grátis do R2 (arquivos novos)
const R2_MAX_FILE = 2 * 1024 * 1024 * 1024;
const R2_HARD = 50 * 1024 * 1024 * 1024;  // teto absoluto, mesmo com confirmação
const R2_PRICE_GB = 0.015;                 // US$ por GB-mês acima do grátis
const SESSION_SECS = 60 * 60 * 24 * 30;  // login dura 30 dias
const PBKDF2_ITER = 100000;              // máximo permitido pelo Workers

const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const now = () => Math.floor(Date.now() / 1000);

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
const fail = (status, msg, extra = {}) => json({ error: msg, ...extra }, status);

/* ---------- banco ---------- */
let schemaReady = false;
async function schema(db) {
  if (schemaReady) return;
  await db.batch([
    db.prepare('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS attempts (ip TEXT NOT NULL, ts INTEGER NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS docs (key TEXT PRIMARY KEY, value TEXT NOT NULL, rev INTEGER NOT NULL, updated INTEGER NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS parts (owner TEXT NOT NULL, ver TEXT NOT NULL, idx INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY (owner, ver, idx))'),
    db.prepare('CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL, ts INTEGER NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS media (id TEXT PRIMARY KEY, name TEXT, type TEXT NOT NULL, size INTEGER NOT NULL, chunks INTEGER NOT NULL, done INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL)'),
  ]);
  try { await db.prepare("ALTER TABLE media ADD COLUMN store TEXT NOT NULL DEFAULT 'kv'").run(); } catch (e) { /* coluna já existe */ }
  schemaReady = true;
}

/* ---------- senha e sessão ---------- */
async function hashPassword(password, saltBytes) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: PBKDF2_ITER }, key, 256);
  return b64u(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const sha256 = async s => b64u(await crypto.subtle.digest('SHA-256', enc.encode(s)));

function getCookie(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? m[1] : null;
}
function sessionCookie(token, maxAge) {
  return `sid=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
async function startSession(env, userId) {
  const token = b64u(rand(32));
  const t = now();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires, created) VALUES (?,?,?,?)').bind(await sha256(token), userId, t + SESSION_SECS, t).run();
  await env.DB.prepare('DELETE FROM sessions WHERE expires < ?').bind(t).run();
  return sessionCookie(token, SESSION_SECS);
}
async function currentUser(req, env) {
  const token = getCookie(req, 'sid');
  if (!token || token.length > 80) return null;
  const th = await sha256(token);
  const row = await env.DB.prepare('SELECT s.expires, u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?').bind(th).first();
  if (!row || row.expires < now()) return null;
  if (row.expires - now() < SESSION_SECS / 2) { // renova enquanto ela continua usando
    await env.DB.prepare('UPDATE sessions SET expires = ? WHERE token_hash = ?').bind(now() + SESSION_SECS, th).run();
  }
  return { id: row.id, username: row.username, th };
}

/* ---------- proteção ---------- */
function sameOrigin(req) {
  const o = req.headers.get('origin');
  if (!o) return true;
  try { return new URL(o).host === new URL(req.url).host; } catch { return false; }
}
async function tooManyAttempts(env, ip) {
  const since = now() - 15 * 60;
  await env.DB.prepare('DELETE FROM attempts WHERE ts < ?').bind(since).run();
  const r = await env.DB.prepare('SELECT COUNT(*) n FROM attempts WHERE ip = ?').bind(ip).first();
  return r.n >= 5;
}
const noteFail = (env, ip) => env.DB.prepare('INSERT INTO attempts (ip, ts) VALUES (?,?)').bind(ip, now()).run();

/* ---------- validação do conteúdo ---------- */
const SRC_OK = /^(\/media\/[a-f0-9]{16}|(videos|images)\/[A-Za-z0-9._\-\/]{1,120})$/;
const RATIO_OK = /^\d{1,2}\/\d{1,2}$/;
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

const okSrc = v => typeof v === 'string' && SRC_OK.test(v) && !v.includes('..');
function cleanWork(w) {
  if (!w || typeof w !== 'object') throw new Error('trabalho inválido');
  const t = w.t === 'video' ? 'video' : w.t === 'carousel' ? 'carousel' : 'design';
  const out = { t, title: str(w.title, 120), r: RATIO_OK.test(w.r) ? w.r : '16/9' };
  if (typeof w.g === 'string' && /^[a-z0-9]{1,12}$/.test(w.g)) out.g = w.g;
  if (w.sz === 1 || w.sz === 2 || w.sz === 3 || w.sz === 4) out.sz = w.sz;
  if (t === 'carousel') {
    if (!Array.isArray(w.images)) throw new Error('carrossel inválido');
    if (!w.images.every(okSrc)) throw new Error('arquivo inválido no carrossel');
    out.images = w.images;
    if (Array.isArray(w.kinds) && w.kinds.length === w.images.length && w.kinds.every(k => k === 'i' || k === 'v') && w.kinds.includes('v')) out.kinds = w.kinds;
    return out;
  }
  if (w.src) { if (!okSrc(w.src)) throw new Error('arquivo inválido'); out.src = w.src; }
  if (w.src && w.fit === 'contain' && t !== 'video') out.fit = 'contain';
  if (w.poster && t === 'video' && w.src) { if (!okSrc(w.poster)) throw new Error('capa inválida'); out.poster = w.poster; const pt = Number(w.posterT); if (Number.isFinite(pt) && pt > 0 && pt < 86400) out.posterT = Math.round(pt * 100) / 100; }
  if (w.canva) {
    let u; try { u = new URL(w.canva); } catch { throw new Error('link do Canva inválido'); }
    if (u.protocol !== 'https:') throw new Error('link do Canva inválido');
    out.canva = u.href;
  }
  return out;
}
function cleanItem(c, nested) {
  if (!c || typeof c !== 'object') throw new Error('item inválido');
  const id = str(c.id, 60);
  if (!/^[a-z0-9-]{1,60}$/.test(id)) throw new Error('identificador inválido');
  const out = { id, name: str(c.name, 120), mono: str(c.mono, 4), kind: str(c.kind, 120), desc: str(c.desc, 600) };
  const ig = str(c.ig, 40);
  if (ig) { if (!/^[A-Za-z0-9._]{1,40}$/.test(ig)) throw new Error('Instagram inválido'); out.ig = ig; }
  if (!nested && c.cover) { if (!SRC_OK.test(c.cover) || c.cover.includes('..')) throw new Error('capa inválida'); out.cover = c.cover; }
  const sv = str(c.secV, 60), sd = str(c.secD, 60); if (sv) out.secV = sv; if (sd) out.secD = sd;
  if (Array.isArray(c.layout)) {
    const seenL = new Set(), rows = [];
    for (const r of c.layout) { if (!Array.isArray(r)) continue; const row = r.filter(k => typeof k === 'string' && /^[a-z0-9]{1,12}$/.test(k) && !seenL.has(k) && seenL.add(k)).slice(0, 2); if (row.length) rows.push(row); }
    if (rows.length) out.layout = rows;
  }
  if (Array.isArray(c.groups)) {
    const seen = new Set();
    out.groups = c.groups.map(g => {
      const id = g && typeof g.id === 'string' ? g.id : '';
      if (!/^[a-z0-9]{1,12}$/.test(id) || seen.has(id)) throw new Error('categoria inválida'); seen.add(id);
      return { id, name: str(g.name, 60) };
    });
  }
  if (Array.isArray(c.works)) { out.works = c.works.map(cleanWork); }
  if (!nested && Array.isArray(c.children)) { out.children = c.children.map(k => cleanItem(k, true)); }
  return out;
}
function cleanContent(arr) {
  if (!Array.isArray(arr)) throw new Error('conteúdo inválido');
  const clients = arr.map(c => cleanItem(c, false));
  const ids = new Set();
  for (const c of clients) for (const x of [c, ...(c.children || [])]) { if (ids.has(x.id)) throw new Error('identificador repetido'); ids.add(x.id); }
  return clients;
}
const mediaIds = clients => {
  const s = new Set();
  const add = v => { const m = v && /^\/media\/([a-f0-9]{16})$/.exec(v); if (m) s.add(m[1]); };
  const addW = w => { add(w.src); add(w.poster); (w.images || []).forEach(add); };
  for (const c of clients) { add(c.cover); (c.works || []).forEach(addW); for (const k of c.children || []) (k.works || []).forEach(addW); }
  return s;
};

/* ---------- rodapé ---------- */
const ICONS = new Set(['user', 'instagram', 'whatsapp', 'mail', 'phone', 'link']);
function cleanFooter(arr) {
  if (!Array.isArray(arr)) throw new Error('rodapé inválido');
  return arr.map(i => {
    if (!i || typeof i !== 'object') throw new Error('item do rodapé inválido');
    const out = { icon: ICONS.has(i.icon) ? i.icon : 'link', text: str(i.text, 80) };
    const href = str(i.href, 500);
    if (href) {
      let u; try { u = new URL(href); } catch { throw new Error('Link inválido: ' + href); }
      if (!['https:', 'http:', 'mailto:', 'tel:'].includes(u.protocol)) throw new Error('O link precisa começar com https://, mailto: ou tel:');
      out.href = href;
    }
    return out;
  });
}

/* ---------- ajustes do site ---------- */
const DEFAULT_ABOUT = { label: 'Sobre mim', title: 'Sobre mim', blocks: [], photo: '', ratio: '4/5', shape: 'soft', size: 34, h: 'left', v: 'top', width: 100, align: 'center', bg: '#6F0085', alpha: 55 };
const DEFAULT_SETTINGS = { bg: '', heroA: 'Ideias em', heroB: 'movimento', heroC: '.', tabTitle: 'Portfólio de Design e Vídeo', theme: {}, about: DEFAULT_ABOUT };
/* aparência: só chaves conhecidas; cores em #RRGGBB; fontes "g:Nome|400;700" (Google) ou "s:Nome" (do sistema) */
const THEME_COLORS = new Set(['c_veil', 'c_cardbg', 'c_line', 'c_ink', 'c_muted', 'c_accent', 'c_detail', 'c_hero', 'c_mov', 'c_dot', 'c_sec', 'c_card', 'c_kind', 'c_lead', 'c_ig', 'c_chip', 'c_sub', 'c_blk', 'c_cap', 'c_nav', 'c_foot', 'c_f1', 'c_f2', 'c_g1', 'c_g2', 'c_abbtn', 'c_abt', 'c_abs', 'c_abx']);
const THEME_FONTS = new Set(['f_body', 'f_display', 'f_hero', 'f_sec', 'f_card', 'f_kind', 'f_lead', 'f_ig', 'f_chip', 'f_sub', 'f_blk', 'f_cap', 'f_nav', 'f_foot', 'f_abbtn', 'f_abt', 'f_abs', 'f_abx']);
const THEME_SIZES = new Set(['z_hero', 'z_sec', 'z_pg', 'z_card', 'z_kind', 'z_lead', 'z_blk', 'z_cap', 'z_sub', 'z_nav', 'z_ig', 'z_abbtn', 'z_abt', 'z_abs', 'z_abx']);
const FONT_OK = /^(g:[A-Za-z0-9 ]{2,40}\|\d{3}(;\d{3}){0,5}|s:[A-Za-z ]{2,30})$/;
function cleanTheme(t) {
  const out = {};
  if (!t || typeof t !== 'object') return out;
  for (const [k, v] of Object.entries(t)) {
    if (typeof v !== 'string' || !v) continue;
    if (THEME_COLORS.has(k)) { if (!/^#[0-9a-fA-F]{6}$/.test(v)) throw new Error('cor inválida'); out[k] = v.toUpperCase(); }
    else if (THEME_SIZES.has(k)) { if (!(/^\d{2,3}$/.test(v) && +v >= 50 && +v <= 300) && !(k === 'z_abbtn' && v === '=sec')) throw new Error('tamanho inválido'); out[k] = v; }
    else if (THEME_FONTS.has(k)) { if (!FONT_OK.test(v)) throw new Error('fonte inválida'); out[k] = v; }
  }
  return out;
}
const pick = (v, list, def) => (list.includes(v) ? v : def);
const num = (v, lo, hi, def) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : def; };
function cleanAbout(a) {
  const d = DEFAULT_ABOUT;
  if (!a || typeof a !== 'object') return { ...d };
  const photo = typeof a.photo === 'string' ? a.photo : '';
  if (photo && !okSrc(photo)) throw new Error('foto do Sobre mim inválida');
  const blocks = Array.isArray(a.blocks) ? a.blocks : [];
  return {
    label: str(a.label, 30) || d.label, title: str(a.title, 120),
    blocks: blocks.map(b => ({ title: str(b && b.title, 120), text: str(b && b.text, 4000) })).filter(b => b.title || b.text),
    photo, ratio: RATIO_OK.test(a.ratio) ? a.ratio : d.ratio, shape: pick(a.shape, ['soft', 'round', 'square'], d.shape),
    size: num(a.size, 15, 60, d.size), h: pick(a.h, ['left', 'center', 'right'], d.h), v: pick(a.v, ['top', 'middle', 'bottom'], d.v),
    width: num(a.width, 40, 100, d.width), align: pick(a.align, ['left', 'center', 'right'], d.align),
    bg: /^#[0-9a-fA-F]{6}$/.test(a.bg) ? a.bg.toUpperCase() : d.bg, alpha: num(a.alpha, 15, 95, d.alpha)
  };
}
function cleanSettings(o) {
  if (!o || typeof o !== 'object') throw new Error('ajustes inválidos');
  const bg = typeof o.bg === 'string' ? o.bg : '';
  if (bg && !okSrc(bg)) throw new Error('imagem de fundo inválida');
  return { bg, heroA: str(o.heroA, 60), heroB: str(o.heroB, 40), heroC: str(o.heroC, 10), tabTitle: str(o.tabTitle, 80), theme: cleanTheme(o.theme), about: cleanAbout(o.about) };
}

/* ---------- conteúdo ---------- */
async function loadSeed(env) {
  return (await env.ASSETS.fetch(new Request('https://assets.local/seed.json'))).json();
}
const videoCount = c => [...(c.works || []), ...(c.children || []).flatMap(k => k.works || [])].filter(w => w.t === 'video').length;
/* ---------- textos grandes: o conteúdo do site é guardado em pedaços quando passa do limite de 2 MB de uma linha do banco ---------- */
const PART = 400000;
async function readBig(env, v) {
  const m = /^@@parts:([a-z0-9]+):([a-z0-9]+):(\d+)$/.exec(v);
  if (!m) return v;
  const r = await env.DB.prepare('SELECT value FROM parts WHERE owner = ? AND ver = ? ORDER BY idx').bind(m[1], m[2]).all();
  if (r.results.length !== Number(m[3])) throw new Error('conteúdo incompleto no banco');
  return r.results.map(x => x.value).join('');
}
function planBig(env, owner, ver, str) {
  if (str.length <= PART) return { value: str, stmts: [] };
  const n = Math.ceil(str.length / PART), stmts = [];
  for (let i = 0; i < n; i++) stmts.push(env.DB.prepare('INSERT INTO parts (owner, ver, idx, value) VALUES (?,?,?,?)').bind(owner, ver, i, str.slice(i * PART, (i + 1) * PART)));
  return { value: `@@parts:${owner}:${ver}:${n}`, stmts };
}
const sweepParts = env => env.DB.prepare("DELETE FROM parts WHERE NOT EXISTS (SELECT 1 FROM docs d WHERE d.value LIKE '@@parts:' || parts.owner || ':' || parts.ver || ':%') AND NOT EXISTS (SELECT 1 FROM history h WHERE h.value LIKE '@@parts:' || parts.owner || ':' || parts.ver || ':%')").run();

async function loadContent(env) {
  let row = await env.DB.prepare("SELECT value, rev FROM docs WHERE key = 'content'").first();
  const f = await env.DB.prepare("SELECT value FROM docs WHERE key = 'footer'").first();
  const st = await env.DB.prepare("SELECT value FROM docs WHERE key = 'settings'").first();
  let seed = null;
  const getSeed = async () => seed || (seed = await loadSeed(env));
  if (!row) {
    const sd = await getSeed();
    const clients = cleanContent(sd.clients);
    await env.DB.prepare("INSERT OR IGNORE INTO docs (key, value, rev, updated) VALUES ('content', ?, 1, ?)").bind(JSON.stringify(clients), now()).run();
    await env.DB.prepare("INSERT OR IGNORE INTO docs (key, value, rev, updated) VALUES ('migr_order', '1', 1, ?)").bind(now()).run();
    row = await env.DB.prepare("SELECT value, rev FROM docs WHERE key = 'content'").first();
  } else if (!(await env.DB.prepare("SELECT 1 x FROM docs WHERE key = 'migr_order'").first())) {
    // uma vez só: a ordem antes era "mais vídeos primeiro"; agora a ordem é a que ela escolher
    const cur = JSON.parse(row.value).map((c, i) => ({ c, i })).sort((a, b) => videoCount(b.c) - videoCount(a.c) || a.i - b.i).map(x => x.c);
    await env.DB.prepare("UPDATE docs SET value = ?, rev = rev + 1, updated = ? WHERE key = 'content' AND rev = ?").bind(JSON.stringify(cur), now(), row.rev).run();
    await env.DB.prepare("INSERT OR IGNORE INTO docs (key, value, rev, updated) VALUES ('migr_order', '1', 1, ?)").bind(now()).run();
    row = await env.DB.prepare("SELECT value, rev FROM docs WHERE key = 'content'").first();
  }
  const footer = f ? JSON.parse(f.value) : cleanFooter((await getSeed()).footer);
  const settings = { ...DEFAULT_SETTINGS, ...(st ? JSON.parse(st.value) : ((await getSeed()).settings || {})) };
  return { clients: JSON.parse(await readBig(env, row.value)), raw: row.value, rev: row.rev, footer, settings };
}

async function deleteMedia(env, id) {
  const row = await env.DB.prepare('SELECT chunks, store FROM media WHERE id = ?').bind(id).first();
  if (!row) return;
  const bin = row.store === 'r2' ? env.R2 : env.MEDIA;
  for (let i = 0; i < row.chunks; i++) await bin.delete(`m:${id}:${i}`);
  await env.DB.prepare('DELETE FROM media WHERE id = ?').bind(id).run();
}
async function usedMediaIds(env) {
  const { clients, settings } = await loadContent(env);
  const used = mediaIds(clients);
  for (const m of JSON.stringify(settings).matchAll(/\/media\/([a-f0-9]{16})/g)) used.add(m[1]);
  return used;
}
async function usedBytes(env, store) {
  const r = store
    ? await env.DB.prepare('SELECT COALESCE(SUM(size),0) n FROM media WHERE store = ?').bind(store).first()
    : await env.DB.prepare('SELECT COALESCE(SUM(size),0) n FROM media').first();
  return r.n;
}

/* ---------- servir arquivos (público, com suporte a Range para vídeo) ---------- */
async function serveMedia(req, env, id) {
  const m = await env.DB.prepare('SELECT type, size, chunks, store FROM media WHERE id = ? AND done = 1').bind(id).first();
  if (!m) return new Response('Não encontrado', { status: 404 });
  const headers = { 'content-type': m.type, 'accept-ranges': 'bytes', 'cache-control': 'public, max-age=31536000, immutable', 'x-content-type-options': 'nosniff' };
  let start = 0, end = m.size - 1, status = 200;
  const rg = /^bytes=(\d*)-(\d*)$/.exec(req.headers.get('range') || '');
  if (rg && (rg[1] || rg[2])) {
    if (rg[1] === '') { start = Math.max(m.size - Number(rg[2]), 0); }
    else { start = Number(rg[1]); if (rg[2]) end = Math.min(Number(rg[2]), m.size - 1); }
    if (start > end || start >= m.size) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${m.size}` } });
    status = 206;
    headers['content-range'] = `bytes ${start}-${end}/${m.size}`;
  }
  headers['content-length'] = String(end - start + 1);
  if (req.method === 'HEAD') return new Response(null, { status, headers });
  const first = Math.floor(start / CHUNK), last = Math.floor(end / CHUNK);
  const { readable, writable } = new TransformStream();
  const w = writable.getWriter();
  (async () => {
    try {
      for (let i = first; i <= last; i++) {
        const from = i === first ? start - i * CHUNK : 0;
        if (m.store === 'r2') {
          const len = i === m.chunks - 1 ? m.size - CHUNK * i : CHUNK;
          const to = i === last ? end - i * CHUNK + 1 : len;
          const obj = await env.R2.get(`m:${id}:${i}`, { range: { offset: from, length: to - from } });
          if (!obj) throw new Error('pedaço ausente');
          await w.write(new Uint8Array(await obj.arrayBuffer()));
          continue;
        }
        const buf = await env.MEDIA.get(`m:${id}:${i}`, 'arrayBuffer');
        if (!buf) throw new Error('pedaço ausente');
        const to = i === last ? end - i * CHUNK + 1 : buf.byteLength;
        await w.write(new Uint8Array(buf, from, to - from));
      }
      await w.close();
    } catch (e) { await w.abort(e); }
  })();
  return new Response(readable, { status, headers });
}

/* vídeos que já vêm no projeto (pasta /videos): garante Range para dar para avançar o vídeo */
async function serveStaticRange(req, env) {
  const res = await env.ASSETS.fetch(new Request(new URL(req.url).href));
  if (res.status !== 200) return res;
  const buf = await res.arrayBuffer(); const size = buf.byteLength;
  const h = new Headers(res.headers); h.set('accept-ranges', 'bytes');
  const rg = /^bytes=(\d*)-(\d*)$/.exec(req.headers.get('range') || '');
  if (!rg || (!rg[1] && !rg[2])) { h.set('content-length', String(size)); return new Response(req.method === 'HEAD' ? null : buf, { status: 200, headers: h }); }
  let start, end = size - 1;
  if (rg[1] === '') start = Math.max(size - Number(rg[2]), 0); else { start = Number(rg[1]); if (rg[2]) end = Math.min(Number(rg[2]), size - 1); }
  if (start > end || start >= size) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${size}` } });
  h.set('content-range', `bytes ${start}-${end}/${size}`); h.set('content-length', String(end - start + 1));
  return new Response(req.method === 'HEAD' ? null : buf.slice(start, end + 1), { status: 206, headers: h });
}

/* ---------- roteador ---------- */
const SEC = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'x-frame-options': 'DENY', 'content-security-policy': "frame-ancestors 'none'" };
const withSec = (res) => { try { const r = new Response(res.body, res); for (const k in SEC) if (!r.headers.has(k)) r.headers.set(k, SEC[k]); return r; } catch { return res; } };

export default {
  async fetch(req, env) { return withSec(await handle(req, env)); }
};

const handle = async (req, env) => {
  {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      await schema(env.DB);

      if (path.startsWith('/media/')) {
        if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('Método não permitido', { status: 405 });
        return serveMedia(req, env, path.slice(7).split('/')[0]);
      }
      if (path === '/seed.json') return new Response('Não encontrado', { status: 404 });
      if (path.startsWith('/videos/') && req.headers.get('range')) return serveStaticRange(req, env);
      if (!path.startsWith('/api/')) return env.ASSETS.fetch(req);

      const ip = req.headers.get('cf-connecting-ip') || 'local';
      const method = req.method;

      /* públicas */
      if (path === '/api/content' && method === 'GET') {
        const { clients, rev, footer, settings } = await loadContent(env);
        return json({ clients, rev, footer, settings }, 200, { 'cache-control': 'no-cache' });
      }
      if (path === '/api/me' && method === 'GET') {
        const u = await currentUser(req, env);
        const n = await env.DB.prepare('SELECT COUNT(*) n FROM users').first();
        return json({ admin: !!u, username: u ? u.username : null, needsSetup: n.n === 0 });
      }

      /* tudo que muda alguma coisa exige mesma origem + cabeçalho próprio (anti-CSRF) */
      if (method !== 'GET' && method !== 'HEAD') {
        if (!sameOrigin(req) || req.headers.get('x-requested-with') !== 'portfolio') return fail(403, 'Requisição bloqueada.');
      }

      if (path === '/api/setup' && method === 'POST') {
        const n = await env.DB.prepare('SELECT COUNT(*) n FROM users').first();
        if (n.n > 0) return fail(403, 'O acesso já foi configurado.');
        const body = await req.json().catch(() => ({}));
        const username = str(body.username, 40).toLowerCase();
        const password = typeof body.password === 'string' ? body.password : '';
        if (!/^[a-z0-9._-]{3,40}$/.test(username)) return fail(400, 'Use de 3 a 40 letras minúsculas, números, ponto, traço ou sublinhado no usuário.');
        if (password.length < 10 || password.length > 200) return fail(400, 'A senha precisa ter pelo menos 10 caracteres.');
        const salt = rand(16);
        const hash = await hashPassword(password, salt);
        const ins = await env.DB.prepare('INSERT INTO users (username, salt, hash, created) SELECT ?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)').bind(username, b64u(salt), hash, now()).run();
        if (!ins.meta.changes) return fail(403, 'O acesso já foi configurado.');
        const u = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
        return json({ ok: true }, 200, { 'set-cookie': await startSession(env, u.id) });
      }

      if (path === '/api/login' && method === 'POST') {
        if (await tooManyAttempts(env, ip)) return fail(429, 'Muitas tentativas. Aguarde 15 minutos e tente de novo.');
        const body = await req.json().catch(() => ({}));
        const username = str(body.username, 40).toLowerCase();
        const password = typeof body.password === 'string' ? body.password.slice(0, 200) : '';
        const u = await env.DB.prepare('SELECT id, salt, hash FROM users WHERE username = ?').bind(username).first();
        const salt = u ? unb64u(u.salt) : rand(16); // gasta o mesmo tempo mesmo se o usuário não existir
        const hash = await hashPassword(password, salt);
        if (!u || !safeEqual(hash, u.hash)) { await noteFail(env, ip); return fail(401, 'Usuário ou senha incorretos.'); }
        await env.DB.prepare('DELETE FROM attempts WHERE ip = ?').bind(ip).run();
        return json({ ok: true }, 200, { 'set-cookie': await startSession(env, u.id) });
      }

      if (!/^\/api\/(admin-ui\.js|logout|password|content|footer|settings|usage|media)(\/|$)/.test(path)) return fail(404, 'Rota não encontrada.');
      /* ===== daqui para baixo: SOMENTE administradora autenticada ===== */
      const user = await currentUser(req, env);
      if (!user) return fail(401, 'Faça login para continuar.');

      if (path === '/api/admin-ui.js' && method === 'GET') {
        return new Response(ADMIN_UI, { headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store' } });
      }
      if (path === '/api/logout' && method === 'POST') {
        await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(user.th).run();
        return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
      }
      if (path === '/api/password' && method === 'POST') {
        const body = await req.json().catch(() => ({}));
        const row = await env.DB.prepare('SELECT salt, hash FROM users WHERE id = ?').bind(user.id).first();
        const cur = await hashPassword(typeof body.current === 'string' ? body.current.slice(0, 200) : '', unb64u(row.salt));
        if (!safeEqual(cur, row.hash)) return fail(403, 'Senha atual incorreta.');
        const next = typeof body.next === 'string' ? body.next : '';
        if (next.length < 10 || next.length > 200) return fail(400, 'A nova senha precisa ter pelo menos 10 caracteres.');
        const salt = rand(16);
        await env.DB.prepare('UPDATE users SET salt = ?, hash = ? WHERE id = ?').bind(b64u(salt), await hashPassword(next, salt), user.id).run();
        await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').bind(user.id, user.th).run();
        return json({ ok: true });
      }

      if (path === '/api/content' && method === 'PUT') {
        const raw = await req.text();
        if (raw.length > 60_000_000) return fail(413, 'Conteúdo grande demais.');
        let body; try { body = JSON.parse(raw); } catch { return fail(400, 'JSON inválido.'); }
        let clients; try { clients = cleanContent(body.clients); } catch (e) { return fail(400, e.message); }
        const cur = await loadContent(env);
        if (Number(body.rev) !== cur.rev) return fail(409, 'O site foi alterado em outro lugar. Recarregue a página.', { rev: cur.rev });
        const t = now();
        const ver = t.toString(36) + Array.from(crypto.getRandomValues(new Uint8Array(4)), b => b.toString(16).padStart(2, '0')).join('');
        const plan = planBig(env, 'content', ver, JSON.stringify(clients));
        const upd = env.DB.prepare("UPDATE docs SET value = ?, rev = rev + 1, updated = ? WHERE key = 'content' AND rev = ?").bind(plan.value, t, cur.rev);
        const out = await env.DB.batch([...plan.stmts, upd]);
        if (!out[out.length - 1].meta.changes) { await env.DB.prepare('DELETE FROM parts WHERE owner = ? AND ver = ?').bind('content', ver).run(); return fail(409, 'O site foi alterado em outro lugar. Recarregue a página.'); }
        await env.DB.prepare('INSERT INTO history (value, ts) VALUES (?,?)').bind(cur.raw, t).run();
        await env.DB.prepare('DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT 30)').run();
        await sweepParts(env);
        // limpeza: apaga arquivos enviados que não aparecem mais em lugar nenhum (com 2h de folga para uploads em andamento)
        const used = mediaIds(clients);
        const stRow = await env.DB.prepare("SELECT value FROM docs WHERE key = 'settings'").first();
        if (stRow) for (const m of stRow.value.matchAll(/\/media\/([a-f0-9]{16})/g)) used.add(m[1]);
        const all = await env.DB.prepare('SELECT id, created FROM media').all();
        for (const m of all.results) if (!used.has(m.id) && m.created < t - 7200) await deleteMedia(env, m.id);
        return json({ ok: true, rev: cur.rev + 1 });
      }

      if (path === '/api/footer' && method === 'PUT') {
        const body = await req.json().catch(() => ({}));
        let footer; try { footer = cleanFooter(body.footer); } catch (e) { return fail(400, e.message); }
        await env.DB.prepare("INSERT INTO docs (key, value, rev, updated) VALUES ('footer', ?, 1, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated").bind(JSON.stringify(footer), now()).run();
        return json({ ok: true, footer });
      }

      if (path === '/api/settings' && method === 'PUT') {
        const body = await req.json().catch(() => ({}));
        // quem não mandar "tema" ou "sobre mim" não apaga o que já está salvo
        if (body.settings && typeof body.settings === 'object' && (body.settings.theme === undefined || body.settings.about === undefined)) {
          const cur = (await loadContent(env)).settings;
          if (body.settings.theme === undefined) body.settings.theme = cur.theme;
          if (body.settings.about === undefined) body.settings.about = cur.about;
        }
        let settings; try { settings = cleanSettings(body.settings); } catch (e) { return fail(400, e.message); }
        await env.DB.prepare("INSERT INTO docs (key, value, rev, updated) VALUES ('settings', ?, 1, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated").bind(JSON.stringify(settings), now()).run();
        return json({ ok: true, settings });
      }

      if (path === '/api/usage' && method === 'GET') {
        return json({ used: await usedBytes(env), quota: QUOTA + (env.R2 ? R2_QUOTA : 0), r2: !!env.R2 });
      }

      if (path === '/api/media/init' && method === 'POST') {
        const body = await req.json().catch(() => ({}));
        const size = Number(body.size), type = String(body.type || '');
        if (!Number.isFinite(size) || size <= 0) return fail(400, 'Arquivo vazio.');
        if (!/^(image\/(jpeg|png|webp|gif|avif)|video\/(mp4|webm|quicktime))$/.test(type)) return fail(400, 'Tipo de arquivo não aceito. Use JPG, PNG, WEBP, GIF, MP4 ou WEBM.');
        const store = env.R2 ? 'r2' : 'kv';
        const maxFile = store === 'r2' ? R2_MAX_FILE : 500 * 1024 * 1024;
        if (size > maxFile) return fail(413, `Arquivo grande demais (máximo ${(maxFile / 1048576).toFixed(0)} MB).`);
        const used = await usedBytes(env, store);
        if (store === 'kv') {
          if (used + size > QUOTA) return fail(507, `Sem espaço: usado ${(used / 1048576).toFixed(0)} MB de ${(QUOTA / 1048576).toFixed(0)} MB. Apague arquivos antigos antes de enviar.`);
        } else {
          const free = Number(env.R2_FREE_LIMIT) || R2_QUOTA, after = used + size;
          if (after > R2_HARD) return fail(507, 'Passaria do teto de 50 GB do site. Apague arquivos antes de enviar.');
          if (after > free && body.confirmOver !== true) {
            const gb = n => n / 1073741824, extra = Math.ceil(Math.max(0, gb(after) - 10));
            return fail(409, 'Este envio passa dos 10 GB grátis do R2.', { needsConfirm: true, used, after, free, extraGb: extra, costMonth: +(extra * R2_PRICE_GB).toFixed(2) });
          }
        }
        const id = [...rand(8)].map(b => b.toString(16).padStart(2, '0')).join('');
        await env.DB.prepare('INSERT INTO media (id, name, type, size, chunks, done, created, store) VALUES (?,?,?,?,?,0,?,?)').bind(id, str(body.name, 120), type, size, Math.ceil(size / CHUNK), now(), store).run();
        return json({ id, chunk: CHUNK, chunks: Math.ceil(size / CHUNK) });
      }
      let m = /^\/api\/media\/([a-f0-9]{16})\/(\d+)$/.exec(path);
      if (m && method === 'PUT') {
        const row = await env.DB.prepare('SELECT size, chunks, done, store FROM media WHERE id = ?').bind(m[1]).first();
        const i = Number(m[2]);
        if (!row || row.done || i >= row.chunks) return fail(404, 'Envio inválido.');
        const buf = await req.arrayBuffer();
        const expect = i === row.chunks - 1 ? row.size - CHUNK * i : CHUNK;
        if (buf.byteLength !== expect) return fail(400, 'Pedaço com tamanho errado.');
        // se o envio foi cancelado (arquivo apagado) enquanto o pedaço chegava, não grava
        if (!(await env.DB.prepare('SELECT 1 x FROM media WHERE id = ?').bind(m[1]).first())) return fail(404, 'Envio cancelado.');
        await (row.store === 'r2' ? env.R2 : env.MEDIA).put(`m:${m[1]}:${i}`, buf);
        return json({ ok: true });
      }
      m = /^\/api\/media\/([a-f0-9]{16})\/done$/.exec(path);
      if (m && method === 'POST') {
        const row = await env.DB.prepare('SELECT chunks, store FROM media WHERE id = ?').bind(m[1]).first();
        if (!row) return fail(404, 'Envio inválido.');
        // cada pedaço já foi conferido (tamanho exato) ao ser gravado; aqui só olhamos o primeiro e o último (poucas leituras, resposta rápida)
        for (const i of new Set([0, row.chunks - 1])) if (!(await (row.store === 'r2' ? env.R2.head(`m:${m[1]}:${i}`) : env.MEDIA.get(`m:${m[1]}:${i}`, { type: 'stream' })))) return fail(400, 'Envio incompleto, tente de novo.');
        await env.DB.prepare('UPDATE media SET done = 1 WHERE id = ?').bind(m[1]).run();
        return json({ ok: true, src: `/media/${m[1]}` });
      }
      if (path === '/api/media' && method === 'GET') {
        const used = await usedMediaIds(env);
        const rows = await env.DB.prepare('SELECT id, name, type, size, done, created, store FROM media ORDER BY created DESC').all();
        return json({ files: rows.results.map(r => ({ ...r, used: used.has(r.id) })) });
      }
      m = /^\/api\/media\/([a-f0-9]{16})$/.exec(path);
      if (m && method === 'DELETE') {
        const row = await env.DB.prepare('SELECT done FROM media WHERE id = ?').bind(m[1]).first();
        if (row && row.done && (await usedMediaIds(env)).has(m[1])) return fail(409, 'Este arquivo está em uso no site. Tire ele do card primeiro.');
        await deleteMedia(env, m[1]);
        return json({ ok: true });
      }

      return fail(404, 'Rota não encontrada.');
    } catch (e) {
      return fail(500, 'Erro interno. Tente novamente.');
    }
  }
};
