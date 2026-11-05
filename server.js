'use strict';
/* Fyx auth server: one file, no npm packages (Node 18+).
   Run:  node server.js   then open http://localhost:3000
   Data: users.json next to this file (passwords are scrypt-hashed, never stored in plain text). */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';          // use 0.0.0.0 behind a reverse proxy
const SECURE = process.env.COOKIE_SECURE === '1';       // set to 1 when served over HTTPS
const PROXY = process.env.TRUST_PROXY === '1';          // set to 1 behind nginx to read X-Forwarded-For
const DB = path.join(__dirname, 'users.json');
const PAGE = path.join(__dirname, 'fyx-auth.html');
const TTL = 30 * 864e5;

/* ---------- storage ---------- */
let db = { users: [], sessions: [] };
try {
  db = JSON.parse(fs.readFileSync(DB, 'utf8'));
  db.users = db.users || []; db.sessions = db.sessions || [];
} catch (e) {
  if (e.code !== 'ENOENT') { console.error('Cannot read users.json (fix or delete it):', e.message); process.exit(1); }
}
let queue = Promise.resolve();
function save() {                                       // serialized, atomic write
  queue = queue.then(async () => {
    const tmp = DB + '.tmp';
    await fs.promises.writeFile(tmp, JSON.stringify(db, null, 2));
    await fs.promises.rename(tmp, DB);
  }).catch(e => console.error('Save failed:', e.message));
  return queue;
}
const purge = () => { const n = Date.now(); db.sessions = db.sessions.filter(s => s.exp > n); };

/* ---------- helpers ---------- */
const scrypt = (pw, salt) => new Promise((ok, no) =>
  crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => e ? no(e) : ok(k)));
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const DUMMY = crypto.randomBytes(16);                   // keeps timing equal for unknown users
const UNAME = /^[A-Za-z][A-Za-z0-9_]{4,23}$/;

const hits = new Map(), fails = new Map();
setInterval(() => { const n = Date.now(); hits.clear(); for (const [k, v] of fails) if (v.until < n && n - v.at > 36e5) fails.delete(k); }, 6e5).unref();
const ipOf = req => (PROXY && (req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;
const limited = ip => { const n = Date.now(), a = (hits.get(ip) || []).filter(t => n - t < 6e4); a.push(n); hits.set(ip, a); return a.length > 20; };

const SEC = {
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store'
};
function send(res, code, obj, extra) {
  res.writeHead(code, { ...SEC, 'Content-Type': 'application/json; charset=utf-8', ...extra });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((ok, no) => {
    let s = '';
    req.setEncoding('utf8');
    req.on('data', c => { s += c; if (s.length > 1e4) { no(new Error('big')); req.destroy(); } });
    req.on('end', () => { try { ok(JSON.parse(s || '{}')); } catch { no(new Error('json')); } });
    req.on('error', no);
  });
}
const cookieOf = req => (/(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie || '') || [])[1];
const setCookie = (v, age) => ({ 'Set-Cookie': `sid=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${SECURE ? '; Secure' : ''}` });
const pub = u => ({ id: u.id, uname: u.uname, name: u.name });
function sessionUser(req) {
  const t = cookieOf(req); if (!t) return null;
  const h = sha(t), s = db.sessions.find(x => x.h === h && x.exp > Date.now());
  return s ? db.users.find(u => u.id === s.uid) || null : null;
}
async function openSession(res, user) {
  purge();
  const tok = crypto.randomBytes(32).toString('hex');
  db.sessions.push({ h: sha(tok), uid: user.id, exp: Date.now() + TTL });
  await save();
  send(res, 200, { user: pub(user) }, setCookie(tok, TTL / 1000));
}

/* ---------- routes ---------- */
async function register(req, res) {
  const b = await readBody(req);
  const uname = typeof b.uname === 'string' ? b.uname.trim() : '';
  const pw = typeof b.pw === 'string' ? b.pw : '';
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (!UNAME.test(uname) || pw.length < 8 || pw.length > 128 || !name || name.length > 40) return send(res, 400, { e: 'invalid' });
  const salt = crypto.randomBytes(16), hash = await scrypt(pw, salt);
  const key = uname.toLowerCase();
  if (db.users.some(u => u.key === key)) return send(res, 409, { e: 'taken' });   // checked after hashing: no race
  const user = { id: crypto.randomUUID(), uname, key, name, salt: salt.toString('hex'), hash: hash.toString('hex'), created: new Date().toISOString() };
  db.users.push(user);
  await openSession(res, user);
}
async function login(req, res) {
  const b = await readBody(req);
  const uname = typeof b.uname === 'string' ? b.uname.trim().toLowerCase() : '';
  const pw = typeof b.pw === 'string' ? b.pw : '';
  if (!uname || !pw || pw.length > 128) return send(res, 400, { e: 'invalid' });
  const f = fails.get(uname) || { n: 0, until: 0, at: 0 };
  if (f.until > Date.now()) return send(res, 429, { e: 'locked' });
  const user = db.users.find(u => u.key === uname);
  const got = await scrypt(pw, user ? Buffer.from(user.salt, 'hex') : DUMMY);
  if (!user || !crypto.timingSafeEqual(got, Buffer.from(user.hash, 'hex'))) {
    f.n++; f.at = Date.now(); if (f.n >= 5) { f.until = Date.now() + 3e5; f.n = 0; }
    fails.set(uname, f);
    return send(res, 401, { e: 'creds' });
  }
  fails.delete(uname);
  await openSession(res, user);
}
async function logout(req, res) {
  const t = cookieOf(req);
  if (t) { const h = sha(t); db.sessions = db.sessions.filter(s => s.h !== h); await save(); }
  send(res, 200, { ok: true }, setCookie('', 0));
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname.replace(/^\/api(?=\/)/, '');

    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      const html = await fs.promises.readFile(PAGE);
      res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" });
      return res.end(html);
    }
    if (req.method === 'GET' && p === '/me') {
      const u = sessionUser(req);
      return u ? send(res, 200, { user: pub(u) }) : send(res, 401, { e: 'auth' });
    }
    if (req.method === 'POST' && ['/register', '/login', '/logout'].includes(p)) {
      const o = req.headers.origin;
      if (o && new URL(o).host !== req.headers.host) return send(res, 403, { e: 'origin' });
      if (!/^application\/json/i.test(req.headers['content-type'] || '')) return send(res, 400, { e: 'invalid' });
      if (limited(ipOf(req))) return send(res, 429, { e: 'rate' });
      return await ({ '/register': register, '/login': login, '/logout': logout })[p](req, res);
    }
    send(res, 404, { e: 'notfound' });
  } catch (e) {
    if (res.headersSent) return res.end();
    if (e.message === 'json' || e.message === 'big') return send(res, 400, { e: 'invalid' });
    console.error(e);
    send(res, 500, { e: 'server' });
  }
});

server.listen(PORT, HOST, () => console.log(`Fyx auth running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`));
