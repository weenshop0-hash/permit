/**
 * سيرفر WebSocket لمنظومة التراخيص الملاحية  — بدون أي مكتبات خارجية (Node 16+ فقط)
 * ------------------------------------------------------------------------------
 * - يحتفظ بآخر نسخة كاملة (JSON) في state.json ويرسلها لكل عميل فور اتصاله.
 * - عند وصول نسخة جديدة من عميل يحفظها ويبثّها فوراً لباقي العملاء المتصلين.
 * - رمز دخول اختياري عبر TOKEN (تضعه في الصفحة، ويُمرَّر كـ ?token=...).
 *
 * التشغيل:   TOKEN=سري PORT=8080 node server.js
 * للإنترنت: ضعه خلف HTTPS (Caddy / Nginx / Cloudflare Tunnel) ليصبح wss:// — صفحات https تشترط ذلك.
 */
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');

const PORT  = +process.env.PORT || 8080;
const TOKEN = process.env.TOKEN || '';                              // فارغ = بدون مصادقة
const FILE  = process.env.STATE_FILE || path.join(__dirname, 'state.json');
const MAX   = 50 * 1024 * 1024;                                     // أقصى حجم رسالة
const GUID  = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

let latest = null, at = 0;
try { const o = JSON.parse(fs.readFileSync(FILE, 'utf8')); latest = o.content; at = o.at; } catch (e) {}
const save = () => { const t = FILE + '.tmp'; fs.writeFile(t, JSON.stringify({ content: latest, at }), e => { if (!e) fs.rename(t, FILE, () => {}); }); };
const valid = c => { try { const d = JSON.parse(c); return d && Array.isArray(d.L); } catch (e) { return false; } };

const clients = new Set();

/* ---------- ترميز/فك ترميز إطارات WebSocket (RFC 6455) ---------- */
function frame(op, payload) {
  const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const n = p.length; let h;
  if (n < 126) h = Buffer.from([0x80 | op, n]);
  else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(n, 2); }
  else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  return Buffer.concat([h, p]);
}
const sendText = (c, s) => { if (!c.dead) c.sock.write(frame(1, s)); };
function kill(c, code) { if (c.dead) return; c.dead = true; clients.delete(c); try { c.sock.write(frame(8, Buffer.from([code >> 8, code & 255]))); } catch (e) {} c.sock.end(); setTimeout(() => c.sock.destroy(), 500); }

function onData(c, chunk) {
  c.buf = Buffer.concat([c.buf, chunk]);
  for (;;) {
    const b = c.buf; if (b.length < 2) return;
    const fin = !!(b[0] & 0x80), op = b[0] & 15, masked = !!(b[1] & 0x80);
    let len = b[1] & 127, off = 2;
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
    if (len > MAX) return kill(c, 1009);
    if (!masked) return kill(c, 1002);                              // العميل يجب أن يقنّع الإطارات
    if (b.length < off + 4 + len) return;
    const mask = b.subarray(off, off + 4), data = Buffer.from(b.subarray(off + 4, off + 4 + len));
    for (let i = 0; i < len; i++) data[i] ^= mask[i & 3];
    c.buf = b.subarray(off + 4 + len);
    if (op === 8) return kill(c, 1000);
    if (op === 9) { c.sock.write(frame(10, data)); continue; }       // ping → pong
    if (op === 10) { c.alive = true; continue; }
    if (op === 0 || op === 1) {                                      // نص / استكمال
      c.parts.push(data); c.size += len; if (c.size > MAX) return kill(c, 1009);
      if (fin) { const msg = Buffer.concat(c.parts).toString('utf8'); c.parts = []; c.size = 0; onMessage(c, msg); }
    }
  }
}

function onMessage(c, raw) {
  c.alive = true;
  let m; try { m = JSON.parse(raw); } catch (e) { return; }
  if (m.type === 'ping') return sendText(c, '{"type":"pong"}');
  if (m.type === 'state' && typeof m.content === 'string' && valid(m.content)) {
    latest = m.content; at = Date.now(); save();
    const out = JSON.stringify({ type: 'state', content: latest, at });
    clients.forEach(o => { if (o !== c) sendText(o, out); });        // بثّ لباقي العملاء
    sendText(c, JSON.stringify({ type: 'ack', at }));
  }
}

/* ---------- HTTP + الترقية إلى WebSocket ---------- */
const server = http.createServer((req, res) => {                     // فحص الصحة
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*' });
  res.end(JSON.stringify({ ok: true, clients: clients.size, hasState: !!latest, at }));
});
server.on('upgrade', (req, sock) => {
  const key = req.headers['sec-websocket-key'];
  if (!key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') return sock.destroy();
  const tk = new URL(req.url, 'http://x').searchParams.get('token') || '';
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' +
    crypto.createHash('sha1').update(key + GUID).digest('base64') + '\r\n\r\n');
  const c = { sock, buf: Buffer.alloc(0), parts: [], size: 0, alive: true, dead: false };
  sock.setNoDelay(true);
  sock.on('data', d => onData(c, d));
  sock.on('close', () => { c.dead = true; clients.delete(c); });
  sock.on('error', () => { c.dead = true; clients.delete(c); });
  if (TOKEN && tk !== TOKEN) return kill(c, 4401);                   // مرفوض: رمز خاطئ
  clients.add(c);
  if (latest) sendText(c, JSON.stringify({ type: 'state', content: latest, at }));   // آخر نسخة عند الاتصال
});

setInterval(() => clients.forEach(c => { if (!c.alive) return kill(c, 1001); c.alive = false; c.sock.write(frame(9, '')); }), 30000);
server.listen(PORT, () => console.log(`WebSocket server on :${PORT} ${TOKEN ? '(token required)' : '(no token)'}`));
