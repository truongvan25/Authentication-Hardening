const express = require('express');
const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

const rateLimiter = require('./middleware/rateLimiter');
const accountLock = require('./middleware/accountLock');
const store       = require('./store');

const BACKEND_HOST = 'localhost';
const BACKEND_PORT = 3000;

// Manually forward POST /login so we can rewrite 401 bodies (TC-03).
// Using native http.request avoids the selfHandleResponse stream-piping
// issues in http-proxy-middleware v2 that cause ReadTimeout.
function forwardLogin(req, res) {
  const body = JSON.stringify(req.body || {});

  const proxyReq = http.request(
    {
      hostname: BACKEND_HOST,
      port:     BACKEND_PORT,
      path:     '/login',
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    },
    (proxyRes) => {
      const chunks = [];
      proxyRes.on('data', chunk => chunks.push(chunk));
      proxyRes.on('end', () => {
        const raw = Buffer.concat(chunks).toString();

        if (proxyRes.statusCode === 401) {
          // TC-03: normalize — same message regardless of which field was wrong
          return res.status(401).json({ error: 'Invalid credentials.' });
        }

        res.status(proxyRes.statusCode)
           .set('Content-Type', proxyRes.headers['content-type'] || 'application/json')
           .send(raw);
      });
    }
  );

  proxyReq.on('error', () => {
    res.status(502).json({ error: 'Backend unavailable.' });
  });

  proxyReq.write(body);
  proxyReq.end();
}

const passthroughProxy = createProxyMiddleware({
  target: `http://${BACKEND_HOST}:${BACKEND_PORT}`,
  changeOrigin: true,
});

const app = express();
app.use(express.json());

// Serve dashboard UI
app.use('/dashboard', express.static(path.join(__dirname, 'public')));

// Protection layers apply ONLY to POST /login
app.post('/login', rateLimiter, accountLock, forwardLogin);

// --- Admin endpoints ---

app.post('/admin/reset', (_req, res) => {
  store.ipTimestamps.clear();
  store.blacklist.clear();
  store.accountFails.clear();
  store.accountLocks.clear();
  store.ipUsernames.clear();
  console.log('[Proxy] State reset — all counters and blacklists cleared');
  res.json({ message: 'State reset. All counters and blacklists cleared.' });
});

app.get('/admin/stats', (_req, res) => {
  const now = Date.now();
  res.json({
    blacklistedIPs: [...store.blacklist],
    lockedAccounts: [...store.accountLocks.entries()]
      .filter(([, lock]) => now < lock.until)
      .map(([username, lock]) => ({
        username,
        minutesLeft: Math.ceil((lock.until - now) / 60000),
      })),
    accountFails: [...store.accountFails.entries()]
      .map(([username, count]) => ({ username, count })),
    ipUsernames: [...store.ipUsernames.entries()]
      .filter(([, d]) => d.usernames.size > 0)
      .map(([ip, d]) => ({ ip, count: d.usernames.size, usernames: [...d.usernames] })),
  });
});

app.get('/admin/log', (_req, res) => {
  const logPath = path.join(__dirname, '..', 'attack.log');
  try {
    if (!fs.existsSync(logPath)) return res.json({ entries: [] });
    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
    const entries = lines.slice(-100).reverse().map(l => {
      try { return JSON.parse(l); } catch { return { raw: l }; }
    });
    res.json({ entries });
  } catch {
    res.json({ entries: [] });
  }
});

// Used by TC-03 in the dashboard: compare backend responses for ghost vs admin
// (browser can't hit :3000 directly due to cross-origin port difference)
app.get('/admin/enumeration-test', (_req, res) => {
  const probe = (body) => new Promise((resolve) => {
    const b = JSON.stringify(body);
    const req = http.request(
      { hostname: BACKEND_HOST, port: BACKEND_PORT, path: '/login', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) } },
      (r) => { let d = ''; r.on('data', c => d += c); r.on('end', () => resolve({ status: r.statusCode, body: JSON.parse(d) })); }
    );
    req.on('error', () => resolve({ status: 0, body: {} }));
    req.write(b); req.end();
  });

  Promise.all([
    probe({ username: 'ghost', password: 'x' }),
    probe({ username: 'admin', password: 'x' }),
  ]).then(([ghost, admin]) => res.json({ ghost, admin }));
});

// All other routes forwarded transparently
app.use('/', passthroughProxy);

app.listen(4000, () => {
  console.log('[Proxy] Auth Hardening Middleware on http://localhost:4000');
  console.log(`[Proxy] Forwarding to backend at http://${BACKEND_HOST}:${BACKEND_PORT}`);
  console.log('[Proxy] Protection: IP rate-limit | Account lockout | Response normalization');
});
