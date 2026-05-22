const express = require('express');
const http    = require('http');
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

// Protection layers apply ONLY to POST /login
app.post('/login', rateLimiter, accountLock, forwardLogin);

// Demo helper — clears all in-memory state between test cases
app.post('/admin/reset', (req, res) => {
  store.ipTimestamps.clear();
  store.blacklist.clear();
  store.accountFails.clear();
  store.accountLocks.clear();
  store.ipUsernames.clear();
  console.log('[Proxy] State reset — all counters and blacklists cleared');
  res.json({ message: 'State reset. All counters and blacklists cleared.' });
});

// All other routes forwarded transparently
app.use('/', passthroughProxy);

app.listen(4000, () => {
  console.log('[Proxy] Auth Hardening Middleware on http://localhost:4000');
  console.log(`[Proxy] Forwarding to backend at http://${BACKEND_HOST}:${BACKEND_PORT}`);
  console.log('[Proxy] Protection: IP rate-limit | Account lockout | Response normalization');
});
