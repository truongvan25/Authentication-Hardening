const express = require('express');
const crypto  = require('crypto');
const users   = require('./users.json');

const app = express();
app.use(express.json());

let requestCount = 0;

// FIXED: timing-safe password comparison.
//
// VULNERABLE (before):  user.password !== password
//   JavaScript's === exits on the FIRST differing character.
//   A password sharing more prefix with the real value takes microseconds longer
//   to reject — attacker can measure this over many samples and guess char-by-char.
//
// FIXED (after): crypto.timingSafeEqual()
//   Compares every byte regardless of where the difference is.
//   Response time is identical whether the password is completely wrong
//   or wrong only on the last character.
function timingSafeCompare(stored, input) {
  const a = Buffer.from(String(stored));
  const b = Buffer.from(String(input));
  if (a.length !== b.length) {
    // Run a dummy comparison so length mismatch doesn't create a fast-path
    crypto.timingSafeEqual(Buffer.alloc(a.length), Buffer.alloc(a.length));
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

app.post('/login', (req, res) => {
  requestCount++;
  console.log(`[Backend :3000] Request #${requestCount} — user: "${req.body?.username || req.body?.email}"`);

  const { username, email, password } = req.body || {};
  const identifier = username || email || '';

  const user = users.find(u => u.username === identifier || u.email === identifier);

  if (!user) {
    // VULNERABILITY: reveals username does not exist (intentional for TC-03 demo)
    return res.status(401).json({ error: 'User not found' });
  }

  if (!timingSafeCompare(user.password, password || '')) {
    // VULNERABILITY: reveals username exists but password is wrong (intentional for TC-03 demo)
    return res.status(401).json({ error: 'Incorrect password' });
  }

  return res.status(200).json({
    message: 'Login successful',
    token: 'sess_' + Buffer.from(user.username).toString('base64'),
    user: { username: user.username, email: user.email }
  });
});

app.get('/status', (_req, res) => {
  res.json({ status: 'ok', requestsReceived: requestCount });
});

app.listen(3000, () => {
  console.log('[Backend] Vulnerable target app on http://localhost:3000');
});
