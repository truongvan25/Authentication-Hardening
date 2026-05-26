const express = require('express');
const bcrypt  = require('bcrypt');
const users   = require('./users.json');

const app = express();
app.use(express.json());

let requestCount = 0;

app.post('/login', async (req, res) => {
  requestCount++;
  console.log(`[Backend :3000] Request #${requestCount} — user: "${req.body?.username || req.body?.email}"`);

  const { username, email, password } = req.body || {};
  const identifier = username || email || '';

  const user = users.find(u => u.username === identifier || u.email === identifier);

  if (!user) {
    // VULNERABILITY: reveals username does not exist (intentional for TC-03 demo)
    return res.status(401).json({ error: 'User not found' });
  }

  // bcrypt.compare is timing-safe by design — runs full work factor (12 rounds)
  // regardless of whether the password is completely wrong or off by one character.
  const match = await bcrypt.compare(password || '', user.password);

  if (!match) {
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
