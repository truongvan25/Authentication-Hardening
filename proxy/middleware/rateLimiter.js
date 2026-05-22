const store  = require('../store');
const logger = require('./logger');

const IP_WINDOW_MS            = 60 * 1000;      // 1-minute sliding window
const IP_MAX_REQUESTS         = 5;              // max total requests per IP per window (TC-01)
const UNIQUE_USERNAME_THRESHOLD = 3;            // max distinct usernames per IP per window (TC-02)
const LOCKOUT_MS              = 15 * 60 * 1000; // 15-minute IP blacklist

module.exports = function rateLimiter(req, res, next) {
  // X-Real-IP is trusted for local demo (simulates different upstream IPs in TC-04).
  // X-Forwarded-For is NOT trusted — TC-05 proves spoofing it has no effect.
  const ip  = req.headers['x-real-ip'] || req.socket.remoteAddress || req.ip;
  const now = Date.now();

  // --- Blacklist check (TC-01, TC-02, TC-05) ---
  if (store.blacklist.has(ip)) {
    logger.log({ type: 'BLOCKED_BLACKLIST', ip });
    return res.status(429).json({
      error: 'Too many failed attempts. Try again later.',
      retryAfter: '15 minutes'
    });
  }

  // --- Sliding window: prune timestamps older than the window ---
  if (!store.ipTimestamps.has(ip)) store.ipTimestamps.set(ip, []);
  const timestamps = store.ipTimestamps.get(ip).filter(t => now - t < IP_WINDOW_MS);
  store.ipTimestamps.set(ip, timestamps);

  // --- TC-01: Brute force — too many total requests from one IP ---
  if (timestamps.length >= IP_MAX_REQUESTS) {
    store.blacklist.add(ip);
    setTimeout(() => store.blacklist.delete(ip), LOCKOUT_MS);
    logger.log({ type: 'RATE_LIMIT_EXCEEDED', ip, count: timestamps.length });
    return res.status(429).json({ error: 'Too many requests. Locked for 15 minutes.' });
  }

  // --- TC-02: Credential stuffing — too many DISTINCT usernames from one IP ---
  const username = req.body?.username || req.body?.email || '';
  if (!store.ipUsernames.has(ip)) {
    store.ipUsernames.set(ip, { usernames: new Set(), windowStart: now });
  }
  const userData = store.ipUsernames.get(ip);
  // Reset the username set if the window has expired
  if (now - userData.windowStart >= IP_WINDOW_MS) {
    userData.usernames.clear();
    userData.windowStart = now;
  }
  if (username) userData.usernames.add(username);

  if (userData.usernames.size >= UNIQUE_USERNAME_THRESHOLD) {
    store.blacklist.add(ip);
    setTimeout(() => {
      store.blacklist.delete(ip);
      store.ipUsernames.delete(ip);
    }, LOCKOUT_MS);
    logger.log({
      type:        'CREDENTIAL_STUFFING_DETECTED',
      ip,
      uniqueUsers: userData.usernames.size,
      accounts:    [...userData.usernames],
    });
    return res.status(429).json({ error: 'Suspicious activity detected. Locked for 15 minutes.' });
  }

  // Record this attempt
  timestamps.push(now);
  store.ipTimestamps.set(ip, timestamps);

  next();
};
