const store  = require('../store');
const logger = require('./logger');

const ACCOUNT_MAX_FAILS  = 10;               // cumulative failures before lockout
const ACCOUNT_LOCKOUT_MS = 30 * 60 * 1000;  // 30-minute account lockout

module.exports = function accountLock(req, res, next) {
  const username = req.body?.username || req.body?.email || '';

  // --- TC-04: check if account is currently locked ---
  const lock = store.accountLocks.get(username);
  if (lock && Date.now() < lock.until) {
    logger.log({ type: 'ACCOUNT_LOCKED', username, ip: req.socket.remoteAddress });
    return res.status(423).json({
      error: 'Account temporarily locked due to too many failed attempts.',
      retryAfter: Math.ceil((lock.until - Date.now()) / 60000) + ' minutes'
    });
  }

  // Hook into the response AFTER the backend replies to count failures
  res.on('finish', () => {
    if (res.statusCode === 401) {
      const fails = (store.accountFails.get(username) || 0) + 1;
      store.accountFails.set(username, fails);
      logger.info({ type: 'ACCOUNT_FAIL', username, fails });

      if (fails >= ACCOUNT_MAX_FAILS) {
        store.accountLocks.set(username, { until: Date.now() + ACCOUNT_LOCKOUT_MS });
        // Auto-clear lock after expiry so subsequent logins work again
        setTimeout(() => {
          store.accountLocks.delete(username);
          store.accountFails.delete(username);
        }, ACCOUNT_LOCKOUT_MS);
        logger.log({ type: 'ACCOUNT_LOCK_TRIGGERED', username, fails });
      }
    } else if (res.statusCode === 200) {
      store.accountFails.delete(username);
    }
  });

  next();
};
