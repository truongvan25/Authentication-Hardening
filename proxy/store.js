// Shared in-memory state across all middleware modules
module.exports = {
  // Map<ip, number[]> — sliding window timestamps per IP
  ipTimestamps: new Map(),

  // Set<ip> — blacklisted IPs (auto-expires via setTimeout)
  blacklist: new Set(),

  // Map<username, number> — cumulative failed login count per account
  accountFails: new Map(),

  // Map<username, { until: number }> — locked accounts with expiry timestamp
  accountLocks: new Map(),

  // Map<ip, { usernames: Set<string>, windowStart: number }>
  // Tracks how many DISTINCT usernames one IP has tried in the current window.
  // High username diversity from a single IP = credential stuffing signal.
  ipUsernames: new Map(),
};
