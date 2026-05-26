/**
 * Run once to hash plaintext passwords in users.json.
 * Usage: node hash-passwords.js
 * Output: overwrites users.json with bcrypt hashes (12 rounds).
 */
const bcrypt = require('bcrypt');
const fs     = require('fs');
const path   = require('path');

const ROUNDS   = 12;
const FILE     = path.join(__dirname, 'users.json');
const users    = JSON.parse(fs.readFileSync(FILE, 'utf8'));

(async () => {
  const hashed = await Promise.all(
    users.map(async u => ({
      ...u,
      password: await bcrypt.hash(u.password, ROUNDS),
    }))
  );

  fs.writeFileSync(FILE, JSON.stringify(hashed, null, 2));
  console.log(`[hash-passwords] Done — ${hashed.length} users hashed with bcrypt (${ROUNDS} rounds).`);
  hashed.forEach(u => console.log(`  ${u.username.padEnd(8)} ${u.password}`));
})();
