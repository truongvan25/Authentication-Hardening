const fs   = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, '../../attack.log');

module.exports = {
  log(event) {
    const entry = JSON.stringify({ ...event, time: new Date().toISOString() });
    console.log('\x1b[31m[BLOCKED]\x1b[0m', entry);
    fs.appendFileSync(LOG_FILE, entry + '\n');
  },

  info(event) {
    const entry = JSON.stringify({ ...event, time: new Date().toISOString() });
    console.log('\x1b[33m[INFO]\x1b[0m', entry);
  }
};
