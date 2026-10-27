const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'lab.db'));

const accounts = [
  ['admin', 'Password123!', 'Demo Administrator'],
  ['alice', 'Alice456!', 'Demo User']
];

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT NOT NULL
  )
`);

const count = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
if (count === 0) {
  const insert = db.prepare(
    'INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)'
  );
  for (const account of accounts) insert.run(...account);
}

function vulnerableLogin(username, password) {
  const query = `SELECT id, username, full_name FROM users WHERE username = '${username}' AND password = '${password}'`;
  const user = db.prepare(query).get();
  return { user: user || null, query };
}

function secureLogin(username, password) {
  const query = 'SELECT id, username, full_name FROM users WHERE username = ? AND password = ?';
  const user = db.prepare(query).get(username, password);
  return { user: user || null, query };
}

module.exports = { vulnerableLogin, secureLogin };