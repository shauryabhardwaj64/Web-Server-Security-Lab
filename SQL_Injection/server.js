const express = require('express');
const path = require('path');
const { vulnerableLogin, secureLogin } = require('./database');

const app = express();
const HOST = '127.0.0.1';
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function handleLogin(loginFunction, mode) {
  return (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ success: false, message: 'Enter a username and password.' });
    }

    try {
      const result = loginFunction(username, password);
      if (result.user) {
        const bypass = mode === 'vulnerable' &&
          !(username === result.user.username && password === (username === 'admin' ? 'Password123!' : 'Alice456!'));

        return res.json({
          success: true,
          bypass,
          message: bypass
            ? 'VULNERABILITY CONFIRMED: Login succeeded without valid credentials.'
            : `Login successful. Welcome, ${result.user.full_name}.`,
          user: { username: result.user.username, fullName: result.user.full_name },
          query: result.query
        });
      }

      return res.status(401).json({
        success: false,
        bypass: false,
        message: 'Authentication failed: invalid username or password.',
        query: result.query
      });
    } catch (error) {
      console.error(`${mode} login error:`, error.message);
      return res.status(400).json({
        success: false,
        bypass: false,
        message: 'Login failed. The query could not be processed.'
      });
    }
  };
}

app.post('/api/login/vulnerable', handleLogin(vulnerableLogin, 'vulnerable'));
app.post('/api/login/secure', handleLogin(secureLogin, 'secure'));

app.listen(PORT, HOST, () => {
  console.log(`SQL Injection Lab: http://${HOST}:${PORT}`);
  console.log('Local educational use only. Do not expose this server to a network.');
});