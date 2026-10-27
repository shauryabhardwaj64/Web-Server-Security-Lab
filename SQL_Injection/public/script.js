const form = document.getElementById('loginForm');
const username = document.getElementById('username');
const password = document.getElementById('password');
const vulnerableTab = document.getElementById('vulnerableTab');
const secureTab = document.getElementById('secureTab');
const modeNote = document.getElementById('modeNote');
const result = document.getElementById('result');
const resultTitle = document.getElementById('resultTitle');
const resultMessage = document.getElementById('resultMessage');
const userDetails = document.getElementById('userDetails');
const query = document.getElementById('query');
const queryPattern = document.getElementById('queryPattern');
const queryHeading = document.getElementById('queryHeading');
const whyText = document.getElementById('whyText');

let mode = 'vulnerable';

function setMode(nextMode) {
  mode = nextMode;
  const secure = mode === 'secure';
  vulnerableTab.classList.toggle('active', !secure);
  secureTab.classList.toggle('active', secure);
  modeNote.className = `note ${secure ? 'safe' : 'danger'}`;
  modeNote.textContent = secure
    ? 'Secure mode: the SQL statement uses placeholders and bound values.'
    : 'Vulnerable mode: input is inserted directly into the SQL query.';
  queryHeading.textContent = secure ? 'Secure query pattern' : 'Vulnerable query pattern';
  queryPattern.textContent = secure
    ? 'SELECT ... WHERE username = ? AND password = ?'
    : "SELECT ... WHERE username = '${username}' AND password = '${password}'";
  whyText.textContent = secure
    ? 'The SQL structure is separate from the supplied values. Input such as quotes and comment markers is treated as ordinary text, not SQL syntax.'
    : 'The application joins user input into the SQL text. A crafted username can change the query meaning and comment out the password condition.';
  result.hidden = true;
}

vulnerableTab.addEventListener('click', () => setMode('vulnerable'));
secureTab.addEventListener('click', () => setMode('secure'));

document.getElementById('fillPayload').addEventListener('click', () => {
  username.value = "admin' --";
  password.value = 'wrong-password';
});
document.getElementById('fillInvalid').addEventListener('click', () => {
  username.value = 'admin';
  password.value = 'wrong-password';
});
document.getElementById('fillValid').addEventListener('click', () => {
  username.value = 'admin';
  password.value = 'Password123!';
});
document.getElementById('clear').addEventListener('click', () => {
  username.value = '';
  password.value = '';
  result.hidden = true;
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const endpoint = `/api/login/${mode}`;
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value, password: password.value })
    });
    const data = await response.json();

    result.hidden = false;
    result.className = `result ${data.success ? 'success' : 'failure'}`;
    resultTitle.textContent = data.bypass
      ? 'VULNERABILITY CONFIRMED'
      : data.success ? 'Login successful' : 'Authentication failed';
    resultMessage.textContent = data.message;
    userDetails.textContent = data.user
      ? `Authenticated user: ${data.user.username} (${data.user.fullName})`
      : '';
    query.textContent = data.query || 'Query not returned.';
  } catch {
    result.hidden = false;
    result.className = 'result failure';
    resultTitle.textContent = 'Request failed';
    resultMessage.textContent = 'Could not reach the local server. Check that npm start is running.';
    userDetails.textContent = '';
    query.textContent = '';
  }
});

setMode('vulnerable');
