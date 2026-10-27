# SQL Injection: Authentication Bypass

Standalone, local-only security lab comparing a vulnerable login query with a parameterized version. Do not expose it to a network or deploy it publicly.

## Run

Requires Node.js 18 or newer.

```bash
npm install
npm start
```

Open [http://127.0.0.1:3000/](http://127.0.0.1:3000/).

## Demo

1. In **Vulnerable Login**, try an invalid password, then use **Fill test payload** and submit.
2. Switch to **Secure Login** and submit the same input; authentication should fail.
3. Use **Fill valid login** to verify a legitimate login still works.
4. Compare `vulnerableLogin()` and `secureLogin()` in `database.js`.

The vulnerable query concatenates input into SQL, allowing it to change the query's meaning. The secure version uses `?` placeholders and bound values.

## Mitigation notes

Use parameterized queries as the primary defense. Allow-list validation and least-privilege database access provide additional protection; return generic authentication errors to users.

## Safety

The server binds to `127.0.0.1`. Demo credentials are fictional, and this lab is not production-ready authentication code.
