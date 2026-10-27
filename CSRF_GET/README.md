# GET-based CSRF lab

A small Flask banking demo for the **GET-based forged action** CSRF variant.

The victim app runs at `http://localhost:5000`. The attacker page is a static
HTML file served from `http://127.0.0.1:5001`, a different host, so the browser
treats it as a cross-site origin.

The same app can run in two modes:

| Mode | Session cookie | Behaviour |
|---|---|---|
| `vulnerable` | `SameSite=Lax` | A cross-site top-level GET still carries the session cookie, so the forged transfer executes. |
| `secure` | `SameSite=Strict` | The browser does not attach the cookie to a cross-site request, so the forged transfer is rejected. |

## Files

```text
csrf/
  app.py                  # victim Flask app (login, dashboard, GET /transfer)
  templates/              # login, dashboard, error pages
  static/style.css
  attacker/index.html     # meta-refresh GET CSRF payload
  run_vulnerable.bat      # starts the app in vulnerable mode
  run_secure.bat          # starts the app in secure mode
  run_attacker.bat        # serves the attacker page on 127.0.0.1:5001
  requirements.txt
```

## Setup

From `D:\CS_Lab`:

```powershell
py -m pip install -r .\csrf\requirements.txt
```

## Run the vulnerable version

Open two terminals.

Terminal 1:

```powershell
cd D:\CS_Lab\csrf
py app.py --mode vulnerable
```

Terminal 2:

```powershell
cd D:\CS_Lab\csrf
py -m http.server 5001 --bind 127.0.0.1 --directory attacker
```

Then:

1. Open `http://localhost:5000/login`.
2. Log in as `alice` / `alice123`.
3. Confirm Alice's balance is Rs. 1,000.
4. In the same browser, open `http://127.0.0.1:5001/`.
5. The attacker page meta-refreshes to:

   ```text
   http://localhost:5000/transfer?to=mallory&amount=250
   ```

6. The transfer executes. Alice's balance becomes Rs. 750 and Mallory's
   becomes Rs. 250.

The server log shows the forged request with the victim's session cookie
present, even though the request came from `127.0.0.1:5001`.

## Run the secure version

Stop the victim app from the first terminal and start it again:

```powershell
cd D:\CS_Lab\csrf
py app.py --mode secure
```

Leave the attacker server running. Log in as Alice again, then open the same
attacker page:

```text
http://127.0.0.1:5001/
```

The exact same URL is requested, but the browser does not send the
`SameSite=Strict` session cookie. The app returns HTTP 403 and no transfer
happens. Alice's balance stays Rs. 1,000.

A normal transfer from Alice's dashboard to Bob still works in secure mode,
because it is same-site and the Strict cookie is sent.

## What to check in the browser

Open DevTools -> Network -> select the `/transfer` request.

- Vulnerable mode: Request Headers contain `Cookie: csrf_demo_session=...`.
- Secure mode: there is no `Cookie` header on the forged request.

That difference is the whole demonstration.

## Evidence captured

The `evidence/` folder contains screenshots from a real Chrome run:

- `01-vulnerable-before.png` — Alice starts at Rs. 1,000.
- `02-vulnerable-after-exploit.png` — the forged GET executes; Alice is at Rs. 750 and Mallory at Rs. 250.
- `03-secure-blocked-403.png` — the same forged URL returns HTTP 403 in secure mode.
- `04-secure-balance-unchanged.png` — Alice is still at Rs. 1,000 after the blocked attempt.

Server-side proof from the same run:

```text
vulnerable: cookie_header=present  -> TRANSFER_COMPLETED  alice=750 mallory=250
secure:     cookie_header=absent   -> BLOCKED reason=no_session_cookie
```

## Demo accounts

| Username | Password | Role | Starting balance |
|---|---|---|---|
| `alice` | `alice123` | victim | Rs. 1,000 |
| `mallory` | `mallory123` | attacker | Rs. 0 |
| `bob` | `bob123` | normal recipient | Rs. 500 |

## Notes

- The app deliberately uses `GET /transfer`. That is the vulnerable design:
  GET should be safe and idempotent, but here it changes balances.
- The legitimate transfer form also uses GET so the vulnerable and secure
  versions share exactly the same request path. A production app should use
  POST plus a synchronizer token.
- The attacker page uses a top-level meta refresh, not an `<img>`. A cross-site
  image is a subresource and `SameSite=Lax` already blocks its cookie. A
  top-level GET is the request type that Lax allows and Strict blocks.
- `localhost` and `127.0.0.1` are different hosts, so the attacker server does
  not receive the victim's `localhost` cookie. The forged request goes to
  `localhost`; the browser decides whether to attach the cookie.
- `SESSION_COOKIE_SECURE` is intentionally false for local HTTP. In production
  it should be true and the app should run over HTTPS.
- All state is in memory; restarting the app resets balances and transfers.
