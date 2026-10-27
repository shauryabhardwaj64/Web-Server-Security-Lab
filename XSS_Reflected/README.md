# Reflected XSS: Exploitation and Mitigation

Standalone local-only cybersecurity lab. **Variant:** Reflected Cross-Site Scripting (XSS). Do not deploy publicly.

## Run

1. Install Python 3 and pip.
2. In this folder run:

   ```bash
   python -m venv .venv
   source .venv/bin/activate       # Linux/macOS
   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   python app.py
   ```
3. Open `http://127.0.0.1:5000/` in a browser.

## Demo (about 2–3 minutes)

1. Visit `/vulnerable`. Search for `hello`: normal search text is shown.
2. Search for `<script>alert('XSS Demo')</script>`. A JavaScript popup appears. The text travels as the GET query parameter `q` and is **reflected** into the HTML response.
3. Show `templates/vulnerable.html`: `{{ query | safe }}` disables Jinja's HTML escaping and lets untrusted markup execute. Show `app.py` to demonstrate where `q` comes from.
4. Visit `/secure` and submit the **same** input. The page displays the characters as harmless text; there is no popup.
5. Show `templates/secure.html`: `{{ query }}` uses Jinja's HTML escaping by default. Explain context-aware output encoding as the implemented mitigation.

If the popup does not appear, type the payload directly into the search field and press Search; do not paste raw angle brackets into the browser address bar.

## Other XSS mitigations (theory)

- **Framework auto-escaping:** template engines escape unsafe characters by default when rendering HTML text; this is used in the secure page.
- **Context-aware output encoding:** use different safe encodings for HTML text, attributes, JavaScript, and URLs; plain HTML escaping alone is not enough for every context.
- **HTML sanitization:** if an application intentionally accepts rich HTML, use a vetted sanitization library and an explicit allowed-tags/attributes policy.
- **Content Security Policy (CSP):** constrain script sources and use nonces/hashes, reducing impact as an additional layer rather than a replacement for encoding.
- **HttpOnly cookies:** prevent injected JavaScript from reading these cookies, though they do not prevent XSS itself.
- **Safe DOM sinks:** use `textContent` rather than `innerHTML` for user content in browser-side JavaScript.

## Individual ownership declaration

| Member | Roll number | Category | Variant |
| --- | --- | --- | --- |
| Shaurya Bhardwaj | IIT2024251 | Cross-Site Scripting (XSS) | Reflected XSS |

## Evidence checklist

- Screenshot of popup in the vulnerable version.
- Screenshot of harmless escaped payload in the secure version.
- Code screenshots showing vulnerable `safe` and fixed escaped interpolation.
- Live individual explanation of root cause and mitigation.

## Key viva points

**Reflected XSS:** attacker-supplied input is immediately included in an HTTP response and executed as JavaScript in a browser because the output was not safely encoded. Unlike stored XSS, it is not persisted in a database. The vulnerable sink is `{{ query | safe }}`; the implemented fix is to remove `| safe` so the template engine escapes HTML metacharacters.
