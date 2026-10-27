# Demo narration (2–3 minutes)

Hello, my vulnerability category is Cross-Site Scripting, or XSS. I implemented the **reflected XSS** variant using a Flask application with a search form.

In reflected XSS, a value provided in an HTTP request is included in the immediate HTML response. If it is inserted into an unsafe output context, the browser can interpret malicious HTML or JavaScript as executable code.

First, I open the vulnerable page and search for `hello`. The page prints my search phrase. Now I enter `<script>alert('XSS Demo')</script>`. The browser executes this script and an alert appears. This demonstrates successful XSS against our own local demo app.

The root cause is in the `vulnerable.html` template. The `query` value comes from the GET parameter `q` in `app.py`. The template uses `{{ query | safe }}`, which explicitly disables automatic HTML escaping. As a result, the browser treats the search term as HTML and JavaScript.

Now I open the secure page. I use exactly the same payload. The popup no longer appears; instead, the text is displayed literally. In `secure.html`, we use `{{ query }}` without the `safe` filter, so Jinja escapes unsafe HTML characters. This is our implemented mitigation: context-appropriate output encoding for an HTML text node.

Other XSS defenses include sanitization for allowed HTML, a restrictive Content Security Policy, safe browser DOM APIs, and HttpOnly cookies that reduce certain consequences of XSS. These are complementary defenses, not substitutes for appropriate escaping.

This completes my demonstration of the vulnerability, the exploit, its root cause, and the mitigation.
