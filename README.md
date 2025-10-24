# DOMPurify

Nice — below I’ll give you a ready-to-run, Kali-friendly automation tool (Node.js) that uses **Puppeteer** + **DOMPurify** to test payloads against *any* website. It works two ways:

* **param-mode**: replace a `PAYLOAD` token inside a URL (useful for testing query parameters).
* **inject-mode**: open the page, inject payloads into a safe sandbox `div` via `innerHTML`, and detect whether `alert()` (or script execution) fires — it compares raw payload vs DOMPurify-sanitized payload.

**Important legal note:** only run this against systems you own or have explicit permission to test. Unauthorized scanning/attacks are illegal.

---

# 1) Install (Kali)

Open a terminal and run:

```bash
sudo apt update
sudo apt install -y nodejs npm
mkdir dompurify-scanner && cd dompurify-scanner
npm init -y
npm install puppeteer isomorphic-dompurify jsdom
```

Puppeteer will download Chromium; if you prefer the system Chrome, see Puppeteer docs — but the above works out-of-the-box on Kali.

---



**Note:** The script uses `minimist` for argument parsing — if not installed, install with:

```bash
npm install minimist
```

(Or you can edit the script to not depend on it; using `minimist` is convenient.)

---

# 3) Create `payloads.txt`

Example `payloads.txt` (one per line):

```
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
<svg onload=alert(1)>
"><img src=x onerror=alert(1)>
```

---

# 4) Run examples

Param mode (replace `PAYLOAD` in URL):

```bash
node scan.js --mode param --url "http://vulnerable.test/search?q=PAYLOAD" --payloads payloads.txt --out param-results.json
```

Inject mode (open page, inject payloads into sandbox):

```bash
node scan.js --mode inject --url "http://vulnerable.test/page" --payloads payloads.txt --out inject-results.json
```

After run, open the JSON results file to see for each payload whether the **raw** injection triggered `alert()` (indicating execution) and whether the **sanitised** injection (DOMPurify.sanitize) triggered execution. The script also records the sanitized string (trimmed) for inspection.

---

# 5) How to interpret results (quick)

* `rawResult.alerted === true` — raw payload executed in the page sink (vulnerable to DOM XSS at that injection point).
* `cleanResult.alerted === false` — DOMPurify prevented immediate script execution for that payload in the tested sink.
* If `cleanResult.alerted === true` — DOMPurify configuration or page behavior may still allow execution; investigate the `clean` string and the sink (or other scripts rewriting DOM).
* If the page itself modified or escaped your payload before you injected (param-mode), `bodyContains` in results helps show if payload made it into page HTML.

---

# 6) Next-level automation tips

* Use a list of target URLs and loop the script from a shell to scan many hosts (again — only with permission).
* Integrate with Burp: use Burp to replay captured requests, fetch the rendered HTML, then run DOMPurify locally to see what would be stripped.
* If you need to detect other sinks (e.g., `setAttribute`, `src`, `href`, `location.hash` usage), adapt the `page.evaluate` to recreate the exact sink semantics (e.g., `el.setAttribute('href', pl)`).
* For large-scale crawling, consider building a crawler that finds inputs (forms, query params, hash) and programmatically calls this script for each injection point.

---

If you want, I can:

* produce a trimmed version with no extra dependencies (remove `minimist`) and a step-by-step run output example, or
* convert this to a small Dockerfile to run consistently in an isolated container.

Which would you like me to produce now?
