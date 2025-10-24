#!/usr/bin/env node
// scan.js
// Usage examples (see below in README section)
// Node dependencies: puppeteer, isomorphic-dompurify, jsdom (installed by instructions)

const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');

function readPayloads(file) {
  return fs.readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .map(s => s.trim())
    .filter(Boolean);
}

function usage() {
  console.log(`
Usage:
  node scan.js --mode param --url "http://example.com/search?q=PAYLOAD" --payloads payloads.txt
  node scan.js --mode inject --url "http://example.com" --payloads payloads.txt
  Optional:
    --wait <ms>        (default 1000) time to wait after injection before checking
    --out <file>       (default results.json)
  Notes:
    - For param mode, script will replace the string "PAYLOAD" in the URL with each payload (URL-encoded).
    - For inject mode, the script opens the page, adds DOMPurify to the page, then injects raw payload and sanitized payload into an isolated div,
      overriding window.alert to detect if scripts executed.
  `);
}

(async () => {
  const argv = require('minimist')(process.argv.slice(2));
  if (!argv.mode || !argv.url || !argv.payloads) {
    usage();
    process.exit(1);
  }
  const mode = argv.mode;
  const url = argv.url;
  const payloadFile = argv.payloads;
  const waitMs = parseInt(argv.wait || '1000', 10);
  const outFile = argv.out || 'results.json';

  if (!fs.existsSync(payloadFile)) {
    console.error('Payload file not found:', payloadFile);
    process.exit(2);
  }

  const payloads = readPayloads(payloadFile);

  const browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'] });
  const page = await browser.newPage();
  // make alert() observable
  await page.exposeFunction('__node_alert_hook', (message) => {
    // will be caught in page.evaluate via window.__node_alert_called = true
    // but exposeFunction ensures the function exists if needed
  });

  const results = [];

  if (mode === 'param') {
    console.log('[*] Running param-mode tests:', payloads.length, 'payloads');
    for (const payload of payloads) {
      const encoded = encodeURIComponent(payload);
      const target = url.replace(/PAYLOAD/g, encoded);
      console.log('-> Testing URL:', target);
      try {
        const resp = await page.goto(target, { waitUntil: 'networkidle2', timeout: 30000 });
        const status = resp ? resp.status() : 'no-response';
        // simple detection: check if response contains payload (raw) and sanitized inference by running DOMPurify in page
        // inject DOMPurify (CDN)
        await page.addScriptTag({ url: 'https://unpkg.com/dompurify@2.4.0/dist/purify.min.js' });
        const sanitizeResult = await page.evaluate((pl) => {
          try {
            if (typeof DOMPurify === 'undefined') return { error: 'DOMPurify-not-loaded' };
            const clean = DOMPurify.sanitize(pl);
            // sniff whether the page contains the raw payload in HTML text
            const bodyContains = document.documentElement.outerHTML.includes(pl);
            return { clean, bodyContains };
          } catch (e) {
            return { error: e.message };
          }
        }, payload);
        results.push({ mode: 'param', payload, target, status, sanitizeResult });
      } catch (err) {
        console.error('  ! Error testing', target, err.message);
        results.push({ mode: 'param', payload, target, error: err.message });
      }
    }
  } else if (mode === 'inject') {
    console.log('[*] Running inject-mode tests against URL:', url);
    // open target page once (reopened for each payload to reset state)
    for (const payload of payloads) {
      console.log('-> payload:', payload);
      try {
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
        // add DOMPurify
        await page.addScriptTag({ url: 'https://unpkg.com/dompurify@2.4.0/dist/purify.min.js' });

        // prepare: override alert, create sandbox div
        await page.evaluate(() => {
          window.__alerted = false;
          window.alert = function(msg) {
            window.__alerted = true;
            // keep original behavior suppressed (so no popup)
            console.log('alert called:', msg);
          };
          // create isolated sandbox
          let s = document.getElementById('__dompurify_scan_sandbox');
          if (s) s.remove();
          s = document.createElement('div');
          s.id = '__dompurify_scan_sandbox';
          // keep it off-screen
          s.style.position = 'absolute';
          s.style.left = '-9999px';
          document.body.appendChild(s);
        });

        // test raw injection
        const rawResult = await page.evaluate(async (pl) => {
          window.__alerted = false;
          const s = document.getElementById('__dompurify_scan_sandbox');
          // assign raw to innerHTML (sink to test)
          try {
            s.innerHTML = pl;
          } catch (e) {
            // innerHTML assignment error
            return { error: 'innerHTML-assign-error:' + e.message, alerted: !!window.__alerted };
          }
          // give any possible scripts/mutation a tick
          await new Promise(res => setTimeout(res, 50));
          return { alerted: !!window.__alerted, html: s.innerHTML.slice(0, 200) };
        }, payload);

        // test sanitized injection
        const cleanResult = await page.evaluate(async (pl) => {
          if (typeof DOMPurify === 'undefined') return { error: 'DOMPurify-not-loaded' };
          window.__alerted = false;
          const s = document.getElementById('__dompurify_scan_sandbox');
          const clean = DOMPurify.sanitize(pl);
          try {
            s.innerHTML = clean;
          } catch (e) {
            return { error: 'innerHTML-assign-error:' + e.message, clean, alerted: !!window.__alerted };
          }
          await new Promise(res => setTimeout(res, 50));
          return { clean, alerted: !!window.__alerted, html: s.innerHTML.slice(0,200) };
        }, payload);

        results.push({
          mode: 'inject',
          payload,
          rawResult,
          cleanResult
        });

        // small wait to avoid being too aggressive
        await page.waitForTimeout( Math.min(500, parseInt(1000)) );
      } catch (err) {
        console.error('  ! Error on payload', payload, err.message);
        results.push({ mode: 'inject', payload, error: err.message });
      }
    }
  } else {
    console.error('Unknown mode:', mode);
    usage();
    await browser.close();
    process.exit(3);
  }

  await browser.close();

  fs.writeFileSync(outFile, JSON.stringify(results, null, 2));
  console.log('[*] Done. Results saved to', outFile);
})();
