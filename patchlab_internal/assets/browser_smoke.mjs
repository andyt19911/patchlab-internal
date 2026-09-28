// PatchLab Internal browser smoke check: load each route of a web app in a
// headless Chromium (a sidecar) and report, per route, as TAP:
//   - "<route> renders": the page's mount point has content once it settles;
//   - "<route> has no uncaught errors": no exception reached the top level.
// It gives a UI with no tests of its own a runtime check a typecheck can't:
// a dependency upgrade that breaks rendering fails here.
//
// Plain Node (18+), no dependencies: the Chrome DevTools Protocol over a
// minimal WebSocket client, so nothing is installed into the app under test.
//
// usage: node browser_smoke.mjs --url http://app:4173 --browser browser:9222
//                               [--root '#root'] [--settle 1500] route ...

import dns from "node:dns/promises";
import http from "node:http";
import crypto from "node:crypto";

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  if (i < 0) return dflt;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
};
let base = opt("url", "http://app:4173").replace(/\/$/, "");
const browser = opt("browser", "browser:9222");
const rootSel = opt("root", "#root");
const settle = Number(opt("settle", "1500"));
const waitFor = Number(opt("wait", "60"));
const routes = args.length ? args : ["/"];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Chrome answers DevTools HTTP requests only when the Host header is an IP
// address or localhost, so resolve the sidecar's name first.
async function endpoint() {
  const [host, port] = browser.split(":");
  const { address } = await dns.lookup(host, { family: 4 });
  return { host: address, port: Number(port || 9222) };
}

function httpJson(ep, method, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: ep.host, port: ep.port, method, path }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try { resolve(JSON.parse(body)); } catch (e) { reject(new Error(`${path}: ${body.slice(0, 200)}`)); }
      });
    });
    req.on("error", reject);
    req.setTimeout(10000, () => req.destroy(new Error(`${path}: timed out`)));
    req.end();
  });
}

// A minimal WebSocket client (RFC 6455): text frames, client-side masking.
function websocket(url) {
  const u = new URL(url);
  const key = crypto.randomBytes(16).toString("base64");
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: u.hostname, port: u.port, path: u.pathname,
      headers: { Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key },
    });
    req.on("error", reject);
    req.on("response", (res) => reject(new Error(`websocket refused: HTTP ${res.statusCode}`)));
    req.on("upgrade", (_res, socket) => {
      let buf = Buffer.alloc(0);
      const listeners = [];
      socket.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        for (;;) {
          if (buf.length < 2) return;
          let len = buf[1] & 0x7f, off = 2;
          if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
          else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
          if (buf.length < off + len) return;
          const op = buf[0] & 0x0f, payload = buf.subarray(off, off + len);
          buf = buf.subarray(off + len);
          if (op === 1) listeners.forEach((f) => f(payload.toString("utf8")));
        }
      });
      const send = (text) => {
        const data = Buffer.from(text, "utf8"), mask = crypto.randomBytes(4);
        const head = data.length < 126 ? Buffer.from([0x81, 0x80 | data.length])
          : data.length < 65536 ? Buffer.from([0x81, 0x80 | 126, data.length >> 8, data.length & 0xff])
          : (() => { const h = Buffer.alloc(10); h[0] = 0x81; h[1] = 0x80 | 127; h.writeBigUInt64BE(BigInt(data.length), 2); return h; })();
        for (let i = 0; i < data.length; i++) data[i] ^= mask[i % 4];
        socket.write(Buffer.concat([head, mask, data]));
      };
      resolve({ send, onMessage: (f) => listeners.push(f), close: () => socket.destroy() });
    });
    req.end();
  });
}

async function cdp(wsUrl) {
  const ws = await websocket(wsUrl);
  let id = 0;
  const pending = new Map(), handlers = [];
  ws.onMessage((text) => {
    const msg = JSON.parse(text);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
    } else if (msg.method) handlers.forEach((h) => h(msg));
  });
  return {
    call: (method, params = {}) => new Promise((resolve, reject) => {
      pending.set(++id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    }),
    on: (h) => handlers.push(h),
    close: () => ws.close(),
  };
}

// Dev servers refuse unknown Host headers (Vite's allowedHosts), and an IP
// address is always allowed, so the app is addressed by IP too.
async function resolveBase() {
  const u = new URL(base);
  if (!/^[\d.]+$/.test(u.hostname)) {
    u.hostname = (await dns.lookup(u.hostname, { family: 4 })).address;
    base = u.toString().replace(/\/$/, "");
  }
}

async function waitForApp() {
  const deadline = Date.now() + waitFor * 1000;
  let last = "no answer";
  for (;;) {
    try {
      await new Promise((resolve, reject) => {
        http.get(base + "/", (res) => {
          res.resume();
          last = `HTTP ${res.statusCode}`;
          res.statusCode < 400 ? resolve() : reject(new Error(last));
        }).on("error", (e) => { last = e.message; reject(e); });
      });
      return;
    } catch {
      if (Date.now() > deadline) throw new Error(`the app did not answer at ${base} within ${waitFor}s (${last})`);
      await sleep(500);
    }
  }
}

async function main() {
  await resolveBase();
  await waitForApp();
  const ep = await endpoint();
  const target = await httpJson(ep, "PUT", "/json/new?about:blank");
  const page = await cdp(target.webSocketDebuggerUrl.replace(/\/\/[^/]+/, `//${ep.host}:${ep.port}`));
  let errors = [];
  page.on((m) => {
    if (m.method === "Runtime.exceptionThrown") {
      const d = m.params.exceptionDetails;
      errors.push((d.exception && d.exception.description) || d.text);
    }
  });
  await page.call("Runtime.enable");
  await page.call("Page.enable");

  console.log("TAP version 13");
  console.log(`1..${routes.length * 2}`);
  let n = 0, failed = 0;
  for (const route of routes) {
    errors = [];
    await page.call("Page.navigate", { url: base + route });
    await sleep(settle);
    const res = await page.call("Runtime.evaluate", {
      expression: `(() => { const el = document.querySelector(${JSON.stringify(rootSel)});
                     return el ? el.innerText.trim().length + el.childElementCount : -1; })()`,
      returnByValue: true,
    });
    const size = res.result.value;
    const renders = typeof size === "number" && size > 0;
    console.log(`${renders ? "ok" : "not ok"} ${++n} - ${route} renders`);
    if (!renders) {
      failed++;
      console.log(`  # ${size < 0 ? `no ${rootSel} element` : `${rootSel} is empty`}`);
    }
    const clean = errors.length === 0;
    console.log(`${clean ? "ok" : "not ok"} ${++n} - ${route} has no uncaught errors`);
    if (!clean) {
      failed++;
      errors.slice(0, 3).forEach((e) => console.log(`  # ${String(e).split("\n")[0]}`));
    }
  }
  page.close();
  await httpJson(ep, "GET", `/json/close/${target.id}`).catch(() => {});
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.log(`Bail out! ${e.message}`);
  process.exit(2);
});
