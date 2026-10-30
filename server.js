const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";

const DATA_FILE = path.join(__dirname, "data.json");
const ACCOUNTS_FILE = path.join(__dirname, "accounts.json");

const ADMIN_KEY = process.env.ADMIN_KEY || "";
const MOONPAY_API_KEY = process.env.MOONPAY_API_KEY || "";
const MOONPAY_SECRET_KEY = process.env.MOONPAY_SECRET_KEY || "";
const DESTINATION_WALLET_ADDRESS = (
  process.env.DESTINATION_WALLET_ADDRESS ||
  process.env.TRUST_WALLET_ADDRESS ||
  ""
).trim();

const BSC_RPC_URL =
  process.env.BSC_RPC_URL || "https://bsc-dataseed.bnbchain.org";

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

// --------------------------------------------------
// FILE STORAGE
// --------------------------------------------------

function readJsonFile(file, fallback = []) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJsonFile(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

function loadEntries() {
  return readJsonFile(DATA_FILE, []);
}

function saveEntries(entries) {
  writeJsonFile(DATA_FILE, entries);
}

function loadAccounts() {
  const raw = readJsonFile(ACCOUNTS_FILE, []);

  return (Array.isArray(raw) ? raw : []).map((a) => ({
    id: a.id,
    email: a.email,
    name: a.name,
    phone: a.phone,
    address: a.address,
    salt: a.salt,
    authHash: a.authHash,
    keystore: a.keystore,
    createdAt: a.createdAt,
  }));
}

function saveAccounts(accounts) {
  writeJsonFile(ACCOUNTS_FILE, accounts);
}

// --------------------------------------------------
// HTTP HELPERS
// --------------------------------------------------

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });

  res.end(JSON.stringify(data));
}

function sendHtml(res, statusCode, html) {
  res.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });

  res.end(html);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    let tooLarge = false;

    req.on("data", (chunk) => {
      body += chunk.toString();

      if (body.length > 1024 * 1024) {
        tooLarge = true;
        reject(new Error("Request body is too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (tooLarge) return;

      if (!body.trim()) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON request body"));
      }
    });

    req.on("error", reject);
  });
}

// --------------------------------------------------
// ADMIN AUTHENTICATION
// --------------------------------------------------

function isAdmin(req) {
  if (!ADMIN_KEY) return false;

  const authorization = req.headers.authorization || "";
  const bearerKey = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  const suppliedKey =
    req.headers["x-admin-key"] || bearerKey;

  if (typeof suppliedKey !== "string") return false;

  const expected = Buffer.from(ADMIN_KEY);
  const supplied = Buffer.from(suppliedKey);

  return (
    expected.length === supplied.length &&
    crypto.timingSafeEqual(expected, supplied)
  );
}

function requireAdmin(req, res) {
  if (isAdmin(req)) return true;

  sendJson(res, 401, {
    error: ADMIN_KEY
      ? "Unauthorized. Valid admin credentials are required."
      : "Admin access is not configured. Set the ADMIN_KEY environment variable.",
  });

  return false;
}

// --------------------------------------------------
// BUY URL
// --------------------------------------------------

function buildBuyUrl(address) {
  // Always use the Trust Wallet address from backend .env.
  // Ignore any address supplied by the frontend.
  const trustWallet = DESTINATION_WALLET_ADDRESS;

  if (!ADDRESS_RE.test(trustWallet)) {
    throw new Error(
      "Invalid Trust Wallet address. Check DESTINATION_WALLET_ADDRESS in your backend .env file."
    );
  }

  const url = new URL("https://buy.moonpay.com");

  if (MOONPAY_API_KEY) {
    url.searchParams.set("apiKey", MOONPAY_API_KEY);
  }

  url.searchParams.set("walletAddress", trustWallet);

  url.searchParams.set("currencyCode", "usdc");
  url.searchParams.set("baseCurrencyCode", "usd");

  return url.toString();
}
// --------------------------------------------------
// ACCOUNTS: sessions, login-key hashing, rate limiting
// --------------------------------------------------

const { promisify } = require("util");
const scrypt = promisify(crypto.scrypt);

const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const sessions = new Map(); // session token -> { accountId, expires } (memory only: a restart logs everyone out)
const failures = new Map(); // "email|ip" -> { count, resetAt }

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const AUTHKEY_RE = /^[a-f0-9]{64}$/;
const DUMMY_SALT = crypto.randomBytes(16).toString("hex");

async function hashAuthKey(authKey, saltHex) {
  const buf = await scrypt(authKey, Buffer.from(saltHex, "hex"), 64);
  return buf.toString("hex");
}

function createSession(accountId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { accountId, expires: Date.now() + SESSION_MS });
  return token;
}

function sessionFrom(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;

  const token = header.slice(7);
  const session = sessions.get(token);
  if (!session) return null;

  if (session.expires < Date.now()) {
    sessions.delete(token);
    return null;
  }

  return { token, accountId: session.accountId };
}

function tooManyFailures(key) {
  const f = failures.get(key);
  return !!f && f.resetAt > Date.now() && f.count >= 8;
}

function recordFailure(key) {
  const now = Date.now();
  const f = failures.get(key);

  if (!f || f.resetAt <= now) {
    failures.set(key, { count: 1, resetAt: now + 15 * 60 * 1000 });
  } else {
    f.count += 1;
  }
}

// --------------------------------------------------
// BNB SMART CHAIN BALANCE
// --------------------------------------------------

async function onChainBalance(address) {
  if (!ADDRESS_RE.test(address || "")) {
    throw new Error("Invalid wallet address");
  }

  const response = await fetch(BSC_RPC_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "eth_getBalance",
      params: [address, "latest"],
      id: 1,
    }),
  });

  if (!response.ok) {
    throw new Error("Unable to contact the BNB Smart Chain RPC");
  }

  const result = await response.json();

  if (result.error || !result.result) {
    throw new Error(
      result.error?.message || "Unable to retrieve wallet balance"
    );
  }

  const wei = BigInt(result.result);
  const whole = wei / 10n ** 18n;
  const remainder = wei % 10n ** 18n;

  const decimal = remainder
    .toString()
    .padStart(18, "0")
    .replace(/0+$/, "");

  const balance = decimal
    ? `${whole}.${decimal}`
    : whole.toString();

  return {
    address,
    balance,
    currency: "BNB",
    network: "BNB Smart Chain",
  };
}

// --------------------------------------------------
// BASIC ADMIN PAGE
// --------------------------------------------------

const ADMIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Wallet Admin Dashboard</title>
  <style>
    * { box-sizing: border-box; }

    body {
      margin: 0;
      padding: 24px;
      font-family: Arial, sans-serif;
      background: #f3f5f9;
      color: #172033;
    }

    main {
      max-width: 1100px;
      margin: auto;
    }

    h1 { margin-bottom: 8px; }

    .panel {
      background: white;
      padding: 20px;
      border-radius: 12px;
      margin: 20px 0;
      box-shadow: 0 3px 15px #0000000a;
      overflow-x: auto;
    }

    input, button {
      padding: 11px;
      border-radius: 6px;
      border: 1px solid #d4dae4;
      font-size: 14px;
      margin: 4px 0;
    }

    button {
      cursor: pointer;
      background: #173b81;
      border-color: #173b81;
      color: white;
    }

    table {
      border-collapse: collapse;
      width: 100%;
      min-width: 550px;
    }

    th, td {
      border-bottom: 1px solid #e7eaf0;
      padding: 12px;
      text-align: left;
      overflow-wrap: anywhere;
    }

    th { background: #f7f8fb; }

    .message { white-space: pre-wrap; }

    .danger { background: #b42318; border-color: #b42318; }

    @media (max-width: 600px) {
      body { padding: 12px; }
      .panel { padding: 14px; }
    }
  </style>
</head>
<body>
<main>
  <h1>Wallet Admin Dashboard</h1>
  <p>Manage wallet ledger entries and view account confirmation status.</p>

  <section class="panel">
    <h2>Admin access</h2>
    <input id="adminKey" type="password"
      placeholder="Enter your admin key" autocomplete="current-password">
    <button id="loadButton">Load dashboard</button>
    <p id="message" class="message"></p>
  </section>

  <section class="panel">
    <h2>Add ledger entry</h2>

    <form id="entryForm">
      <input id="address" placeholder="Wallet address (optional)">
      <input id="amount" type="number" step="any"
        min="0" placeholder="Amount" required>
      <input id="note" placeholder="Note">
      <button type="submit">Add entry</button>
    </form>
  </section>

  <section class="panel">
    <h2>Ledger entries</h2>
    <div id="entries">Load the dashboard to view entries.</div>
  </section>

  <section class="panel">
    <h2>Registered accounts</h2>
    <div id="accounts">Load the dashboard to view accounts.</div>
    <p>Passwords and recovery phrases are never stored or displayed. The server holds only an encrypted copy of each wallet.</p>
  </section>
</main>

<script>
  const keyInput = document.getElementById("adminKey");
  const message = document.getElementById("message");
  const entriesBox = document.getElementById("entries");
  const accountsBox = document.getElementById("accounts");

  function adminKey() {
    return keyInput.value.trim();
  }

  async function api(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-Admin-Key": adminKey(),
        ...(options.headers || {})
      }
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Request failed");
    }

    return data;
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, function (character) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      }[character];
    });
  }

  async function loadDashboard() {
    message.textContent = "Loading...";

    try {
      const [ledgerData, accountData] = await Promise.all([
        api("/api/admin/entries"),
        api("/api/admin/accounts")
      ]);

      entriesBox.innerHTML = ledgerData.entries.length
        ? \`<table>
            <thead><tr>
              <th>Date</th><th>Address</th><th>Amount</th>
              <th>Note</th><th>Action</th>
            </tr></thead>
            <tbody>
            \${ledgerData.entries.map(function (entry) {
              return \`<tr>
                <td>\${escapeHtml(entry.date || entry.createdAt || "")}</td>
                <td>\${escapeHtml(entry.address || "")}</td>
                <td>\${escapeHtml(entry.amount ?? 0)}</td>
                <td>\${escapeHtml(entry.note || "")}</td>
                <td><button class="danger"
                  data-delete="\${escapeHtml(entry.id)}">Delete</button></td>
              </tr>\`;
            }).join("")}
            </tbody>
          </table>\`
        : "<p>No ledger entries yet.</p>";

      accountsBox.innerHTML = accountData.accounts.length
        ? \`<table>
            <thead><tr>
              <th>Email</th><th>Name</th><th>Wallet address</th><th>Signed up</th>
            </tr></thead>
            <tbody>
            \${accountData.accounts.map(function (account) {
              return \`<tr>
                <td>\${escapeHtml(account.email || "(old entry)")}</td>
                <td>\${escapeHtml(account.name || "")}</td>
                <td>\${escapeHtml(account.address)}</td>
                <td>\${escapeHtml(account.createdAt || "")}</td>
              </tr>\`;
            }).join("")}
            </tbody>
          </table>\`
        : "<p>No registered wallet addresses yet.</p>";

      message.textContent = "Dashboard loaded.";
    } catch (error) {
      message.textContent = error.message;
    }
  }

  document.getElementById("loadButton").addEventListener("click", loadDashboard);

  document.getElementById("entryForm").addEventListener("submit", async function (event) {
    event.preventDefault();

    const address = document.getElementById("address").value.trim();
    const amount = Number(document.getElementById("amount").value);
    const note = document.getElementById("note").value.trim();

    try {
      await api("/api/admin/entries", {
        method: "POST",
        body: JSON.stringify({ address, amount, note })
      });

      message.textContent = "Ledger entry added.";
      event.target.reset();
      await loadDashboard();
    } catch (error) {
      message.textContent = error.message;
    }
  });

  document.addEventListener("click", async function (event) {
    const button = event.target.closest("[data-delete]");
    if (!button) return;

    const id = button.getAttribute("data-delete");
    if (!confirm("Delete this ledger entry?")) return;

    try {
      await api("/api/admin/entries/" + encodeURIComponent(id), {
        method: "DELETE"
      });

      message.textContent = "Ledger entry deleted.";
      await loadDashboard();
    } catch (error) {
      message.textContent = error.message;
    }
  });
</script>
</body>
</html>`;

// --------------------------------------------------
// SERVER
// --------------------------------------------------

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, DELETE, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Admin-Key"
  );

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const p = url.pathname;

  try {
    // Home page
    if (req.method === "GET" && p === "/") {
      const indexFile = path.join(__dirname, "index.html");

      if (fs.existsSync(indexFile)) {
        return sendHtml(
          res,
          200,
          fs.readFileSync(indexFile, "utf8")
        );
      }

      return sendHtml(
        res,
        200,
        "<h1>Wallet API is running</h1><p>Admin: /admin</p>"
      );
    }

    // Admin dashboard shell. All admin data APIs require an admin key.
    if (req.method === "GET" && p === "/admin") {
      return sendHtml(res, 200, ADMIN_PAGE);
    }

    // Public configuration
    if (req.method === "GET" && p === "/api/config") {
      return sendJson(res, 200, {
        network: "BNB Smart Chain",
        chainId: 56,
        currency: "BNB",
        rpcUrl: BSC_RPC_URL,
        moonpayConfigured: Boolean(MOONPAY_API_KEY),
      });
    }

    // Generate MoonPay buy URL
   if (req.method === "GET" && p === "/api/buy-url") {
  try {
    return sendJson(res, 200, {
      url: buildBuyUrl(),
    });
  } catch (error) {
    return sendJson(res, 500, {
      error: error.message,
    });
  }
}

    // Public ledger
    if (req.method === "GET" && p === "/api/ledger") {
      return sendJson(res, 200, {
        entries: loadEntries(),
      });
    }

    // On-chain BNB balance
    if (req.method === "GET" && p === "/api/chain-balance") {
      const address = url.searchParams.get("address") || "";

      try {
        const balance = await onChainBalance(address);
        return sendJson(res, 200, balance);
      } catch (error) {
        return sendJson(res, 400, {
          error: error.message,
        });
      }
    }

    // Sign a MoonPay URL using the server-side secret
    if (req.method === "POST" && p === "/api/moonpay-sign") {
      if (!MOONPAY_SECRET_KEY) {
        return sendJson(res, 503, {
          error: "MoonPay signing is not configured on the server",
        });
      }

      const body = await readBody(req);
      const requestedUrl = String(body.url || "");

      // MoonPay signs only the query string (starting with "?"), not the host or the path.
      let search;

      if (requestedUrl.startsWith("?")) {
        search = requestedUrl;
      } else {
        let parsedUrl;

        try {
          parsedUrl = new URL(requestedUrl);
        } catch {
          return sendJson(res, 400, {
            error: "A valid MoonPay URL is required",
          });
        }

        if (
          parsedUrl.protocol !== "https:" ||
          !/(^|\.)moonpay\.com$/.test(parsedUrl.hostname)
        ) {
          return sendJson(res, 400, {
            error: "Only valid MoonPay HTTPS URLs can be signed",
          });
        }

        search = parsedUrl.search;
      }

      // The publishable key in the URL must match the secret key's environment (test or live).
      const apiKey = new URLSearchParams(search).get("apiKey") || "";
      const expectedPrefix = MOONPAY_SECRET_KEY.startsWith("sk_live_")
        ? "pk_live_"
        : "pk_test_";

      if (!apiKey.startsWith(expectedPrefix)) {
        return sendJson(res, 400, {
          error: "The API key in the URL does not match the secret key's environment",
        });
      }

      const payload = search;

      const signature = crypto
        .createHmac("sha256", MOONPAY_SECRET_KEY)
        .update(payload)
        .digest("base64");

      return sendJson(res, 200, { signature });
    }

    // Return credits for one wallet address
const creditsMatch = p.match(
  /^\/api\/credits\/(0x[a-fA-F0-9]{40})$/
);

if (req.method === "GET" && creditsMatch) {
  const session = sessionFrom(req);

  if (!session) {
    return sendJson(res, 401, {
      error: "Please log in to view your credits.",
    });
  }

  const accounts = loadAccounts();

  const account = accounts.find(
    (a) => a.id === session.accountId
  );

  const address = creditsMatch[1].toLowerCase();

  if (
    !account ||
    account.address.toLowerCase() !== address
  ) {
    return sendJson(res, 403, {
      error: "You cannot access this account's credits.",
    });
  }

  const mine = loadEntries()
    .filter(
      (entry) =>
        String(entry.address || "").toLowerCase() === address
    )
    .sort(
      (a, b) =>
        new Date(b.date).getTime() -
        new Date(a.date).getTime()
    );

  const total = mine.reduce((sum, entry) => {
    const amount = Number(entry.amount);
    return sum + (Number.isFinite(amount) ? amount : 0);
  }, 0);

  return sendJson(res, 200, {
    address,
    total: total.toFixed(2),
    entries: mine.map((entry) => ({
      id: entry.id,
      amount: entry.amount,
      note: entry.note,
      date: entry.date,
    })),
  });
}

    // ── Accounts ──
    // Sign up: the browser sends the email, a login key derived from the password (never the
    // password itself), the public address, and the wallet already encrypted with the password.
    if (req.method === "POST" && p === "/api/auth/signup") {
      const body = await readBody(req);
      const email = String(body.email || "").trim().toLowerCase();
      const authKey = String(body.authKey || "");
      const address = String(body.address || "").trim().toLowerCase();
      const keystoreRaw = typeof body.keystore === "string" ? body.keystore : "";

      if (!EMAIL_RE.test(email)) {
        return sendJson(res, 400, { error: "Enter a valid email address" });
      }

      if (!AUTHKEY_RE.test(authKey)) {
        return sendJson(res, 400, { error: "Invalid request" });
      }

      if (!ADDRESS_RE.test(address)) {
        return sendJson(res, 400, { error: "A valid wallet address is required" });
      }

      let ks;

      try {
        ks = JSON.parse(keystoreRaw);
      } catch {
        return sendJson(res, 400, { error: "Invalid wallet data" });
      }

      const ksAddr = String((ks && ks.address) || "").toLowerCase().replace(/^0x/, "");

      if (!ks || !(ks.crypto || ks.Crypto) || ksAddr !== address.slice(2)) {
        return sendJson(res, 400, { error: "Wallet data does not match the address" });
      }

      const accounts = loadAccounts();

      if (accounts.some((a) => a.email === email)) {
        return sendJson(res, 409, {
          error: "An account with this email already exists. Log in instead.",
        });
      }

      if (accounts.some((a) => a.address === address)) {
        return sendJson(res, 409, { error: "This wallet is already registered" });
      }

      const salt = crypto.randomBytes(16).toString("hex");

      const account = {
        id: crypto.randomUUID(),
        email,
        name: String(body.name || "").trim().slice(0, 100),
        phone: String(body.phone || "").trim().slice(0, 30),
        address,
        salt,
        authHash: await hashAuthKey(authKey, salt),
        keystore: keystoreRaw,
        createdAt: new Date().toISOString(),
      };

      accounts.push(account);
      saveAccounts(accounts);

      return sendJson(res, 201, { token: createSession(account.id), address });
    }

    // Log in: checks the login key, then hands back the ENCRYPTED wallet. The browser decrypts it.
    if (req.method === "POST" && p === "/api/auth/login") {
      const body = await readBody(req);
      const email = String(body.email || "").trim().toLowerCase();
      const authKey = String(body.authKey || "");
      const limitKey = email + "|" + (req.socket.remoteAddress || "");

      if (tooManyFailures(limitKey)) {
        return sendJson(res, 429, {
          error: "Too many attempts. Please wait a few minutes and try again.",
        });
      }

      const keyOk = AUTHKEY_RE.test(authKey);
      const account = keyOk
        ? loadAccounts().find((a) => a.email === email && a.authHash)
        : null;

      // Always do the same amount of work, so timing doesn't reveal whether an email exists.
      const hash = await hashAuthKey(
        keyOk ? authKey : "0".repeat(64),
        account ? account.salt : DUMMY_SALT
      );

      const ok =
        !!account &&
        crypto.timingSafeEqual(
          Buffer.from(hash, "hex"),
          Buffer.from(account.authHash, "hex")
        );

      if (!ok) {
        recordFailure(limitKey);
        return sendJson(res, 401, { error: "Incorrect email or password" });
      }

      failures.delete(limitKey);

      return sendJson(res, 200, {
        token: createSession(account.id),
        address: account.address,
        keystore: account.keystore,
      });
    }

    if (req.method === "GET" && p === "/api/auth/me") {
      const session = sessionFrom(req);
      const account = session && loadAccounts().find((a) => a.id === session.accountId);

      if (!account) return sendJson(res, 401, { error: "Not logged in" });

      return sendJson(res, 200, {
        address: account.address,
        email: account.email,
        name: account.name,
      });
    }

    if (req.method === "POST" && p === "/api/auth/logout") {
      const session = sessionFrom(req);
      if (session) sessions.delete(session.token);

      return sendJson(res, 200, { ok: true });
    }

    // Admin: list accounts. Fields are picked one by one, so the login hash, salt and
    // encrypted wallet never leave the server.
    if (req.method === "GET" && p === "/api/admin/accounts") {
      if (!requireAdmin(req, res)) return;

      const accounts = loadAccounts().map(({ id, email, name, address, createdAt }) => ({
        id,
        email,
        name,
        address,
        createdAt,
      }));

      return sendJson(res, 200, { accounts });
    }

    // Admin: list ledger entries
    if (req.method === "GET" && p === "/api/admin/entries") {
      if (!requireAdmin(req, res)) return;

      return sendJson(res, 200, {
        entries: loadEntries(),
      });
    }

    // Admin: create ledger entry
    if (req.method === "POST" && p === "/api/admin/entries") {
      if (!requireAdmin(req, res)) return;

      const body = await readBody(req);
      const amount = Number(body.amount);
      const address = String(body.address || "").trim();
      const note = String(body.note || "").trim();

      if (!Number.isFinite(amount) || amount < 0) {
        return sendJson(res, 400, {
          error: "Enter a valid, non-negative amount",
        });
      }

      if (address && !ADDRESS_RE.test(address)) {
        return sendJson(res, 400, {
          error: "Enter a valid wallet address or leave the field empty",
        });
      }

      const entries = loadEntries();

      const entry = {
        id: crypto.randomUUID(),
        address: address.toLowerCase(),
        amount,
        note,
        date: new Date().toISOString(),
      };

      entries.push(entry);
      saveEntries(entries);

      return sendJson(res, 201, {
        ok: true,
        entry,
      });
    }

    // Admin: delete ledger entry
    const deleteMatch = p.match(/^\/api\/admin\/entries\/([^/]+)$/);

    if (req.method === "DELETE" && deleteMatch) {
      if (!requireAdmin(req, res)) return;

      const id = decodeURIComponent(deleteMatch[1]);
      const entries = loadEntries();
      const updatedEntries = entries.filter(
        (entry) => entry.id !== id
      );

      if (updatedEntries.length === entries.length) {
        return sendJson(res, 404, {
          error: "Ledger entry not found",
        });
      }

      saveEntries(updatedEntries);

      return sendJson(res, 200, {
        ok: true,
      });
    }

    return sendJson(res, 404, {
      error: "Route not found",
    });
  } catch (error) {
    console.error("Server error:", error.message);

    if (!res.headersSent) {
      return sendJson(res, 500, {
        error: error.message || "Internal server error",
      });
    }
  }
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

server.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
  console.log(`Admin dashboard: http://${HOST}:${PORT}/admin`);

  if (!ADMIN_KEY) {
    console.warn(
      "WARNING: ADMIN_KEY is not set. Admin API access is disabled."
    );
  }
});