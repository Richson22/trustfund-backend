
require("dotenv").config();

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { promisify } = require("util");
const { MongoClient } = require("mongodb");

// ==================================================
// CONFIGURATION
// ==================================================

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const ADMIN_KEY = process.env.ADMIN_KEY || "";

const MONGODB_URI = process.env.MONGODB_URI || "";
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || "trustfund";

const MOONPAY_API_KEY = process.env.MOONPAY_API_KEY || "";
const MOONPAY_SECRET_KEY = process.env.MOONPAY_SECRET_KEY || "";

const DESTINATION_WALLET_ADDRESS = (
  process.env.DESTINATION_WALLET_ADDRESS ||
  process.env.TRUST_WALLET_ADDRESS ||
  ""
).trim();

const BSC_RPC_URL =
  process.env.BSC_RPC_URL ||
  "https://bsc-dataseed.bnbchain.org";

// Set this in Render to your actual Vercel domain.
// Multiple origins can be separated by commas.
const FRONTEND_ORIGINS = (
  process.env.FRONTEND_ORIGIN || "*"
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const AUTHKEY_RE = /^[a-f0-9]{64}$/i;

const MAX_BODY_BYTES = 12 * 1024 * 1024;

const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 8;
const LOGIN_LOCK_MS = 15 * 60 * 1000;

const scrypt = promisify(crypto.scrypt);

// ==================================================
// MONGODB
// ==================================================

let mongoClient;
let accountsCollection;
let entriesCollection;

async function connectDatabase() {
  if (!MONGODB_URI) {
    throw new Error(
      "MONGODB_URI is missing from Render environment variables."
    );
  }

  mongoClient = new MongoClient(MONGODB_URI, {
    serverSelectionTimeoutMS: 15000,
  });

  await mongoClient.connect();

  const database = mongoClient.db();

  accountsCollection = database.collection("accounts");
  entriesCollection = database.collection("ledgerEntries");

  await accountsCollection.createIndex(
    { email: 1 },
    { unique: true }
  );

  await accountsCollection.createIndex(
    { address: 1 },
    { unique: true }
  );

  await entriesCollection.createIndex({
    address: 1,
    date: -1,
  });

  await entriesCollection.createIndex(
    { id: 1 },
    { unique: true }
  );

  console.log("MongoDB connected successfully.");
 
}

// ==================================================
// SESSIONS AND LOGIN SECURITY
// ==================================================

// Sessions are stored in memory for seven days.
// Restarting Render logs users out of the server.
const sessions = new Map();

// Failed attempts are also memory-only.
const failures = new Map();

const DUMMY_SALT = crypto.randomBytes(16).toString("hex");

async function hashAuthKey(authKey, saltHex) {
  const buffer = await scrypt(
    authKey,
    Buffer.from(saltHex, "hex"),
    64
  );

  return buffer.toString("hex");
}

function createSession(accountId) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    accountId,
    expires: Date.now() + SESSION_MS,
  });

  return token;
}

function sessionFrom(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.slice(7);
  const session = sessions.get(token);

  if (!session) return null;

  if (session.expires <= Date.now()) {
    sessions.delete(token);
    return null;
  }

  return {
    token,
    accountId: session.accountId,
  };
}

function removeExpiredSessions() {
  const now = Date.now();

  for (const [token, session] of sessions.entries()) {
    if (session.expires <= now) {
      sessions.delete(token);
    }
  }
}

function tooManyFailures(key) {
  const failure = failures.get(key);

  return Boolean(
    failure &&
    failure.resetAt > Date.now() &&
    failure.count >= LOGIN_MAX_ATTEMPTS
  );
}

function recordFailure(key) {
  const now = Date.now();
  const failure = failures.get(key);

  if (!failure || failure.resetAt <= now) {
    failures.set(key, {
      count: 1,
      resetAt: now + LOGIN_LOCK_MS,
    });
  } else {
    failure.count += 1;
  }

  // Prevent the in-memory map from growing indefinitely.
  if (failures.size > 10000) {
    for (const [storedKey, value] of failures.entries()) {
      if (value.resetAt <= now) {
        failures.delete(storedKey);
      }
    }
  }
}

// ==================================================
// ADMIN AUTHENTICATION
// ==================================================

function isAdmin(req) {
  if (!ADMIN_KEY) return false;

  const authorization =
    req.headers.authorization || "";

  const bearerKey = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  const suppliedKey =
    req.headers["x-admin-key"] || bearerKey;

  if (typeof suppliedKey !== "string") {
    return false;
  }

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
      : "Admin access is not configured.",
  });

  return false;
}

// ==================================================
// PUBLIC ACCOUNT DETAILS
// ==================================================

function publicAccount(account) {
  return {
    id: account.id,
    name: account.name,
    email: account.email,
    phone: account.phone,
    address: account.address,
    createdAt: account.createdAt,
  };
}

// ==================================================
// HTTP HELPERS
// ==================================================

function sendJson(res, statusCode, data) {
  if (res.destroyed || res.headersSent) return;

  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });

  res.end(JSON.stringify(data));
}

function sendHtml(res, statusCode, html) {
  if (res.destroyed || res.headersSent) return;

  res.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });

  res.end(html);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;

    req.on("data", (chunk) => {
      if (settled) return;

      size += chunk.length;

      if (size > MAX_BODY_BYTES) {
        settled = true;

        const error = new Error(
          "Request body is too large."
        );

        error.statusCode = 413;

        reject(error);
        req.resume();
        return;
      }

      chunks.push(chunk);
    });

    req.on("end", () => {
      if (settled) return;

      const body = Buffer.concat(chunks).toString("utf8");

      if (!body.trim()) {
        settled = true;
        return resolve({});
      }

      try {
        const parsed = JSON.parse(body);
        settled = true;
        resolve(parsed);
      } catch {
        settled = true;

        const error = new Error("Invalid JSON request body.");
        error.statusCode = 400;

        reject(error);
      }
    });

    req.on("error", (error) => {
      if (settled) return;

      settled = true;
      reject(error);
    });
  });
}

// ==================================================
// CORS
// ==================================================

function applyCors(req, res) {
  const origin = req.headers.origin || "";

  if (FRONTEND_ORIGINS.includes("*")) {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (
    origin &&
    FRONTEND_ORIGINS.includes(origin)
  ) {
    res.setHeader(
      "Access-Control-Allow-Origin",
      origin
    );
  }

  res.setHeader("Vary", "Origin");

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, DELETE, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Admin-Key"
  );

  res.setHeader("Access-Control-Max-Age", "86400");
}

// ==================================================
// PURCHASE URL
// ==================================================

function buildBuyUrl() {
  const trustWallet = DESTINATION_WALLET_ADDRESS;

  if (!ADDRESS_RE.test(trustWallet)) {
    throw new Error(
      "Invalid Trust Wallet destination. Check DESTINATION_WALLET_ADDRESS in Render."
    );
  }

  const url = new URL("https://buy.moonpay.com");

  if (MOONPAY_API_KEY) {
    url.searchParams.set("apiKey", MOONPAY_API_KEY);
  }

  // Always use your configured destination wallet.
  // Ignore wallet addresses supplied by frontend requests.
  url.searchParams.set("walletAddress", trustWallet);

  url.searchParams.set("currencyCode", "usdc");
  url.searchParams.set("baseCurrencyCode", "usd");

  return url.toString();
}

// ==================================================
// BNB SMART CHAIN BALANCE
// ==================================================

async function onChainBalance(address) {
  if (!ADDRESS_RE.test(address || "")) {
    throw new Error("Invalid wallet address.");
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
    throw new Error(
      "Unable to contact the BNB Smart Chain RPC."
    );
  }

  const result = await response.json();

  if (result.error || !result.result) {
    throw new Error(
      result.error?.message ||
      "Unable to retrieve wallet balance."
    );
  }

  const wei = BigInt(result.result);
  const whole = wei / 10n ** 18n;
  const remainder = wei % 10n ** 18n;

  const decimal = remainder
    .toString()
    .padStart(18, "0")
    .replace(/0+$/, "");

  return {
    address,
    balance: decimal
      ? `${whole}.${decimal}`
      : whole.toString(),
    currency: "BNB",
    network: "BNB Smart Chain",
  };
}

// ==================================================
// ADMIN PAGE
// ==================================================

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
      min-width: 650px;
    }

    th, td {
      border-bottom: 1px solid #e7eaf0;
      padding: 12px;
      text-align: left;
      overflow-wrap: anywhere;
    }

    th { background: #f7f8fb; }

    .message {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }

    .danger {
      background: #b42318;
      border-color: #b42318;
    }

    @media (max-width: 600px) {
      body { padding: 12px; }
      .panel { padding: 14px; }
    }
  </style>
</head>

<body>
<main>
  <h1>Wallet Admin Dashboard</h1>
  <p>Manage registered accounts and internal account credits.</p>

  <section class="panel">
    <h2>Admin access</h2>

    <input
      id="adminKey"
      type="password"
      placeholder="Enter your admin key"
      autocomplete="current-password"
    >

    <button id="loadButton">Load dashboard</button>

    <p id="message" class="message"></p>
  </section>

  <section class="panel">
    <h2>Registered accounts</h2>
    <div id="accounts">Enter your admin key to load accounts.</div>
  </section>

  <section class="panel">
    <h2>Add account credit</h2>

    <form id="entryForm">
      <input
        id="address"
        placeholder="Account wallet address"
        required
      >

      <input
        id="amount"
        type="number"
        step="any"
        min="0.000001"
        placeholder="Credit amount in USD"
        required
      >

      <input
        id="note"
        placeholder="Credit note"
      >

      <button type="submit">Add credit</button>
    </form>
  </section>

  <section class="panel">
    <h2>Account credit ledger</h2>
    <div id="entries">Load dashboard to view credits.</div>
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

  async function loadDashboard() {
    message.textContent = "Loading dashboard...";

    try {
      const [ledgerData, accountData] = await Promise.all([
        api("/api/admin/entries"),
        api("/api/admin/accounts")
      ]);

      accountsBox.innerHTML = accountData.accounts.length
        ? \`<table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Phone</th>
                <th>Wallet Address</th>
                <th>Registration Date</th>
              </tr>
            </thead>
            <tbody>
              \${accountData.accounts.map(function (account) {
                return \`<tr>
                  <td>\${escapeHtml(account.name)}</td>
                  <td>\${escapeHtml(account.email)}</td>
                  <td>\${escapeHtml(account.phone)}</td>
                  <td>\${escapeHtml(account.address)}</td>
                  <td>\${escapeHtml(account.createdAt)}</td>
                </tr>\`;
              }).join("")}
            </tbody>
          </table>\`
        : "<p>No registered accounts yet.</p>";

      entriesBox.innerHTML = ledgerData.entries.length
        ? \`<table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Account Address</th>
                <th>Amount (USD)</th>
                <th>Note</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              \${ledgerData.entries.map(function (entry) {
                return \`<tr>
                  <td>\${escapeHtml(entry.date)}</td>
                  <td>\${escapeHtml(entry.address)}</td>
                  <td>\${escapeHtml(entry.amount)}</td>
                  <td>\${escapeHtml(entry.note || "")}</td>
                  <td>
                    <button class="danger"
                      data-delete="\${escapeHtml(entry.id)}">
                      Delete
                    </button>
                  </td>
                </tr>\`;
              }).join("")}
            </tbody>
          </table>\`
        : "<p>No credits have been added yet.</p>";

      message.textContent = "Dashboard loaded successfully.";
    } catch (error) {
      message.textContent = error.message;
    }
  }

  document
    .getElementById("loadButton")
    .addEventListener("click", loadDashboard);

  document
    .getElementById("entryForm")
    .addEventListener("submit", async function (event) {
      event.preventDefault();

      const address = document
        .getElementById("address")
        .value.trim();

      const amount = Number(
        document.getElementById("amount").value
      );

      const note = document
        .getElementById("note")
        .value.trim();

      try {
        await api("/api/admin/entries", {
          method: "POST",
          body: JSON.stringify({
            address,
            amount,
            note
          })
        });

        message.textContent = "Credit added successfully.";

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

    if (!confirm("Delete this credit entry?")) return;

    try {
      await api(
        "/api/admin/entries/" + encodeURIComponent(id),
        { method: "DELETE" }
      );

      message.textContent = "Credit deleted successfully.";

      await loadDashboard();
    } catch (error) {
      message.textContent = error.message;
    }
  });
</script>
</body>
</html>`;

// ==================================================
// HTTP SERVER
// ==================================================

const server = http.createServer(async (req, res) => {
  applyCors(req, res);

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(
    req.url,
    "http://localhost"
  );

  const p = url.pathname;

  try {

    // ------------------------------------------------
    // HOME PAGE
    // ------------------------------------------------

    if (req.method === "GET" && p === "/") {
      const indexFile = path.join(__dirname, "index.html");

      if (fs.existsSync(indexFile)) {
        return sendHtml(
          res,
          200,
          fs.readFileSync(indexFile, "utf8")
        );
      }

      return sendJson(res, 200, {
        ok: true,
        message: "Trust Funds backend is running.",
      });
    }

    // ------------------------------------------------
    // ADMIN PAGE
    // ------------------------------------------------

    if (req.method === "GET" && p === "/admin") {
      return sendHtml(res, 200, ADMIN_PAGE);
    }

    // ------------------------------------------------
    // PUBLIC CONFIG
    // ------------------------------------------------

    if (req.method === "GET" && p === "/api/config") {
      return sendJson(res, 200, {
        network: "BNB Smart Chain",
        chainId: 56,
        currency: "BNB",
        rpcUrl: BSC_RPC_URL,
        moonpayConfigured: Boolean(MOONPAY_API_KEY),
      });
    }

    // ------------------------------------------------
    // PURCHASE URL
    // ------------------------------------------------

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

    // ------------------------------------------------
    // ON-CHAIN BNB BALANCE
    // ------------------------------------------------

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

    // ------------------------------------------------
    // AUTH: SIGNUP
    // ------------------------------------------------

    if (req.method === "POST" && p === "/api/auth/signup") {
      const body = await readBody(req);

      const email = String(body.email || "")
        .trim()
        .toLowerCase();

      const name = String(body.name || "")
        .trim()
        .slice(0, 100);

      const phone = String(body.phone || "")
        .trim()
        .slice(0, 30);

      const address = String(body.address || "")
        .trim()
        .toLowerCase();

      const authKey = String(body.authKey || "");

      const keystoreRaw =
        typeof body.keystore === "string"
          ? body.keystore
          : "";

      if (!EMAIL_RE.test(email) || !name || !phone) {
        return sendJson(res, 400, {
          error: "Please provide a valid name, email and phone number.",
        });
      }

      if (!AUTHKEY_RE.test(authKey)) {
        return sendJson(res, 400, {
          error: "Invalid account authentication data.",
        });
      }

      if (!ADDRESS_RE.test(address)) {
        return sendJson(res, 400, {
          error: "A valid wallet address is required.",
        });
      }

      if (
        !keystoreRaw ||
        Buffer.byteLength(keystoreRaw, "utf8") > 10 * 1024 * 1024
      ) {
        return sendJson(res, 400, {
          error: "Valid encrypted wallet data is required.",
        });
      }

      // Validate that the encrypted keystore belongs to the address.
      let keystore;

      try {
        keystore = JSON.parse(keystoreRaw);
      } catch {
        return sendJson(res, 400, {
          error: "Invalid encrypted wallet data.",
        });
      }

      const keystoreAddress = String(
        keystore?.address || ""
      )
        .toLowerCase()
        .replace(/^0x/, "");

      if (
        !(keystore?.crypto || keystore?.Crypto) ||
        keystoreAddress !== address.slice(2)
      ) {
        return sendJson(res, 400, {
          error: "Encrypted wallet does not match the wallet address.",
        });
      }

      try {
        const salt = crypto.randomBytes(16).toString("hex");

        const authHash = await hashAuthKey(
          authKey,
          salt
        );

        const account = {
          id: crypto.randomUUID(),
          name,
          email,
          phone,
          address,
          salt,
          authHash,
          keystore: keystoreRaw,
          createdAt: new Date().toISOString(),
        };

        await accountsCollection.insertOne(account);

        const token = createSession(account.id);

        return sendJson(res, 201, {
          ok: true,
          token,
          address,
        });

      } catch (error) {
        if (error.code === 11000) {
          return sendJson(res, 409, {
            error: "This email or wallet is already registered. Please log in instead.",
          });
        }

        console.error("Signup error:", error);

        return sendJson(res, 500, {
          error: "Could not create your account.",
        });
      }
    }

    // ------------------------------------------------
    // AUTH: LOGIN
    // ------------------------------------------------

    if (req.method === "POST" && p === "/api/auth/login") {
      const body = await readBody(req);

      const email = String(body.email || "")
        .trim()
        .toLowerCase();

      const authKey = String(body.authKey || "");

      const ip = req.socket.remoteAddress || "unknown";
      const limitKey = `${email}|${ip}`;

      const genericError = {
        error: "Incorrect email or password.",
      };

      if (tooManyFailures(limitKey)) {
        return sendJson(res, 429, {
          error: "Too many attempts. Please wait 15 minutes and try again.",
        });
      }

      const validKey = AUTHKEY_RE.test(authKey);

      const account = EMAIL_RE.test(email)
        ? await accountsCollection.findOne({ email })
        : null;

      // Hash even when account does not exist.
      const keyToCheck = validKey
        ? authKey
        : "0".repeat(64);

      const validSalt =
        account &&
        /^[a-f0-9]{32}$/i.test(account.salt || "");

      const saltToUse = validSalt
        ? account.salt
        : DUMMY_SALT;

      const calculatedHash = await hashAuthKey(
        keyToCheck,
        saltToUse
      );

      const storedHashIsValid =
        account &&
        /^[a-f0-9]{128}$/i.test(account.authHash || "");

      const storedHash = storedHashIsValid
        ? Buffer.from(account.authHash, "hex")
        : Buffer.alloc(64);

      const calculatedBuffer = Buffer.from(
        calculatedHash,
        "hex"
      );

      const hashMatches =
        storedHash.length === calculatedBuffer.length &&
        crypto.timingSafeEqual(
          calculatedBuffer,
          storedHash
        );

      const successful =
        Boolean(account) &&
        Boolean(validKey) &&
        Boolean(storedHashIsValid) &&
        hashMatches &&
        typeof account.keystore === "string";

      if (!successful) {
        recordFailure(limitKey);

        return sendJson(res, 401, genericError);
      }

      failures.delete(limitKey);

      removeExpiredSessions();

      const token = createSession(account.id);

      return sendJson(res, 200, {
        ok: true,
        token,
        address: account.address,
        keystore: account.keystore,
      });
    }

    // ------------------------------------------------
    // AUTH: CURRENT ACCOUNT
    // ------------------------------------------------

    if (req.method === "GET" && p === "/api/auth/me") {
      const session = sessionFrom(req);

      if (!session) {
        return sendJson(res, 401, {
          error: "Not logged in.",
        });
      }

      const account = await accountsCollection.findOne(
        { id: session.accountId }
      );

      if (!account) {
        return sendJson(res, 404, {
          error: "Account not found.",
        });
      }

      return sendJson(res, 200, {
        account: publicAccount(account),
      });
    }

    // ------------------------------------------------
    // AUTH: GET ENCRYPTED WALLET
    // ------------------------------------------------

    if (req.method === "GET" && p === "/api/auth/wallet") {
      const session = sessionFrom(req);

      if (!session) {
        return sendJson(res, 401, {
          error: "Not logged in.",
        });
      }

      const account = await accountsCollection.findOne(
        { id: session.accountId },
        { projection: { keystore: 1 } }
      );

      if (!account) {
        return sendJson(res, 404, {
          error: "Account not found.",
        });
      }

      return sendJson(res, 200, {
        keystore: account.keystore,
      });
    }

    // ------------------------------------------------
    // AUTH: LOGOUT
    // ------------------------------------------------

    if (req.method === "POST" && p === "/api/auth/logout") {
      const session = sessionFrom(req);

      if (session) {
        sessions.delete(session.token);
      }

      return sendJson(res, 200, {
        ok: true,
        message: "Logged out successfully.",
      });
    }

    // ------------------------------------------------
    // ACCOUNT CREDITS
    // ------------------------------------------------

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

      const address = creditsMatch[1].toLowerCase();

      const account = await accountsCollection.findOne({
        id: session.accountId,
      });

      if (
        !account ||
        String(account.address).toLowerCase() !== address
      ) {
        return sendJson(res, 403, {
          error: "You cannot access this account's credits.",
        });
      }

      const mine = await entriesCollection
        .find({ address })
        .sort({ date: -1 })
        .project({
          _id: 0,
          id: 1,
          amount: 1,
          note: 1,
          date: 1,
        })
        .toArray();

      const total = mine.reduce((sum, entry) => {
        const amount = Number(entry.amount);

        return sum + (
          Number.isFinite(amount) ? amount : 0
        );
      }, 0);

      return sendJson(res, 200, {
        address,
        total: total.toFixed(2),
        entries: mine,
      });
    }

    // ------------------------------------------------
    // ADMIN: REGISTERED ACCOUNTS
    // ------------------------------------------------

    if (req.method === "GET" && p === "/api/admin/accounts") {
      if (!requireAdmin(req, res)) return;

      const accounts = await accountsCollection
        .find(
          {},
          {
            projection: {
              _id: 0,
              id: 1,
              name: 1,
              email: 1,
              phone: 1,
              address: 1,
              createdAt: 1,
            },
          }
        )
        .sort({ createdAt: -1 })
        .toArray();

      return sendJson(res, 200, {
        accounts,
      });
    }

    // ------------------------------------------------
    // ADMIN: LEDGER ENTRIES
    // ------------------------------------------------

    if (req.method === "GET" && p === "/api/admin/entries") {
      if (!requireAdmin(req, res)) return;

      const entries = await entriesCollection
        .find(
          {},
          {
            projection: {
              _id: 0,
              id: 1,
              address: 1,
              amount: 1,
              note: 1,
              date: 1,
            },
          }
        )
        .sort({ date: -1 })
        .toArray();

      return sendJson(res, 200, {
        entries,
      });
    }

    // ------------------------------------------------
    // ADMIN: PUBLIC LEDGER IS ADMIN-PROTECTED
    // ------------------------------------------------

    if (req.method === "GET" && p === "/api/ledger") {
      if (!requireAdmin(req, res)) return;

      const entries = await entriesCollection
        .find({})
        .sort({ date: -1 })
        .toArray();

      return sendJson(res, 200, {
        entries,
      });
    }

    // ------------------------------------------------
    // ADMIN: ADD CREDIT
    // ------------------------------------------------

    if (req.method === "POST" && p === "/api/admin/entries") {
      if (!requireAdmin(req, res)) return;

      const body = await readBody(req);

      const amount = Number(body.amount);
      const address = String(body.address || "")
        .trim()
        .toLowerCase();

      const note = String(body.note || "")
        .trim()
        .slice(0, 500);

      if (!Number.isFinite(amount) || amount <= 0) {
        return sendJson(res, 400, {
          error: "Enter an amount greater than zero.",
        });
      }

      if (!ADDRESS_RE.test(address)) {
        return sendJson(res, 400, {
          error: "Enter a valid wallet address.",
        });
      }

      const account = await accountsCollection.findOne({
        address,
      });

      if (!account) {
        return sendJson(res, 404, {
          error: "No registered account has this wallet address.",
        });
      }

      const entry = {
        id: crypto.randomUUID(),
        address,
        amount,
        note,
        date: new Date().toISOString(),
      };

      await entriesCollection.insertOne(entry);

      return sendJson(res, 201, {
        ok: true,
        entry,
      });
    }

    // ------------------------------------------------
    // ADMIN: DELETE CREDIT
    // ------------------------------------------------

    const deleteMatch = p.match(
      /^\/api\/admin\/entries\/([^/]+)$/
    );

    if (req.method === "DELETE" && deleteMatch) {
      if (!requireAdmin(req, res)) return;

      const id = decodeURIComponent(deleteMatch[1]);

      const result = await entriesCollection.deleteOne({
        id,
      });

      if (result.deletedCount === 0) {
        return sendJson(res, 404, {
          error: "Ledger entry not found.",
        });
      }

      return sendJson(res, 200, {
        ok: true,
      });
    }

    // ------------------------------------------------
    // MOONPAY URL SIGNING
    // ------------------------------------------------

    if (req.method === "POST" && p === "/api/moonpay-sign") {
      if (!MOONPAY_SECRET_KEY) {
        return sendJson(res, 503, {
          error: "MoonPay signing is not configured.",
        });
      }

      const body = await readBody(req);

      const requestedUrl = String(body.url || "");

      let search;

      if (requestedUrl.startsWith("?")) {
        search = requestedUrl;
      } else {
        let parsedUrl;

        try {
          parsedUrl = new URL(requestedUrl);
        } catch {
          return sendJson(res, 400, {
            error: "A valid MoonPay URL is required.",
          });
        }

        if (
          parsedUrl.protocol !== "https:" ||
          !/(^|\.)moonpay\.com$/i.test(parsedUrl.hostname)
        ) {
          return sendJson(res, 400, {
            error: "Only valid MoonPay HTTPS URLs can be signed.",
          });
        }

        search = parsedUrl.search;
      }

      if (!search) {
        return sendJson(res, 400, {
          error: "MoonPay URL query parameters are required.",
        });
      }

      const apiKey =
        new URLSearchParams(search).get("apiKey") || "";

      const expectedPrefix =
        MOONPAY_SECRET_KEY.startsWith("sk_live_")
          ? "pk_live_"
          : "pk_test_";

      if (!apiKey.startsWith(expectedPrefix)) {
        return sendJson(res, 400, {
          error: "The MoonPay public and secret keys do not match.",
        });
      }

      const signature = crypto
        .createHmac("sha256", MOONPAY_SECRET_KEY)
        .update(search)
        .digest("base64");

      return sendJson(res, 200, {
        signature,
      });
    }

    // ------------------------------------------------
    // NOT FOUND
    // ------------------------------------------------

    return sendJson(res, 404, {
      error: "Route not found.",
    });

  } catch (error) {
    console.error("Server error:", error);

    if (!res.headersSent && !res.destroyed) {
      return sendJson(
        res,
        error.statusCode || 500,
        {
          error:
            error.message || "Internal server error.",
        }
      );
    }
  }
});

// ==================================================
// START SERVER AFTER MONGODB CONNECTION
// ==================================================

connectDatabase()
  .then(() => {
    server.listen(PORT, HOST, () => {
      console.log(`Server listening on port ${PORT}`);
      console.log("MongoDB is connected.");

      if (!ADMIN_KEY) {
        console.warn(
          "WARNING: ADMIN_KEY is not configured."
        );
      }

      if (!ADDRESS_RE.test(DESTINATION_WALLET_ADDRESS)) {
        console.warn(
          "WARNING: Trust Wallet destination address is not configured correctly."
        );
      }
    });
  })
  .catch((error) => {
    console.error("Could not start server:", error);
    process.exit(1);
  });

// Graceful shutdown
async function shutdown() {
  console.log("Shutting down server...");

  server.close(async () => {
    try {
      if (mongoClient) {
        await mongoClient.close();
      }
    } catch (error) {
      console.error("MongoDB shutdown error:", error);
    }

    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
