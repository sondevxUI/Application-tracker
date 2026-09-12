import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import Stripe from "stripe";
import { randomUUID } from "crypto";

const { Pool } = pg;

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "peterson@example.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme123";
const DATABASE_URL = process.env.DATABASE_URL;

// ---------------------------------------------------------------------
// Billing (Stripe)
// FREE_APPLICATION_LIMIT is the whole free-tier gate: once a free user has
// this many applications, further creation is blocked until they upgrade.
// Premium-only features (Gmail auto-detection) are gated separately below.
// ---------------------------------------------------------------------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
// Three tiers: a one-time day-pass (not a recurring daily charge — nobody
// wants to be silently billed $5/day forever) plus two real subscriptions.
const STRIPE_PRICE_DAILY = process.env.STRIPE_PRICE_DAILY;
const STRIPE_PRICE_MONTHLY = process.env.STRIPE_PRICE_MONTHLY;
const STRIPE_PRICE_YEARLY = process.env.STRIPE_PRICE_YEARLY;
const BILLING_PLANS = {
  daily: { price: STRIPE_PRICE_DAILY, mode: "payment" }, // one-time, grants 24h premium
  monthly: { price: STRIPE_PRICE_MONTHLY, mode: "subscription" },
  yearly: { price: STRIPE_PRICE_YEARLY, mode: "subscription" },
};
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const FREE_APPLICATION_LIMIT = 15;

function isPremium(user) {
  if (user.plan !== "premium") return false;
  // null premium_expires_at = lifetime/no-expiry grant; otherwise must be in the future
  return !user.premium_expires_at || new Date(user.premium_expires_at) > new Date();
}

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not set. Set it to your PostgreSQL connection string.");
  process.exit(1);
}

// Render's managed Postgres requires SSL; local/dev connections usually don't.
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
});

// "draft" is a pipeline stage, not a final outcome: it's what we create the
// instant someone shows intent (clicks an outbound apply link, opens the
// Add form) so nothing is lost if they never come back to finish it.
const VALID_STATUSES = ["draft", "applied", "interviewing", "offer", "rejected"];

// --- Schema setup -------------------------------------------------
async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT,
      skills TEXT,
      role TEXT NOT NULL DEFAULT 'user',
      reset_token_hash TEXT,
      reset_token_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // Add columns if this table already existed from an earlier version
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;`);
  // Gmail integration: each user (including admin) can connect their own
  // Gmail via OAuth. We only ever store the refresh_token (never the
  // password/access_token) and the connected address, so we can re-request
  // a fresh access token whenever "Check my Gmail" is clicked.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_refresh_token TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_email TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_connected_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS gmail_last_checked_at TIMESTAMPTZ;`);
  // Billing: "plan" is the single source of truth the rest of the app checks
  // (free vs premium). provider/external ids let more than one payment
  // processor (Stripe now, IntaSend for M-Pesa/Kenyan cards later) update
  // the same plan state without the app caring which one was used.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free';`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS premium_expires_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS billing_provider TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS skills TEXT;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS applications (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      company TEXT NOT NULL,
      role TEXT NOT NULL,
      platform TEXT DEFAULT '',
      date_applied DATE,
      status TEXT NOT NULL DEFAULT 'applied',
      link TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Seed the admin account on first run
  const { rows } = await pool.query("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
  if (rows.length === 0) {
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.query(
      "INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, 'admin')",
      [randomUUID(), ADMIN_EMAIL, passwordHash]
    );
    console.log(`Admin account seeded: ${ADMIN_EMAIL}`);
  }
}

function appRowToJSON(row, userEmail, userDisplayName) {
  return {
    id: row.id,
    userId: row.user_id,
    userEmail: userEmail || row.user_email,
    userDisplayName: userDisplayName || row.user_display_name || null,
    company: row.company,
    role: row.role,
    platform: row.platform,
    dateApplied: row.date_applied ? new Date(row.date_applied).toISOString().slice(0, 10) : null,
    status: row.status,
    link: row.link,
    notes: row.notes,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// --- App setup --------------------------------------------------------
const app = express();
app.use(cors());

// Stripe webhook MUST see the raw request body (for signature verification),
// so this route is registered before the global express.json() below —
// Express matches routes in registration order, so this one never gets
// touched by the JSON parser.
app.post("/api/billing/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(500).send("Stripe not configured");
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Stripe webhook signature check failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const userId = session.client_reference_id;
      if (userId) {
        if (session.mode === "payment") {
          // One-time day-pass: 24 hours of premium from now, no ongoing subscription.
          const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
          await pool.query(
            `UPDATE users SET plan = 'premium', billing_provider = 'stripe',
             stripe_customer_id = COALESCE($1, stripe_customer_id), premium_expires_at = $2
             WHERE id = $3`,
            [session.customer, expires, userId]
          );
        } else {
          // Monthly/yearly subscription — stays premium until cancelled (see below).
          await pool.query(
            `UPDATE users SET plan = 'premium', billing_provider = 'stripe',
             stripe_customer_id = $1, stripe_subscription_id = $2, premium_expires_at = NULL
             WHERE id = $3`,
            [session.customer, session.subscription, userId]
          );
        }
      }
    } else if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.deleted") {
      const sub = event.data.object;
      const active = sub.status === "active" || sub.status === "trialing";
      const expiresAt = active ? null : new Date(sub.current_period_end * 1000);
      await pool.query(
        `UPDATE users SET plan = $1, premium_expires_at = $2 WHERE stripe_subscription_id = $3`,
        [active ? "premium" : "free", expiresAt, sub.id]
      );
    }
    res.json({ received: true });
  } catch (err) {
    console.error("Stripe webhook handling error:", err.message);
    res.status(500).json({ error: "Webhook handler failed" });
  }
});

app.use(express.json());

// --- Auth helpers -----------------------------------------------------
function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role, displayName: user.displayName || null }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid authorization header" });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function adminRequired(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

// --- Auth routes --------------------------------------------------------
app.post("/api/auth/register", async (req, res) => {
  const { email, password, displayName, skills } = req.body || {};
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: "Email and a password (6+ chars) are required" });
  }
  const existing = await pool.query("SELECT id FROM users WHERE lower(email) = lower($1)", [email]);
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "An account with this email already exists" });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const id = randomUUID();
  const cleanDisplayName = displayName && displayName.trim() ? displayName.trim() : null;
  const cleanSkills = skills && skills.trim() ? skills.trim() : null;
  await pool.query(
    "INSERT INTO users (id, email, password_hash, display_name, skills, role) VALUES ($1, $2, $3, $4, $5, 'user')",
    [id, email, passwordHash, cleanDisplayName, cleanSkills]
  );
  const user = { id, email, displayName: cleanDisplayName, role: "user" };
  res.status(201).json({ token: signToken(user), user });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const { rows } = await pool.query("SELECT * FROM users WHERE lower(email) = lower($1)", [email]);
  const dbUser = rows[0];
  if (!dbUser) return res.status(401).json({ error: "Invalid email or password" });
  const valid = await bcrypt.compare(password, dbUser.password_hash);
  if (!valid) return res.status(401).json({ error: "Invalid email or password" });
  const user = { id: dbUser.id, email: dbUser.email, displayName: dbUser.display_name, role: dbUser.role };
  res.json({ token: signToken(user), user });
});

app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ user: req.user });
});

// --- Password reset flow --------------------------------------------------
// Generates a reset token, hashes it in the DB, and returns the raw link.
// Note: with no email service connected, the link is returned directly in
// the response instead of being emailed — see README for how to wire up
// real email delivery later.
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "Email is required" });

  const { rows } = await pool.query("SELECT id FROM users WHERE lower(email) = lower($1)", [email]);
  // Always respond the same way whether or not the account exists, so visitors
  // can't use this endpoint to discover which emails have accounts.
  if (rows.length === 0) {
    return res.json({ message: "If that account exists, a reset link has been generated.", resetLink: null });
  }

  const rawToken = randomUUID() + randomUUID(); // long random token
  const tokenHash = await bcrypt.hash(rawToken, 10);
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await pool.query(
    "UPDATE users SET reset_token_hash = $1, reset_token_expires = $2 WHERE id = $3",
    [tokenHash, expires, rows[0].id]
  );

  const resetLink = `${req.headers.origin || ""}/?resetToken=${encodeURIComponent(rawToken)}&email=${encodeURIComponent(email)}`;
  res.json({
    message: "Reset link generated. In production this would be emailed to you.",
    resetLink,
  });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body || {};
  if (!email || !token || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "Email, token, and a new password (6+ chars) are required" });
  }

  const { rows } = await pool.query(
    "SELECT id, reset_token_hash, reset_token_expires FROM users WHERE lower(email) = lower($1)",
    [email]
  );
  const user = rows[0];
  if (!user || !user.reset_token_hash || !user.reset_token_expires) {
    return res.status(400).json({ error: "Invalid or expired reset link" });
  }
  if (new Date(user.reset_token_expires) < new Date()) {
    return res.status(400).json({ error: "This reset link has expired. Please request a new one." });
  }
  const valid = await bcrypt.compare(token, user.reset_token_hash);
  if (!valid) {
    return res.status(400).json({ error: "Invalid or expired reset link" });
  }

  const newHash = await bcrypt.hash(newPassword, 10);
  await pool.query(
    "UPDATE users SET password_hash = $1, reset_token_hash = NULL, reset_token_expires = NULL WHERE id = $2",
    [newHash, user.id]
  );
  res.json({ message: "Password updated. You can now log in with your new password." });
});

// --- Application validation ---------------------------------------------
// Drafts are allowed to be incomplete on purpose — we'd rather store a
// half-filled row than lose the application entirely. company/role are only
// required once a row is claiming to be a real (non-draft) status.
function isValidApplication(body) {
  if (!body || typeof body !== "object") return false;
  if (body.status && !VALID_STATUSES.includes(body.status)) return false;
  if (body.status !== "draft") {
    if (!body.company || typeof body.company !== "string") return false;
    if (!body.role || typeof body.role !== "string") return false;
  }
  return true;
}

// --- Application routes (all require login) -----------------------------

app.get("/api/applications", authRequired, async (req, res) => {
  const query = req.user.role === "admin"
    ? `SELECT a.*, u.email AS user_email, u.display_name AS user_display_name FROM applications a JOIN users u ON u.id = a.user_id ORDER BY a.created_at DESC`
    : `SELECT a.*, u.email AS user_email, u.display_name AS user_display_name FROM applications a JOIN users u ON u.id = a.user_id WHERE a.user_id = $1 ORDER BY a.created_at DESC`;
  const params = req.user.role === "admin" ? [] : [req.user.id];
  const { rows } = await pool.query(query, params);
  res.json(rows.map((r) => appRowToJSON(r)));
});

app.get("/api/applications/:id", authRequired, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT a.*, u.email AS user_email, u.display_name AS user_display_name FROM applications a JOIN users u ON u.id = a.user_id WHERE a.id = $1`,
    [req.params.id]
  );
  const row = rows[0];
  if (!row) return res.status(404).json({ error: "Application not found" });
  if (req.user.role !== "admin" && row.user_id !== req.user.id) {
    return res.status(403).json({ error: "Not your application" });
  }
  res.json(appRowToJSON(row));
});

// Shared free-tier gate for both ways an application gets created. Admin is
// exempt (this is your own operating account, not a customer). Premium
// users are unlimited; free users are capped at FREE_APPLICATION_LIMIT
// total applications (drafts included, since a draft still "used a slot").
async function canCreateApplication(user) {
  if (user.role === "admin") return true;
  const { rows } = await pool.query("SELECT plan, premium_expires_at FROM users WHERE id = $1", [user.id]);
  if (isPremium(rows[0])) return true;
  const { rows: countRows } = await pool.query("SELECT COUNT(*) FROM applications WHERE user_id = $1", [user.id]);
  return parseInt(countRows[0].count, 10) < FREE_APPLICATION_LIMIT;
}

app.post("/api/applications", authRequired, async (req, res) => {
  if (!isValidApplication(req.body)) {
    return res.status(400).json({ error: "company and role are required; status must be one of " + VALID_STATUSES.join(", ") });
  }
  if (!(await canCreateApplication(req.user))) {
    return res.status(402).json({
      error: `Free plan is limited to ${FREE_APPLICATION_LIMIT} applications — upgrade to add more.`,
      upgradeRequired: true,
    });
  }
  const id = randomUUID();
  const {
    company = "(untitled)",
    role = "(untitled)",
    platform = "",
    status = "applied",
    link = "",
    notes = "",
  } = req.body;
  const dateApplied = req.body.dateApplied || new Date().toISOString().slice(0, 10);

  const { rows } = await pool.query(
    `INSERT INTO applications (id, user_id, company, role, platform, date_applied, status, link, notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [id, req.user.id, company, role, platform, dateApplied, status, link, notes]
  );
  res.status(201).json(appRowToJSON(rows[0], req.user.email, req.user.displayName));
});

// Fire-and-forget capture: called the instant a user shows intent (clicks an
// outbound "Sign up / Log in" link, or opens the Add form) — before they've
// typed anything. Creates a minimal draft row so we have a record even if
// they never come back. No company/role required.
app.post("/api/applications/capture", authRequired, async (req, res) => {
  if (!(await canCreateApplication(req.user))) {
    return res.status(402).json({
      error: `Free plan is limited to ${FREE_APPLICATION_LIMIT} applications — upgrade to add more.`,
      upgradeRequired: true,
    });
  }
  const { platform = "", link = "" } = req.body || {};
  const id = randomUUID();
  const company = "(pending)";
  const role = platform ? `${platform} application` : "(pending)";
  const dateApplied = new Date().toISOString().slice(0, 10);

  const { rows } = await pool.query(
    `INSERT INTO applications (id, user_id, company, role, platform, date_applied, status, link, notes)
     VALUES ($1,$2,$3,$4,$5,$6,'draft',$7,'')
     RETURNING *`,
    [id, req.user.id, company, role, platform, dateApplied, link]
  );
  res.status(201).json(appRowToJSON(rows[0], req.user.email, req.user.displayName));
});

// Owners can update their own rows (needed so a draft can be completed or
// autosaved); admins can update anyone's.
app.patch("/api/applications/:id", authRequired, async (req, res) => {
  const { rows: existingRows } = await pool.query("SELECT * FROM applications WHERE id = $1", [req.params.id]);
  if (!existingRows[0]) return res.status(404).json({ error: "Application not found" });
  if (req.user.role !== "admin" && existingRows[0].user_id !== req.user.id) {
    return res.status(403).json({ error: "Not your application" });
  }

  if (req.body.status && !VALID_STATUSES.includes(req.body.status)) {
    return res.status(400).json({ error: "status must be one of " + VALID_STATUSES.join(", ") });
  }

  const fields = { company: "company", role: "role", platform: "platform", dateApplied: "date_applied", status: "status", link: "link", notes: "notes" };
  const sets = [];
  const values = [];
  let i = 1;
  for (const [bodyKey, col] of Object.entries(fields)) {
    if (req.body[bodyKey] !== undefined) {
      sets.push(`${col} = $${i}`);
      values.push(req.body[bodyKey]);
      i++;
    }
  }
  sets.push(`updated_at = now()`);
  values.push(req.params.id);

  const { rows } = await pool.query(
    `UPDATE applications SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`,
    values
  );
  res.json(appRowToJSON(rows[0]));
});

app.delete("/api/applications/:id", authRequired, adminRequired, async (req, res) => {
  const result = await pool.query("DELETE FROM applications WHERE id = $1", [req.params.id]);
  if (result.rowCount === 0) return res.status(404).json({ error: "Application not found" });
  res.status(204).end();
});

app.get("/api/export/csv", authRequired, adminRequired, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT a.*, u.email AS user_email, u.display_name AS user_display_name FROM applications a JOIN users u ON u.id = a.user_id ORDER BY a.created_at DESC`
  );
  const header = ["Applicant", "Company", "Role", "Platform", "Date Applied", "Status", "Link", "Notes"];
  const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
  const lines = [
    header.join(","),
    ...rows.map((r) =>
      [r.user_email, r.company, r.role, r.platform, r.date_applied, r.status, r.link, r.notes]
        .map(escape)
        .join(",")
    ),
  ];
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=applications.csv");
  res.send(lines.join("\n"));
});

// Admin-only: list every registered user with their profile info (for advising which
// platforms fit them). Passwords are never included — password_hash stays server-side only.
app.get("/api/users", authRequired, adminRequired, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id, email, display_name, skills, role, created_at FROM users ORDER BY created_at DESC"
  );
  res.json(
    rows.map((r) => ({
      id: r.id,
      email: r.email,
      displayName: r.display_name,
      skills: r.skills,
      role: r.role,
      createdAt: r.created_at,
    }))
  );
});

// Admin-only: delete a user account. Their applications go with them
// (ON DELETE CASCADE on applications.user_id), so this is destructive —
// the frontend confirms before calling it. Admin accounts can't be deleted
// this way, and an admin can't delete themselves through this endpoint.
app.delete("/api/users/:id", authRequired, adminRequired, async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: "You can't delete your own account from here" });
  }
  const { rows } = await pool.query("SELECT role FROM users WHERE id = $1", [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: "User not found" });
  if (rows[0].role === "admin") {
    return res.status(403).json({ error: "Admin accounts can't be deleted from here" });
  }
  await pool.query("DELETE FROM users WHERE id = $1", [req.params.id]);
  res.status(204).end();
});

// ---------------------------------------------------------------------
// Billing (Stripe checkout + status)
// The webhook route itself lives up near the top of the file (needs the
// raw body, before express.json() runs). Everything else — creating a
// checkout session, checking current plan/limits — lives here.
// ---------------------------------------------------------------------
app.get("/api/billing/status", authRequired, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT plan, premium_expires_at, billing_provider FROM users WHERE id = $1",
    [req.user.id]
  );
  const user = rows[0];
  const { rows: countRows } = await pool.query(
    "SELECT COUNT(*) FROM applications WHERE user_id = $1",
    [req.user.id]
  );
  res.json({
    plan: user.plan,
    premium: isPremium(user),
    premiumExpiresAt: user.premium_expires_at,
    billingProvider: user.billing_provider,
    applicationCount: parseInt(countRows[0].count, 10),
    freeLimit: FREE_APPLICATION_LIMIT,
  });
});

app.post("/api/billing/checkout", authRequired, async (req, res) => {
  const plan = req.body?.plan;
  const planConfig = BILLING_PLANS[plan];
  if (!stripe || !planConfig || !planConfig.price) {
    return res.status(400).json({ error: "Pick a valid plan (daily, monthly, or yearly) — or payments aren't configured yet." });
  }
  try {
    const { rows } = await pool.query("SELECT stripe_customer_id FROM users WHERE id = $1", [req.user.id]);
    const existingCustomerId = rows[0]?.stripe_customer_id;

    const session = await stripe.checkout.sessions.create({
      mode: planConfig.mode,
      line_items: [{ price: planConfig.price, quantity: 1 }],
      customer: existingCustomerId || undefined,
      customer_email: existingCustomerId ? undefined : req.user.email,
      customer_creation: planConfig.mode === "payment" ? "always" : undefined,
      client_reference_id: req.user.id, // how the webhook maps back to this user
      metadata: { plan },
      success_url: `${FRONTEND_URL}/?billing=success`,
      cancel_url: `${FRONTEND_URL}/?billing=cancelled`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error("Stripe checkout session error:", err.message);
    res.status(500).json({ error: "Couldn't start checkout — try again shortly." });
  }
});

// Lets a premium user manage/cancel their subscription without you doing it
// manually — Stripe's hosted billing portal.
app.post("/api/billing/portal", authRequired, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: "Payments aren't configured yet." });
  const { rows } = await pool.query("SELECT stripe_customer_id FROM users WHERE id = $1", [req.user.id]);
  const customerId = rows[0]?.stripe_customer_id;
  if (!customerId) return res.status(400).json({ error: "No billing account on file yet." });
  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: `${FRONTEND_URL}/`,
  });
  res.json({ url: session.url });
});

// ---------------------------------------------------------------------
// Gmail integration
// Each user connects their own Gmail (read-only) via Google OAuth. We
// store only the refresh_token — never a password — and use it on demand
// (when the user clicks "Check my Gmail") to search their inbox for
// replies related to their tracked applications, then update status
// automatically. Admins can see the results because they can already
// filter the board down to any one user (see /api/users + filterUserId
// on the frontend) — no separate "admin sees everyone's inbox" endpoint,
// each admin still only ever touches their own Gmail account.
// Gmail auto-detection is premium-only — gated in /api/gmail/check below.
// ---------------------------------------------------------------------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
const FRONTEND_URL = process.env.FRONTEND_URL || "https://application-tracker.netlify.app";
const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";

// Step 1: user clicks "Connect Gmail". This is a real page navigation (not
// fetch), so it can't carry an Authorization header — the frontend passes
// the JWT as a query param instead, verified here, then re-signed as a
// short-lived `state` value Google hands back to us in the callback.
app.get("/api/gmail/connect", async (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) {
    return res.status(500).send("Gmail integration isn't configured yet (missing GOOGLE_CLIENT_ID/GOOGLE_REDIRECT_URI on the server).");
  }
  let uid;
  try {
    uid = jwt.verify(req.query.token, JWT_SECRET).id;
  } catch {
    return res.status(401).send("Your session expired — go back and log in again before connecting Gmail.");
  }
  const { rows } = await pool.query("SELECT plan, premium_expires_at, role FROM users WHERE id = $1", [uid]);
  if (rows[0]?.role !== "admin" && !isPremium(rows[0])) {
    return res.redirect(`${FRONTEND_URL}/?gmail=error&reason=premium_required`);
  }
  const state = jwt.sign({ uid }, JWT_SECRET, { expiresIn: "10m" });
  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.set("client_id", GOOGLE_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", GOOGLE_REDIRECT_URI);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", GMAIL_SCOPE);
  authUrl.searchParams.set("access_type", "offline"); // needed to get a refresh_token back
  authUrl.searchParams.set("prompt", "consent"); // forces refresh_token even on repeat connects
  authUrl.searchParams.set("state", state);
  res.redirect(authUrl.toString());
});

// Step 2: Google redirects the browser back here with a one-time code.
app.get("/api/gmail/callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`${FRONTEND_URL}/?gmail=error&reason=${encodeURIComponent(error)}`);
  let uid;
  try {
    uid = jwt.verify(state, JWT_SECRET).uid;
  } catch {
    return res.redirect(`${FRONTEND_URL}/?gmail=error&reason=expired_state`);
  }

  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokenData.error_description || tokenData.error || "token exchange failed");

    // refresh_token is only sent the first time (or after prompt=consent),
    // so don't overwrite an existing one with nothing on a repeat connect.
    let gmailEmail = null;
    if (tokenData.id_token) {
      const payload = JSON.parse(Buffer.from(tokenData.id_token.split(".")[1], "base64url").toString());
      gmailEmail = payload.email || null;
    }

    if (tokenData.refresh_token) {
      await pool.query(
        `UPDATE users SET gmail_refresh_token = $1, gmail_email = $2, gmail_connected_at = now() WHERE id = $3`,
        [tokenData.refresh_token, gmailEmail, uid]
      );
    } else {
      await pool.query(
        `UPDATE users SET gmail_email = COALESCE($1, gmail_email), gmail_connected_at = now() WHERE id = $2`,
        [gmailEmail, uid]
      );
    }
    res.redirect(`${FRONTEND_URL}/?gmail=connected`);
  } catch (err) {
    console.error("Gmail OAuth callback error:", err.message);
    res.redirect(`${FRONTEND_URL}/?gmail=error&reason=token_exchange_failed`);
  }
});

app.post("/api/gmail/disconnect", authRequired, async (req, res) => {
  await pool.query(
    `UPDATE users SET gmail_refresh_token = NULL, gmail_email = NULL, gmail_connected_at = NULL WHERE id = $1`,
    [req.user.id]
  );
  res.status(204).end();
});

app.get("/api/gmail/status", authRequired, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT gmail_email, gmail_connected_at, gmail_last_checked_at FROM users WHERE id = $1",
    [req.user.id]
  );
  const row = rows[0] || {};
  res.json({
    connected: !!row.gmail_connected_at,
    email: row.gmail_email || null,
    lastCheckedAt: row.gmail_last_checked_at || null,
  });
});

async function getGmailAccessToken(refreshToken) {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      grant_type: "refresh_token",
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_description || data.error || "Could not refresh Gmail access token");
  return data.access_token;
}

// v1 keyword classifier. Deliberately simple and cheap (no per-email AI
// call) — checks the subject + snippet against a few common phrase
// patterns per outcome. Rejection phrasing is checked first since
// "unfortunately... interview" type phrasing should read as a rejection,
// not an interview invite.
function classifyEmail(text) {
  const t = text.toLowerCase();
  const has = (...phrases) => phrases.some((p) => t.includes(p));
  if (has("unfortunately", "not moving forward", "not selected", "other candidates", "will not be proceeding", "regret to inform"))
    return "rejected";
  if (has("offer letter", "pleased to offer", "job offer", "we'd like to offer", "congratulations")) return "offer";
  if (has("interview", "schedule a call", "schedule a chat", "phone screen", "hiring manager would like to speak"))
    return "interviewing";
  return null; // no confident match — leave the application's status alone
}

// The actual "Check my Gmail" action. Pulls the user's own applications,
// searches their inbox for anything mentioning each company/platform, and
// bumps status forward (never backward) when a phrase confidently matches.
app.post("/api/gmail/check", authRequired, async (req, res) => {
  const { rows: planRows } = await pool.query("SELECT plan, premium_expires_at FROM users WHERE id = $1", [req.user.id]);
  if (!isPremium(planRows[0])) {
    return res.status(402).json({ error: "Gmail auto-detection is a premium feature — upgrade to use it.", upgradeRequired: true });
  }
  const { rows: userRows } = await pool.query("SELECT gmail_refresh_token FROM users WHERE id = $1", [req.user.id]);
  const refreshToken = userRows[0]?.gmail_refresh_token;
  if (!refreshToken) return res.status(400).json({ error: "Connect your Gmail first." });

  const { rows: apps } = await pool.query(
    "SELECT * FROM applications WHERE user_id = $1 AND status NOT IN ('offer', 'rejected')",
    [req.user.id]
  );
  if (apps.length === 0) {
    await pool.query("UPDATE users SET gmail_last_checked_at = now() WHERE id = $1", [req.user.id]);
    return res.json({ checked: 0, updated: [] });
  }

  let accessToken;
  try {
    accessToken = await getGmailAccessToken(refreshToken);
  } catch (err) {
    return res.status(502).json({ error: "Couldn't reach Gmail — try reconnecting your account. (" + err.message + ")" });
  }

  const updated = [];
  const STATUS_RANK = { draft: 0, applied: 1, interviewing: 2, offer: 3, rejected: 3 };

  for (const app of apps) {
    const searchTerm = (app.company !== "(pending)" && app.company !== "(untitled)") ? app.company : app.platform;
    if (!searchTerm) continue;

    try {
      const gmailRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${encodeURIComponent(`"${searchTerm}" newer_than:60d`)}&maxResults=5`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      const gmailData = await gmailRes.json();
      const messageIds = (gmailData.messages || []).map((m) => m.id);
      if (messageIds.length === 0) continue;

      let bestStatus = null;
      for (const id of messageIds) {
        const msgRes = await fetch(
          `https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}?format=metadata&metadataHeaders=Subject`,
          { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        const msg = await msgRes.json();
        const subject = (msg.payload?.headers || []).find((h) => h.name === "Subject")?.value || "";
        const guess = classifyEmail(`${subject} ${msg.snippet || ""}`);
        if (guess && (STATUS_RANK[guess] ?? 0) > (STATUS_RANK[bestStatus] ?? -1)) bestStatus = guess;
      }

      if (bestStatus && (STATUS_RANK[bestStatus] ?? 0) > (STATUS_RANK[app.status] ?? 0)) {
        await pool.query("UPDATE applications SET status = $1, updated_at = now() WHERE id = $2", [bestStatus, app.id]);
        updated.push({ id: app.id, company: app.company, role: app.role, from: app.status, to: bestStatus });
      }
    } catch (err) {
      console.error(`Gmail check failed for application ${app.id}:`, err.message);
    }
  }

  await pool.query("UPDATE users SET gmail_last_checked_at = now() WHERE id = $1", [req.user.id]);
  res.json({ checked: apps.length, updated });
});

app.get("/api/stats", authRequired, async (req, res) => {
  const query = req.user.role === "admin"
    ? "SELECT status, COUNT(*) FROM applications GROUP BY status"
    : "SELECT status, COUNT(*) FROM applications WHERE user_id = $1 GROUP BY status";
  const params = req.user.role === "admin" ? [] : [req.user.id];
  const { rows } = await pool.query(query, params);
  const stats = { total: 0 };
  for (const s of VALID_STATUSES) stats[s] = 0;
  for (const row of rows) {
    stats[row.status] = parseInt(row.count, 10);
    stats.total += parseInt(row.count, 10);
  }
  res.json(stats);
});

// --- Start server -------------------------------------------------------
initSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Job tracker API running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database schema:", err);
    process.exit(1);
  });
