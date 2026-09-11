import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import { randomUUID } from "crypto";

const { Pool } = pg;

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "peterson@example.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme123";
const DATABASE_URL = process.env.DATABASE_URL;

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

app.post("/api/applications", authRequired, async (req, res) => {
  if (!isValidApplication(req.body)) {
    return res.status(400).json({ error: "company and role are required; status must be one of " + VALID_STATUSES.join(", ") });
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
