import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { JSONFilePreset } from "lowdb/node";
import { randomUUID } from "crypto";

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "peterson@example.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme123";

// --- Database setup -------------------------------------------------
const defaultData = { users: [], applications: [] };
const db = await JSONFilePreset("db.json", defaultData);

const VALID_STATUSES = ["applied", "interviewing", "offer", "rejected"];

// Seed the admin account on first run
await db.read();
if (!db.data.users.find((u) => u.role === "admin")) {
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  db.data.users.push({
    id: randomUUID(),
    email: ADMIN_EMAIL,
    passwordHash,
    role: "admin",
    createdAt: new Date().toISOString(),
  });
  await db.write();
  console.log(`Admin account seeded: ${ADMIN_EMAIL}`);
}

// --- App setup --------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json());

// --- Auth helpers -----------------------------------------------------
function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid authorization header" });
  }
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.user = payload;
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
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: "Email and a password (6+ chars) are required" });
  }
  await db.read();
  if (db.data.users.find((u) => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: "An account with this email already exists" });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: randomUUID(),
    email,
    passwordHash,
    role: "user",
    createdAt: new Date().toISOString(),
  };
  db.data.users.push(user);
  await db.write();
  const token = signToken(user);
  res.status(201).json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  await db.read();
  const user = db.data.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid email or password" });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid email or password" });
  const token = signToken(user);
  res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ user: req.user });
});

// --- Application validation ---------------------------------------------
function isValidApplication(body) {
  if (!body || typeof body !== "object") return false;
  if (!body.company || typeof body.company !== "string") return false;
  if (!body.role || typeof body.role !== "string") return false;
  if (body.status && !VALID_STATUSES.includes(body.status)) return false;
  return true;
}

// --- Application routes (all require login) -----------------------------

// GET applications — regular users see only their own; admin sees everyone's
app.get("/api/applications", authRequired, async (req, res) => {
  await db.read();
  if (req.user.role === "admin") {
    return res.json(db.data.applications);
  }
  res.json(db.data.applications.filter((a) => a.userId === req.user.id));
});

app.get("/api/applications/:id", authRequired, async (req, res) => {
  await db.read();
  const app_ = db.data.applications.find((a) => a.id === req.params.id);
  if (!app_) return res.status(404).json({ error: "Application not found" });
  if (req.user.role !== "admin" && app_.userId !== req.user.id) {
    return res.status(403).json({ error: "Not your application" });
  }
  res.json(app_);
});

// POST — any logged-in user can create their own application
app.post("/api/applications", authRequired, async (req, res) => {
  if (!isValidApplication(req.body)) {
    return res.status(400).json({ error: "company and role are required; status must be one of " + VALID_STATUSES.join(", ") });
  }
  const newApplication = {
    id: randomUUID(),
    userId: req.user.id,
    userEmail: req.user.email,
    company: req.body.company,
    role: req.body.role,
    platform: req.body.platform || "",
    dateApplied: req.body.dateApplied || new Date().toISOString().slice(0, 10),
    status: req.body.status || "applied",
    link: req.body.link || "",
    notes: req.body.notes || "",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await db.update(({ applications }) => applications.push(newApplication));
  res.status(201).json(newApplication);
});

// PATCH — only the admin can edit/move status (regular users cannot edit after creating)
app.patch("/api/applications/:id", authRequired, adminRequired, async (req, res) => {
  await db.read();
  const app_ = db.data.applications.find((a) => a.id === req.params.id);
  if (!app_) return res.status(404).json({ error: "Application not found" });

  if (req.body.status && !VALID_STATUSES.includes(req.body.status)) {
    return res.status(400).json({ error: "status must be one of " + VALID_STATUSES.join(", ") });
  }

  const fields = ["company", "role", "platform", "dateApplied", "status", "link", "notes"];
  for (const field of fields) {
    if (req.body[field] !== undefined) app_[field] = req.body[field];
  }
  app_.updatedAt = new Date().toISOString();
  await db.write();
  res.json(app_);
});

// DELETE — admin only
app.delete("/api/applications/:id", authRequired, adminRequired, async (req, res) => {
  await db.read();
  const before = db.data.applications.length;
  db.data.applications = db.data.applications.filter((a) => a.id !== req.params.id);
  if (db.data.applications.length === before) {
    return res.status(404).json({ error: "Application not found" });
  }
  await db.write();
  res.status(204).end();
});

// GET export as CSV — admin only (full picture across all users)
app.get("/api/export/csv", authRequired, adminRequired, async (req, res) => {
  await db.read();
  const rows = db.data.applications;
  const header = ["Applicant", "Company", "Role", "Platform", "Date Applied", "Status", "Link", "Notes"];
  const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
  const lines = [
    header.join(","),
    ...rows.map((r) =>
      [r.userEmail, r.company, r.role, r.platform, r.dateApplied, r.status, r.link, r.notes]
        .map(escape)
        .join(",")
    ),
  ];
  const csv = lines.join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=applications.csv");
  res.send(csv);
});

// GET stats — admin sees totals across everyone; regular users see their own
app.get("/api/stats", authRequired, async (req, res) => {
  await db.read();
  const apps = req.user.role === "admin"
    ? db.data.applications
    : db.data.applications.filter((a) => a.userId === req.user.id);
  const stats = { total: apps.length };
  for (const status of VALID_STATUSES) {
    stats[status] = apps.filter((a) => a.status === status).length;
  }
  res.json(stats);
});

app.listen(PORT, () => {
  console.log(`Job tracker API running on http://localhost:${PORT}`);
});
