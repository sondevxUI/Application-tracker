import express from "express";
import cors from "cors";
import { JSONFilePreset } from "lowdb/node";
import { randomUUID } from "crypto";

const PORT = process.env.PORT || 4000;

// --- Database setup -------------------------------------------------
const defaultData = { applications: [] };
const db = await JSONFilePreset("db.json", defaultData);

const VALID_STATUSES = ["applied", "interviewing", "offer", "rejected"];

// --- App setup --------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json());

function isValidApplication(body) {
  if (!body || typeof body !== "object") return false;
  if (!body.company || typeof body.company !== "string") return false;
  if (!body.role || typeof body.role !== "string") return false;
  if (body.status && !VALID_STATUSES.includes(body.status)) return false;
  return true;
}

// GET all applications
app.get("/api/applications", async (req, res) => {
  await db.read();
  res.json(db.data.applications);
});

// GET a single application
app.get("/api/applications/:id", async (req, res) => {
  await db.read();
  const app_ = db.data.applications.find((a) => a.id === req.params.id);
  if (!app_) return res.status(404).json({ error: "Application not found" });
  res.json(app_);
});

// POST create a new application
app.post("/api/applications", async (req, res) => {
  if (!isValidApplication(req.body)) {
    return res.status(400).json({ error: "company and role are required; status must be one of " + VALID_STATUSES.join(", ") });
  }
  const newApplication = {
    id: randomUUID(),
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

// PATCH update an existing application (e.g. move between statuses, edit notes)
app.patch("/api/applications/:id", async (req, res) => {
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

// DELETE an application
app.delete("/api/applications/:id", async (req, res) => {
  await db.read();
  const before = db.data.applications.length;
  db.data.applications = db.data.applications.filter((a) => a.id !== req.params.id);
  if (db.data.applications.length === before) {
    return res.status(404).json({ error: "Application not found" });
  }
  await db.write();
  res.status(204).end();
});

// GET export as CSV — the "automation" touch: one click to get a shareable log
app.get("/api/export/csv", async (req, res) => {
  await db.read();
  const rows = db.data.applications;
  const header = ["Company", "Role", "Platform", "Date Applied", "Status", "Link", "Notes"];
  const escape = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
  const lines = [
    header.join(","),
    ...rows.map((r) =>
      [r.company, r.role, r.platform, r.dateApplied, r.status, r.link, r.notes]
        .map(escape)
        .join(",")
    ),
  ];
  const csv = lines.join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=applications.csv");
  res.send(csv);
});

// GET simple stats — quick summary for the dashboard header
app.get("/api/stats", async (req, res) => {
  await db.read();
  const apps = db.data.applications;
  const stats = { total: apps.length };
  for (const status of VALID_STATUSES) {
    stats[status] = apps.filter((a) => a.status === status).length;
  }
  res.json(stats);
});

app.listen(PORT, () => {
  console.log(`Job tracker API running on http://localhost:${PORT}`);
});
