
## Running it locally

**1. Start the backend:**
```bash
cd backend
npm install
npm start
```
This runs the API at `http://localhost:4000`.

**2. Open the frontend:**
Just open `frontend/index.html` directly in your browser (double-click it, or use a simple static server like `npx serve frontend`).

That's it — no database setup, no environment variables required for local use.

## API reference

| Method | Endpoint                  | Description                          |
|--------|----------------------------|---------------------------------------|
| GET    | `/api/applications`        | List all applications                |
| GET    | `/api/applications/:id`    | Get a single application             |
| POST   | `/api/applications`        | Create a new application             |
| PATCH  | `/api/applications/:id`    | Update fields / move status          |
| DELETE | `/api/applications/:id`    | Delete an application                |
| GET    | `/api/stats`                | Get counts per status                |
| GET    | `/api/export/csv`           | Download all applications as CSV     |

## What this project demonstrates

- REST API design with proper validation and status codes (400/404/204)
- Full CRUD lifecycle against a persistent data store
- Clean separation between backend (data/logic) and frontend (presentation)
- A practical automation feature (CSV export) solving a real personal workflow problem
- Deployable as-is: backend can go on Render/Railway/Fly.io, frontend on Netlify/Vercel or served statically

## Possible next steps

- Add authentication if deploying publicly with real data
- Migrate storage from JSON file to PostgreSQL for scale
- Add reminders/notifications for stale applications (e.g. "no update in 14 days")
- Rebuild frontend in React to match the rest of the portfolio's tech stack