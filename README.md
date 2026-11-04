# ClipVue (7gozati)

ClipVue is a low-cost, secure, premium barber booking experience built with Rust,
Actix Web, SQLite, and a single-file installable PWA frontend. Egypt-only
(all times are handled in `Africa/Cairo`).

## DevOps side of this project

- **Docker** — multi-stage `Dockerfile` + `docker-compose.yml` for a one-command local run
- **Deploy** — Fly.io config (`fly.toml`) with a persistent volume for SQLite and secrets kept out of the code
- **CI/CD** — GitHub Actions workflow in `.github/workflows/deploy.yml`
- **Ops scripts** — `scripts/backup-db.sh` for database backups

## Run locally

```bash
cargo run
```

Then open <http://localhost:8080>. In dev mode the app boots with built-in
defaults (a dev-only admin login and a placeholder JWT secret) — fine
locally, but always set your own secrets in production (see below).

## Docker

```bash
docker compose up --build
```

## Deploy to Fly.io (recommended)

The backend is a stateful, long-running server (background reminder loop, in-memory
rate limiter, on-disk SQLite, push keys generated at startup), so it needs a real
host — **not** a serverless platform like Vercel. Fly.io fits and stays cheap.

### 1. Install and sign in
```bash
# install flyctl: https://fly.io/docs/hands-on/install-flyctl/
fly auth signup   # or: fly auth login
```

### 2. Create the app and its data volume
```bash
fly apps create clipvue-barber        # or edit `app = ...` in fly.toml to a free name
fly volumes create clipvue_data --region cdg --size 1
```
The volume is mounted at `/data`; `DATABASE_URL=/data/clipvue.db` (set in fly.toml)
keeps the SQLite database across deploys.

### 3. Set production secrets (REQUIRED)
`DEV_MODE=false` (set in fly.toml) makes the app **refuse to boot** without these:
```bash
fly secrets set JWT_SECRET="$(openssl rand -hex 32)"
# Single-quote the password so the shell doesn't interpret $ & * etc.
fly secrets set ADMIN_PASS='<your-strong-password>'
fly secrets set ADMIN_USER='<your-admin-username>'
```
Optional email reminders (leave unset to disable — the app no-ops without them):
```bash
fly secrets set SMTP_HOST=... SMTP_PORT=587 SMTP_USER=... SMTP_PASS=... SMTP_FROM="noreply@yourdomain.com"
```
Web-push VAPID keys are generated and persisted automatically on first boot; set
`VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY` only if you want to pin your own.

### 4. Deploy
```bash
fly deploy --remote-only
```
`--remote-only` builds the Docker image on Fly's builders, so you don't need Docker
installed locally. The **first deploy is what validates the Docker build.**

### 5. (Optional) Custom domain via Cloudflare — free HTTPS/CDN
```bash
fly certs add booking.yourdomain.com
```
Then add a CNAME `booking -> clipvue-barber.fly.dev` in Cloudflare (proxied). Fly
issues the TLS cert; Cloudflare fronts it.

## Admin

Log in through the normal login form with the admin username/password — the app
detects admin credentials automatically (there is no separate admin button).

## Environment variables

| Var | Purpose |
| --- | --- |
| `DEV_MODE` | `false` in production (Secure cookies + HSTS, enforces secrets). Defaults to dev. |
| `DATABASE_URL` | SQLite path. `/data/clipvue.db` on Fly. |
| `JWT_SECRET` | Session signing key. **Required in production.** |
| `ADMIN_USER` / `ADMIN_PASS` | Admin login. `ADMIN_PASS` **required (non-default) in production.** |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Email reminders (optional). |
| `VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY` | Web push (auto-generated if unset). |

## Roadmap

- WhatsApp/Telegram AI booking bot (LangGraph) as a **separate service** that calls
  this app's HTTP API — so all booking rules stay in one place. Planned; not yet built.
