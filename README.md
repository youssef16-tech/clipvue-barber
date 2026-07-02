# 7gozati

7gozati is a zero-cost, secure, premium barber booking experience built with Rust, Actix Web, SQLite, and a single-file PWA frontend.

## Run locally

```bash
cargo run
```

Then open http://localhost:8080.

## Docker

```bash
docker compose up --build
```

## Free deployment

1. Build and push a Docker image to Docker Hub or GHCR.
2. Deploy it to a free-tier VM such as Oracle Always Free or Fly.io.
3. Put Cloudflare in front of the VM for free HTTPS and CDN.
4. Point your DNS to the Cloudflare proxy and enable TLS.

## Environment variables

- JWT_SECRET
- ADMIN_USER
- ADMIN_PASS
- SMTP_HOST
- SMTP_PORT
- SMTP_USER
- SMTP_PASS
- VAPID_PRIVATE_KEY
- VAPID_PUBLIC_KEY
- DATABASE_URL
