# ICSMOG Deployment Guide

This guide covers a practical production-style deployment using Docker Compose and Nginx reverse proxy.

## 1. Prerequisites

- Docker Engine 24+
- Docker Compose v2+
- A Linux host or VM with ports 80 and (optionally) 443 available

## 2. Configure Environment

Create your runtime environment file:

```bash
cp .env.example .env
```

Set secure values in `.env`:

- `ICSMOG_HOST=0.0.0.0`
- `ICSMOG_PORT=8000`
- `ICSMOG_STORAGE_PATH=/app/data/cybersecurity.db`
- `ICSMOG_ANALYST_KEY=<strong-random-value>`
- `ICSMOG_ADMIN_KEY=<strong-random-value>`

Important:
- Bootstrap keys are applied only when the SQLite database is empty.
- Rotate keys by recreating operator accounts if data already exists.

## 3. Start the Stack

```bash
docker compose up -d --build
```

Services:
- `app` (internal only, reachable by Nginx)
- `nginx` (public entrypoint on port 80)

## 4. Health Checks

```bash
docker compose ps
docker compose logs -f nginx
docker compose logs -f app
curl http://localhost/health
```

## 5. First Login

Open:

- `http://<your-server-ip>/dashboard`

Sign in with bootstrap operators configured by env vars:

- `analyst-1` + `ICSMOG_ANALYST_KEY`
- `admin` + `ICSMOG_ADMIN_KEY`

## 6. Persistent Data

SQLite data is persisted via the named Docker volume:

- `icsmog-data`

Backup example:

```bash
docker run --rm -v icsmog_icsmog-data:/data -v $PWD:/backup alpine \
  sh -c 'cp /data/cybersecurity.db /backup/cybersecurity.db.backup'
```

## 7. TLS (Recommended)

For HTTPS, place a TLS terminator in front of Nginx (recommended: Caddy, Traefik, or cloud load balancer), or extend Nginx with certificate mounts and a 443 server block.

## 8. Updates

```bash
git pull
docker compose up -d --build
```

## 9. Rollback

```bash
git checkout <previous-good-commit>
docker compose up -d --build
```
