# db-backuper

A small, self-hosted MySQL / MariaDB auto-backup panel. It runs `mariadb-dump` / `mysqldump`
on a schedule, stores gzip-compressed SQL dumps on a persistent volume, and gives you a
password-protected web UI to manage them.

Built with Node.js + Express, two runtime dependencies (`express`, `archiver`), one HTML page,
no build step.

## Features

- **Scheduled backups** (default every 30 min), start-to-start cadence, with a hard timeout so
  a hung connection can't stall the scheduler.
- **Gzip-compressed, portable dumps** (`.sql.gz`): schema, data, routines, triggers and events,
  taken with `--single-transaction` (consistent snapshot, no table locks). No
  `CREATE DATABASE` / `USE` header, so you can restore into any database.
- **Two-tier schedule for log tables**: frequent "data" backups skip the rows of tables you mark
  as logs (their structure is still included); a less frequent "full" backup includes everything.
- **Web panel**: set the connection string and intervals, run a backup now, filter by date,
  download one (`.sql.gz` or raw `.sql`) or many (ZIP), delete to free space.
- **Integrity checks**: each backup reports table / view counts and whether mysqldump's
  `-- Dump completed` marker is present; any stored backup can be re-inspected on demand.
- **Persistent activity log** (`DATA_DIR/activity.log`, JSON lines): backups, errors, deletions,
  downloads, settings changes and sign-ins, viewable and downloadable from the panel.

## Quick start

```bash
cp .env.example .env      # set APP_PASSWORD and APP_SECRET (npm run gen-secret)
npm install
npm start                 # http://localhost:3000
```

You need `mariadb-dump` or `mysqldump` on your `PATH` (MySQL / MariaDB client tools).

### Docker

The included `Dockerfile` installs the MariaDB client, which can dump both MariaDB and MySQL:

```bash
docker build -t db-backuper .
docker run -d -p 3000:3000 -v db-backups:/data \
  -e APP_PASSWORD=... -e APP_SECRET=... -e DATA_DIR=/data db-backuper
```

It also deploys as-is to container platforms such as Railway: mount a volume, set `DATA_DIR` to
its mount path, and set the variables below.

Once running, sign in and paste a connection string in **Settings**, for example
`mysql://user:password@db-host:3306/dbname` (`mariadb://` also works; add `?ssl=true` to require
TLS). Auto-backups start immediately.

## Configuration

| Variable           | Required | Default        | Description |
|--------------------|----------|----------------|-------------|
| `APP_PASSWORD`     | yes      |                | Panel login password. |
| `APP_SECRET`       | yes      |                | >= 16 chars (64 hex recommended). Derives the encryption and session-signing keys. Don't change it after saving a connection string. |
| `DATA_DIR`         | no       | `./data`       | Backups, config and activity log. Use a persistent volume. |
| `PORT`             | no       | `3000`         | HTTP port. |
| `NODE_ENV`         | no       |                | `production` enables `Secure` cookies and HSTS. |
| `BIND_HOST`        | no       | `0.0.0.0`      | Set `127.0.0.1` to expose the panel only through an SSH tunnel. |
| `COOKIE_SECURE`    | no       | prod: `true`   | Set `false` only when accessing over a tunnel / localhost. |
| `TRUST_PROXY`      | no       | `1`            | Reverse-proxy hops trusted for the client IP. Use `0` with no proxy in front. |
| `DUMP_BIN`         | no       | auto           | Force `mysqldump` or `mariadb-dump`. |
| `DUMP_EXTRA_ARGS`  | no       |                | Extra dump flags, e.g. `--compress`, `--ssl`, `--set-gtid-purged=OFF`. |
| `DUMP_TIMEOUT_MIN` | no       | `60`           | Abort a single dump after this many minutes. |

The app refuses to start without `APP_PASSWORD` / `APP_SECRET`, or with the placeholder values
from `.env.example`.

## Restoring

```bash
zcat backup_2026-01-01_10-30-00_full.sql.gz | mysql --host=HOST --user=USER --password TARGET_DB
```

In phpMyAdmin, select the target database first, then import the `.sql.gz`.

## Security

- **Login**: single password, compared in constant time; 10 failed attempts per IP per 15 min.
- **Sessions**: HMAC-signed cookie, `HttpOnly`, `SameSite=Strict`, `Secure` in production,
  12 h lifetime. Every state-changing request also requires a per-session CSRF token.
- **Connection string**: encrypted at rest with AES-256-GCM, write-only in the UI (never sent
  back to the browser) and never logged.
- **DB password**: passed to the dump tool through a temporary `0600` `--defaults-extra-file`
  that is deleted after each run, so it never appears in the process list. Values are escaped
  so they can't inject extra option lines; database and table names are validated so they
  can't be parsed as command-line options.
- **Files**: download / delete / inspect only accept bare `*.sql.gz` names inside the backup
  directory (no path traversal).
- **Headers**: CSP with a per-request script nonce, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, HSTS in production.

Anyone with the panel password can download full database dumps, so use a strong password,
serve the panel only over HTTPS (or an SSH tunnel), and keep `APP_SECRET` private.

Sessions are stateless: logging out clears the cookie but a stolen token stays valid until it
expires. Rotate `APP_SECRET` to invalidate all sessions (this also makes a stored connection
string unreadable, so re-enter it afterwards).

## Tests

```bash
npm test
```

## License

[MIT](LICENSE)
