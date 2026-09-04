# ai-vuln-scanner

## How to use the scanner

Start the server:

```
npm run dev
```

This listens on `http://localhost:3000` by default (override with `PORT`; the
SQLite file defaults to `./data/scanner.db`, override with `DB_PATH`).

### Submit a scan

```
curl -X POST localhost:3000/scans \
  -H 'content-type: application/json' \
  -d '{"urls": ["https://example.com", "https://example.org"]}'
```

Optional body fields: `name` (defaults to a timestamp) and `userAgent`
(defaults to the runtime's default `fetch` user agent). Up to 100 URLs per
scan; invalid or disallowed URLs are recorded as `invalid` targets rather
than rejecting the whole request. The response includes the new scan's `id`
with `status: "pending"` — the scan runs in the background.

### Check scan results

```
curl localhost:3000/scans/:id
```

Returns the scan with its `status` (`pending` / `running` / `completed` /
`failed`), each target's raw response data, and any findings recorded for
that target.

### List all scans

```
curl localhost:3000/scans
```

Returns scans newest first.

### Dashboard

Visit `http://localhost:3000/dashboard` in a browser for an HTML view of
scans and their targets/findings.
