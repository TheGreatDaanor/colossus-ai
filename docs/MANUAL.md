# Colossus operator manual

How to run the scanner, start scans, and read the results — including on a
headless server with no browser.

Everything is driven over HTTP with `curl`. The examples assume the server is on
`localhost:3000`.

---

## 1. Start the server

```
npm install
npm run dev
```

You should see:

```
scanner listening on http://localhost:3000
```

That terminal now belongs to the server: it shows the server's log and does not
take input. **Leave it running and open a second terminal** (or a second SSH
session, or run the server under `tmux`) for everything below. Stop the server
with `Ctrl+C`.

### Configuration

All optional, set as environment variables before `npm run dev`:

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `DB_PATH` | `./data/scanner.db` | SQLite database file |
| `SCANNER_USER_AGENT` | `colossus-scanner/1.0` | User-Agent sent to targets |
| `ANTHROPIC_API_KEY` | unset | Enables LLM explanations on findings |
| `ENUMERATION_CADENCE_MS` | 24 h | How stale a program's inventory may get before re-enumeration |
| `ENUMERATION_SWEEP_MS` | 1 h | How often the scheduler checks for stale programs |
| `COLLABORATOR_BASE_DOMAIN`, `COLLABORATOR_QUERY_URL`, `COLLABORATOR_SECRET` | unset | SSRF callback listener — see [§6](#6-ssrf-and-the-collaborator) |

---

## 2. Start a scan

### Passive scan (default)

Fetches each URL and runs non-intrusive checks (headers, cookies, TLS, CVEs,
exposed files, …). No attack payloads.

```
curl -s -X POST localhost:3000/scans \
  -H 'content-type: application/json' \
  -d '{"urls":["https://example.com"],"name":"my first scan"}'
```

### Active scan

Also sends attack payloads (XSS, SSTI, SQLi, LFI, CRLF, SSRF) into each URL's
query parameters. **Only scan targets you are authorized to test.** You must
attest to that with `confirmAuthorized: true`, or the request is rejected.

```
curl -s -X POST localhost:3000/scans \
  -H 'content-type: application/json' \
  -d '{"urls":["https://target.example/page?url=test"],"mode":"active","confirmAuthorized":true,"name":"active check"}'
```

Injection checks only test **query parameters**, so include at least one
(`?url=test` above) or there is nothing to inject into.

### Body fields

| Field | Required | Notes |
|---|---|---|
| `urls` | yes (unless `programId`) | Up to 100. Invalid or disallowed URLs become `invalid` targets rather than failing the scan |
| `name` | no | Defaults to a timestamp |
| `mode` | no | `"passive"` (default) or `"active"` |
| `confirmAuthorized` | for active | Must be `true` in active mode |
| `authorizationNote` | no | Free text recorded with the scan (e.g. the engagement reference) |
| `userAgent` | no | Overrides `SCANNER_USER_AGENT` for this scan |
| `programId` | no | Scan a program's in-scope inventory — see [§5](#5-programs-scope-and-enumeration) |
| `identities`, `confirmIdentitiesAuthorized` | no | Access-control (IDOR) testing — see below |

The response is JSON with the new scan's `id` and `status: "pending"`. The scan
runs in the background.

### Access-control testing (optional)

To check whether one user can read another's resources, pass two or more
identities and attest with `confirmIdentitiesAuthorized: true`:

```
"identities": [
  {"label":"alice","headers":{"Cookie":"session=..."},"privateUrls":["https://target.example/api/orders/1"]},
  {"label":"bob","headers":{"Cookie":"session=..."},"privateUrls":["https://target.example/api/orders/2"]}
],
"confirmIdentitiesAuthorized": true
```

Each identity's private URLs are replayed with the other identities' headers
and with none.

---

## 3. Check progress and results

```
curl -s localhost:3000/scans            # all scans, newest first
curl -s localhost:3000/scans/<id>       # one scan, with targets and findings
```

`status` moves `pending` → `running` → `completed` (or `failed`). The single-scan
response includes `findings_by_severity` and, per target, its raw response data
and findings.

Handy filters if you have `jq`:

```
curl -s localhost:3000/scans/<id> | jq '.status'
curl -s localhost:3000/scans/<id> | jq '[.targets[].findings[] | {category, severity, confidence}]'
```

---

## 4. The dashboard

An HTML view of scans, targets and findings.

- `http://localhost:3000/dashboard` — scan list
- `http://localhost:3000/dashboard/scans/<id>` — one scan's report

These are **web pages**: open them in a browser, not in the terminal.

### On a headless server

Pick one:

**a) Tunnel to your own machine (recommended — you see the real page).** On
your laptop:

```
ssh -L 3000:localhost:3000 <user>@<server>
```

then open `http://localhost:3000/dashboard` in your laptop's browser.

**b) Read it as text on the server:**

```
curl -s localhost:3000/dashboard/scans/<id> | sed 's/<[^>]*>/ /g' | tr -s ' \n'
```

**c) Use a terminal browser**, if installed: `w3m http://localhost:3000/dashboard`
or `lynx http://localhost:3000/dashboard`.

### Reading a scan report

- **Targets** are marked by source: `submitted` (you typed it), `inventory`
  (from a program's enumeration) or `discovered` (found by the crawl).
- **Findings** carry `severity` (how bad) and `confidence`: `definitive` means
  the observation is a fact; `possible` means it is true but may be intentional.
- **SSRF findings** show their proof as labeled fields: param, protocols, caller
  egress IP, tier (`oob` callback or `internal-read`), matched signature, and
  "metadata read: not demonstrated" when the callback was proven but cloud
  credential theft was not. No response body is ever shown.
- **"SSRF: not tested"** — a summary at the top of the report, and a line per
  parameter in each target row, whenever SSRF could not run. A report without
  SSRF findings is only a clean SSRF result if this summary is **absent**. The
  reason says why, e.g. `collaborator-not-configured`.

---

## 5. Programs, scope and enumeration

A program is one engagement: a scope (in/out lists) plus an inventory of hosts
discovered for it.

```
# create from a URL (its apex becomes an inferred in-scope entry)
curl -s -X POST localhost:3000/programs -H 'content-type: application/json' \
  -d '{"url":"https://example.com","name":"Example bounty"}'

curl -s localhost:3000/programs/<id>                       # program + scope entries
```

Inferred scope entries must be **confirmed** before they are used. Confirming
authorizes testing the whole domain and every subdomain:

```
curl -s -X POST localhost:3000/programs/<id>/scope/<entryId>/confirm
```

Edit scope:

```
curl -s -X POST localhost:3000/programs/<id>/scope -H 'content-type: application/json' \
  -d '{"list":"out","pattern":"*.internal.example.com"}'
curl -s -X DELETE localhost:3000/programs/<id>/scope/<entryId>
curl -s 'localhost:3000/programs/<id>/classify?host=a.example.com'   # in_scope / out_of_scope / unscoped
```

Enumerate subdomains (certificate-transparency logs) and view the inventory:

```
curl -s -X POST localhost:3000/programs/<id>/enumerate
curl -s localhost:3000/programs/<id>/hosts
```

Hosts marked `is_new` appeared since the previous enumeration. The server also
re-enumerates automatically on the `ENUMERATION_CADENCE_MS` cadence.

Scan the in-scope inventory:

```
curl -s -X POST localhost:3000/scans -H 'content-type: application/json' \
  -d '{"programId":<id>,"urls":[]}'
```

Check for subdomain takeovers (dangling CNAMEs):

```
curl -s -X POST localhost:3000/programs/<id>/takeovers   # run the check
curl -s localhost:3000/programs/<id>/takeovers           # last results
```

---

## 6. SSRF and the collaborator

SSRF is confirmed out-of-band: the payload points the target at a unique URL on
a callback listener (the *collaborator*), and a callback proves the target made
the request.

Without a collaborator, active scans still run, but every parameter's SSRF
attempt is reported **not tested** (`collaborator-not-configured`) — visible in
the report summary.

To enable it, deploy the listener and set the three `COLLABORATOR_*` variables;
full steps in [collaborator-runbook.md](collaborator-runbook.md). Common
not-tested reasons:

| Reason | Meaning |
|---|---|
| `collaborator-not-configured` | `COLLABORATOR_*` not set (or only partly set — check the startup log) |
| `collaborator-self-test-failed: …` | The pre-scan self-test failed; the message names the broken piece |
| `collaborator-unreachable-mid-drain` | The listener stopped answering while results were being collected |

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| Terminal shows only `scanner listening…` and won't take input | Normal — the server is running. Use a second terminal. |
| `400 mode: "active" requires confirmAuthorized: true` | Add `"confirmAuthorized": true` |
| Active scan finds no injection results | The URL has no query parameters to inject into |
| Every target `invalid` | URL is not http(s), or resolves to a private/internal address (blocked by the SSRF guard) |
| Findings have no explanations | `ANTHROPIC_API_KEY` not set |
| `EADDRINUSE` on start | Another process holds the port; stop it or set `PORT` |
