# Passive check depth

## Problem

Colossus reports on a narrow slice of what a single response already tells it.
It checks whether a handful of security headers are *present*, never whether
they are set to anything useful, and it never looks at the response body at
all — so a site with `Content-Security-Policy: default-src *`, a login form
posting over plaintext, and an exposed `/.env` scans clean. Separately, the
detectors doing this work are buried in a 783-line `scanner.ts` alongside
SSRF guarding, OSV correlation and LLM enrichment, and the remediation advice
attached to findings is matched to them by array position, so a truncated or
reordered LLM response silently puts the HSTS fix on the CORS finding.

## Solution

Extract every pure detector out of `scanner.ts` into a single
`passive-checks.ts` module that takes response data and returns findings with
no I/O, then deepen the passive check set behind that interface: header
*quality* checks for headers that are present but weak, body-derived checks
over an HTML document parsed once per target, and a small fixed probe for
commonly-exposed files. Enrichment is re-keyed so remediation advice can no
longer land on the wrong finding, and the response body is threaded through
the pipeline in memory without ever being persisted.

## User stories

- As the operator, I can see when a target's CSP is present but permissive, so
  that a header set to `unsafe-inline` does not read as protection.
  - Acceptance: a response with `script-src 'unsafe-inline'` produces
    `weak-csp-unsafe-inline` at high severity, `possible` confidence.
- As the operator, I can see when a CSP is report-only, so that I know nothing
  is actually being enforced.
  - Acceptance: a `Content-Security-Policy-Report-Only` header with no
    enforcing policy produces **both** `csp-report-only-only` and the existing
    `missing-csp`.
- As the operator, I can see when HSTS is set to a `max-age` too short to
  matter, so that a two-minute policy does not pass as HSTS.
  - Acceptance: `max-age` under 15552000 produces `weak-hsts-short-max-age`,
    medium, `definitive`.
- As the operator, I can see when HSTS omits subdomains.
  - Acceptance: a policy without `includeSubDomains` produces
    `weak-hsts-no-subdomains`, low, `definitive`.
- As the operator, I can see when a CORS policy is permissive *and*
  credentialed, so that I can tell the dangerous case from the merely open one.
  - Acceptance: `Allow-Origin: *` or a reflected origin together with
    `Allow-Credentials: true` produces `permissive-cors-credentialed` at high;
    the same origin policy without credentials produces
    `permissive-cors-wildcard` at low.
- As the operator, I can see which software versions a target advertises in its
  headers.
  - Acceptance: a `Server`, `X-Powered-By` or `X-AspNet-Version` header
    revealing software produces `information-disclosure-header`, low.
- As the operator, I can see when an HTTPS page pulls subresources over
  plaintext.
  - Acceptance: an `https://` page referencing an `http://` script, style or
    iframe produces `mixed-content`, medium, `definitive`.
- As the operator, I can see when a form posts over plaintext.
  - Acceptance: a `<form action>` resolving to `http://` produces
    `insecure-form-action`, high, `definitive`.
- As the operator, I can see when a password field permits credential
  autofill.
  - Acceptance: an `<input type=password>` without
    `autocomplete="new-password"`/`"current-password"` produces
    `password-field-autocomplete`, low, `possible`.
- As the operator, I can see when a target is serving a directory listing.
  - Acceptance: a response matching an index-of shape produces
    `directory-listing`, medium, `possible`.
- As the operator, I get CVEs for versions revealed in the HTML, not just in
  headers.
  - Acceptance: a `<meta name=generator content="X 1.2.3">` reaches
    `extractVersionBanner` and surfaces as `known-vulnerability` through the
    existing OSV path — no second CVE pathway, and no category of its own.
- As the operator, I can see when a target is exposing a `.git` directory or a
  `.env` file.
  - Acceptance: `/.git/HEAD` returning 200 with `ref:` content produces
    `exposed-git-directory`, critical; `/.env` returning 200 with env-shaped
    content produces `exposed-env-file`, critical.
- As the operator, I do not get an exposed-file finding on every target that
  returns a 200 SPA shell for unknown paths.
  - Acceptance: a stub returning 200 HTML for every path produces no
    exposed-file findings — content shape is checked, not just status.
- As the operator, I can see when a target publishes a `security.txt`.
  - Acceptance: `/.well-known/security.txt` returning 200 produces
    `security-txt-present` at `info`, rendered by the dashboard as
    information and not as an alarm.
- As the operator, I get remediation advice attached to the finding it
  describes, or no advice at all.
  - Acceptance: an LLM response covering a subset of findings, in the wrong
    order, enriches exactly those findings correctly and leaves the rest null.
- As the operator, I keep the precise explanation a detector wrote.
  - Acceptance: a cookie finding retains `Cookie "session" is missing the
    Secure attribute` rather than having it replaced by an LLM paraphrase;
    `suggestedFix` still comes from the LLM.
- As the operator, a hostile or enormous response body cannot exhaust my
  scanner.
  - Acceptance: a body over 2 MB is truncated and detectors run on the prefix;
    a body that fails mid-stream leaves the target `ok` with header and TLS
    findings intact.
- As the operator, probing for exposed files cannot turn one target into a
  flood of requests.
  - Acceptance: no target issues more than `maxExtraRequests` requests beyond
    its primary fetch.

## Data model

No schema change. This is deliberate, and it is the constraint that keeps the
work reviewable:

- Every new check is an ordinary `findings` row. `category` is already free
  text, `severity` and `confidence` already carry the needed values, and
  `info` is already a valid `FindingSeverity`.
- `explanation` and `suggestedFix` are already nullable, so re-keying
  enrichment needs no migration and existing rows keep their stored values.
- The response body is **not** persisted anywhere — not in `scan_targets`, not
  on disk. Persisting bodies is a real storage, size and PII decision, and
  nothing in the check set needs the body once its detectors have run.
- Findings stored before this work keep their old categories. Only new scans
  emit the new ones.

## Modules

```
NEW      passive-checks.ts   — every pure detector: headers, cookies, TLS,
                               weak-header quality, body-derived checks,
                               version-banner extraction
MODIFY   scanner.ts          — orchestration only: fetch, body read + single
                               parse, probe fan-out under a request allowance,
                               keyed LLM enrichment, OSV correlation
```

`passive-checks.ts`:

```ts
export function detectFindings(input: PassiveInput): PendingFinding[]
export function extractVersionBanner(input: PassiveInput): string | null
export type PassiveInput = { headers: Record<string,string>; setCookies: string[];
                             document?: CheerioAPI; tls?: TlsInfo; url: URL }
```

One entry point, no I/O, no mocks needed to test it. Roughly twenty detectors
live behind it and callers never see an individual one.

`scanner.ts` keeps its existing constructor-options seam, gaining
`maxExtraRequests`. No new exported surface.

Per `CONTEXT.md`, `passive-checks.ts` must not import from
`active-scanner.ts` in either direction: mode selects which detector sets run,
and the passive/active split only holds if the code reflects it.

## Implementation decisions

- **Extraction runs after active scanning ships**, not before. `011`-`013`
  touch `#processTarget`/`#runScan` orchestration while the extraction moves
  detectors, so the two barely overlap — the file gets longer, but not in the
  region that gets cut.
- **`ssrf-guard.ts` is already extracted** by the active-scanning work, which
  has to split it out to avoid an import cycle. The extraction here does not
  touch the guard.
- **OSV correlation and LLM enrichment stay in `scanner.ts`.** Splitting them
  is the better end state but stops the extraction being a behavior-free diff,
  and enrichment is being modified in the same window.
- **Body is read in memory, bounded at 2 MB, and discarded** after its
  detectors run.
- **The detector boundary receives a parsed document, not a raw string**, so
  the body-derived checks, the generator-tag banner path and the later
  discovery crawl share a single parse of hostile input.
- **Parser is `cheerio`.** Every consumer is doing selector-and-attribute
  extraction, and cheerio is `parse5` underneath — spec-compliant parsing with
  the ergonomic layer. `parse5` alone means hand-walking the tree in every
  detector; `jsdom` is a full DOM over hostile input, the cost the 2 MB bound
  exists to avoid. The dependency lands with the body threading, not with the
  checks that consume it.
- **Enrichment is keyed by a synthetic per-finding id** (`f0`, `f1`, …) sent
  in the prompt and echoed back. It cannot be keyed by category: cookie
  detection already emits one finding per missing attribute *per cookie*, so
  three insecure cookies produce three findings sharing
  `cookie-missing-secure`. Category is not unique today, before any new check
  is added.
- **Detector explanations take precedence over LLM ones.** A detector's
  explanation is a fact about the response; the LLM's is a paraphrase of a
  category name. The LLM fills only where the detector left `explanation`
  null. `suggestedFix` stays LLM-owned.
- **Exposed-file probing is passive** and needs no authorization attestation:
  these are ordinary GETs for ordinary paths, sending no payload designed to
  trigger a vulnerability. The scanner already makes an unsubmitted request of
  this shape for `robots.txt`.
- **Probe fan-out is bounded by a per-target request allowance**
  (`maxExtraRequests`, default ~6) covering every request beyond the primary
  fetch, enforced in one place so the later discovery crawl reuses it. A
  global in-flight semaphore was rejected: it protects the machine but not the
  target, which is the party there is an attestation with.
- **This allowance is not the active-scan browser cap.** That one bounds
  concurrent browser contexts in active mode; this bounds HTTP requests per
  target in passive mode. Different resource.
- **The probe wordlist stays single digits.** This is a fetch, not a
  content-discovery scan.
- **Probes respect the same SSRF guard, user-agent and timeout handling** as
  the primary fetch.
- **The severity/confidence table for weak headers is reviewed at PR time**
  against real scan output, not cold beforehand. The rows expected to draw
  argument are `weak-csp-unsafe-inline` at high and `permissive-cors-wildcard`
  at low.
- **Confidence grades the certainty of the observation, not of
  exploitability** (per `CONTEXT.md`), so contextual defects like a permissive
  CSP are `possible` while being definitely present; attribute absence is
  `definitive`.

## Testing decisions

- **`passive-checks.ts` is tested directly, with no mocks.** It takes response
  data and returns findings, so every check is a pure input/output assertion.
  This is the seam that makes the extraction worth doing.
- **`scanner.ts` is tested at the `fetch` boundary**, as it is today: stubbed
  responses in, findings and target rows out.
- **The extraction itself is verified by unchanged assertions.**
  `npx vitest run src/services` stays green with no test *assertion* edited —
  only the file the tests live in. A diff review showing behavioral change
  means the extraction is wrong.
- **Enrichment keying is tested against a deliberately hostile stub**: an LLM
  response covering a subset of findings, in the wrong order. The current code
  misattributes; the new code must enrich exactly the covered findings and
  leave the rest null.
- **Body handling is tested for its failure modes, not just its happy path**:
  oversized body truncated, mid-stream failure leaving header findings intact.
- **Probing is tested for the false-positive case as well as the true one**: a
  stub returning 200 HTML for every path must produce nothing.

Deliberately untested:

- **`cheerio`'s parsing itself.** It is a dependency with its own suite;
  testing it here tests someone else's code.
- **Real network behavior of probes.** Every request goes through the existing
  stubbed `fetch` seam; there is no live-target test.
- **Dashboard rendering of `info` findings** beyond confirming
  `security-txt-present` is not displayed as an alarm — this is the first
  `info` finding in the codebase and the check is a look, not a test.

## Out of scope

- **Parsing CSP into a full directive model** — string and directive
  inspection is enough for the checks listed.
- **Validating CSP hashes or nonces** — no check needs them.
- **Cookie value analysis** (entropy, JWT decoding, PII sniffing) — a
  different kind of check with a different false-positive profile.
- **`__Host-`/`__Secure-` prefix validation** — worth doing, not now.
- **Executing JavaScript or checking dynamically-inserted content** — static
  inspection only; a headless browser belongs to active scanning.
- **Secret and API-key scanning in HTML or inline scripts** — the
  false-positive design is a whole conversation, so it gets its own issue.
- **Following or fetching any referenced subresource** — body checks read the
  markup, they do not request what it points at.
- **Storing the response body anywhere** — a storage, size and PII decision
  nothing here needs.
- **Splitting OSV correlation and LLM enrichment into their own modules** —
  the right end state, but it would stop the extraction being a behavior-free
  diff while enrichment is concurrently changing.
- **Chunking or capping the enrichment batch size** — cost is bounded and
  already cached; the keying work is about correctness, not spend.
- **Re-enriching or recategorising historical findings** — old rows keep what
  they have; there is no migration.
- **Any wordlist worth the name** — no `dirb`/`SecLists`-scale enumeration.
- **Downloading or parsing the contents of an exposed `.git` directory** —
  reporting exposure is the finding; exploiting it is not.
- **Link and form discovery from the parsed body** — the crawl is phase 3 and
  has its own PRD; it consumes this parse, it is not built by it.
