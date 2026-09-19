import { load, type CheerioAPI } from 'cheerio';
import type { FindingConfidence, FindingSeverity } from '../db/schema.js';

// The detector boundary carries a parsed document rather than a raw string: three
// consumers (body-derived checks, the generator-tag banner path, link discovery)
// each want selectors over the same up-to-2 MB, hostile body, and re-parsing it
// per consumer is pure waste. `url` travels with it because resolving a relative
// `action`/`src` needs the page it came from.
export type PageDocument = { $: CheerioAPI; url: URL };

export function parsePageDocument(html: string, url: URL): PageDocument {
  return { $: load(html), url };
}

export type HeaderFinding = {
  category: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  explanation?: string;
};

// Severity is not pinned by the PRD beyond the five-value scale, so this is a
// judgment call: missing HSTS/CSP allow the broadest attacks (no encryption
// enforcement / arbitrary script injection) so they skew high; framing and
// MIME-sniffing protections are narrower in impact, so they sit lower.
const MISSING_HEADER_FINDINGS: { header: string; category: string; severity: FindingSeverity }[] = [
  { header: 'content-security-policy', category: 'missing-csp', severity: 'high' },
  { header: 'strict-transport-security', category: 'missing-hsts', severity: 'high' },
  { header: 'x-frame-options', category: 'missing-x-frame-options', severity: 'medium' },
  { header: 'x-content-type-options', category: 'missing-x-content-type-options', severity: 'low' },
  { header: 'referrer-policy', category: 'missing-referrer-policy', severity: 'low' },
  { header: 'permissions-policy', category: 'missing-permissions-policy', severity: 'low' },
];

// One finding per missing attribute, per cookie — a `Record<string,string>` can only
// ever hold the last of several `Set-Cookie` headers, so this takes the raw multi-value
// list (from `Headers.getSetCookie()`) rather than the collapsed header record.
const COOKIE_ATTRIBUTE_CHECKS: { category: string; label: string; isMissing: (attrs: string[]) => boolean }[] = [
  { category: 'cookie-missing-secure', label: 'Secure', isMissing: (attrs) => !attrs.includes('secure') },
  { category: 'cookie-missing-httponly', label: 'HttpOnly', isMissing: (attrs) => !attrs.includes('httponly') },
  {
    category: 'cookie-missing-samesite',
    label: 'SameSite',
    isMissing: (attrs) => !attrs.some((attr) => attr.startsWith('samesite=')),
  },
];

function detectCookieFindings(setCookies: string[]): HeaderFinding[] {
  const result: HeaderFinding[] = [];

  for (const setCookie of setCookies) {
    const [nameValue, ...attrParts] = setCookie.split(';');
    const name = nameValue?.split('=')[0]?.trim() || 'unknown';
    const attrs = attrParts.map((part) => part.trim().toLowerCase());

    for (const check of COOKIE_ATTRIBUTE_CHECKS) {
      if (check.isMissing(attrs)) {
        result.push({
          category: check.category,
          severity: 'medium',
          confidence: 'definitive',
          explanation: `Cookie "${name}" is missing the ${check.label} attribute.`,
        });
      }
    }
  }

  return result;
}

// `confidence` grades the certainty of the *observation*, not of exploitability
// (per CONTEXT), so contextual defects below are `possible` while still being
// definitely present: a report-only CSP or a permissive CORS policy on a public
// API can both be deliberate. The severity/confidence assignments in issue 018
// were reviewed by a human before this landed.

type CspDirectives = Map<string, string[]>;

function parseCsp(policy: string): CspDirectives {
  const directives: CspDirectives = new Map();
  for (const part of policy.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) directives.set(name.toLowerCase(), values.map((v) => v.toLowerCase()));
  }
  return directives;
}

// Deliberately string/directive-level, not a full CSP model (out of scope per 018):
// `script-src` is consulted before `default-src` because it overrides it for scripts,
// but a keyword in either is reported once, not twice.
function detectCspFindings(headers: Record<string, string>): HeaderFinding[] {
  const policy = headers['content-security-policy'];
  const reportOnly = headers['content-security-policy-report-only'];
  const result: HeaderFinding[] = [];

  if (policy === undefined) {
    // `missing-csp` is emitted separately by MISSING_HEADER_FINDINGS; a report-only
    // policy is additionally called out, since the enforcing policy genuinely is absent.
    if (reportOnly !== undefined) {
      result.push({
        category: 'csp-report-only-only',
        severity: 'medium',
        confidence: 'possible',
        explanation: 'Only a Content-Security-Policy-Report-Only header is set, so the policy is monitored but never enforced.',
      });
    }
    return result;
  }

  const directives = parseCsp(policy);
  const scriptSources = directives.get('script-src') ?? directives.get('default-src') ?? [];

  if (scriptSources.includes("'unsafe-inline'")) {
    result.push({
      category: 'weak-csp-unsafe-inline',
      severity: 'high',
      confidence: 'possible',
      explanation: "The policy allows 'unsafe-inline' scripts, which defeats most of the XSS protection a CSP provides.",
    });
  }

  if (scriptSources.includes("'unsafe-eval'")) {
    result.push({
      category: 'weak-csp-unsafe-eval',
      severity: 'medium',
      confidence: 'possible',
      explanation: "The policy allows 'unsafe-eval', permitting string-to-code execution.",
    });
  }

  if (directives.get('default-src')?.includes('*') === true) {
    result.push({
      category: 'weak-csp-wildcard-default-src',
      severity: 'high',
      confidence: 'possible',
      explanation: 'default-src * allows content to be loaded from any origin.',
    });
  }

  if (!directives.has('frame-ancestors')) {
    result.push({
      category: 'weak-csp-missing-frame-ancestors',
      severity: 'low',
      confidence: 'possible',
      explanation: 'The policy sets no frame-ancestors directive, so it places no CSP-level restriction on framing.',
    });
  }

  return result;
}

// 180 days, the floor the HSTS preload list requires.
const MIN_HSTS_MAX_AGE_SECONDS = 15552000;

function detectHstsFindings(headers: Record<string, string>): HeaderFinding[] {
  const policy = headers['strict-transport-security'];
  if (policy === undefined) return [];

  const result: HeaderFinding[] = [];
  const normalized = policy.toLowerCase();
  const maxAge = Number(/max-age\s*=\s*"?(\d+)/.exec(normalized)?.[1] ?? NaN);

  // A malformed or absent max-age is treated as weak: it provides no enforcement window.
  if (!Number.isFinite(maxAge) || maxAge < MIN_HSTS_MAX_AGE_SECONDS) {
    result.push({
      category: 'weak-hsts-short-max-age',
      severity: 'medium',
      confidence: 'definitive',
      explanation: `HSTS max-age is ${Number.isFinite(maxAge) ? `${maxAge} seconds` : 'missing or unparseable'}, below the recommended ${MIN_HSTS_MAX_AGE_SECONDS} (180 days).`,
    });
  }

  if (!normalized.includes('includesubdomains')) {
    result.push({
      category: 'weak-hsts-no-subdomains',
      severity: 'low',
      confidence: 'definitive',
      explanation: 'HSTS does not set includeSubDomains, so subdomains are not covered.',
    });
  }

  return result;
}

// Only a literal `*` is detected. A policy that *reflects* the request Origin is
// indistinguishable from a correct one in a single response that carried no Origin
// header, so catching it needs a second, Origin-bearing request — its own issue.
function detectCorsFindings(headers: Record<string, string>): HeaderFinding[] {
  if (headers['access-control-allow-origin'] !== '*') return [];

  if (headers['access-control-allow-credentials']?.trim().toLowerCase() === 'true') {
    return [
      {
        category: 'permissive-cors-credentialed',
        severity: 'high',
        confidence: 'definitive',
        explanation: 'A wildcard Access-Control-Allow-Origin is combined with Access-Control-Allow-Credentials: true.',
      },
    ];
  }

  return [
    {
      category: 'permissive-cors-wildcard',
      severity: 'low',
      confidence: 'possible',
      explanation: 'Access-Control-Allow-Origin is *, which is intended for public resources but exposes any non-public ones.',
    },
  ];
}

const DISCLOSURE_HEADER_NAMES = ['server', 'x-powered-by', 'x-aspnet-version'];
// A bare version (`X-AspNet-Version: 4.0.30319`) discloses as much as `nginx/1.18.0`,
// but carries no slash, so BANNER_PATTERN alone would miss it.
const BARE_VERSION_PATTERN = /^\d[\w.-]*$/;

// Naming the software is not itself the finding: `Server: cloudflare` gives an
// attacker nothing to match against a CVE feed. A version does.
function detectDisclosureFindings(headers: Record<string, string>): HeaderFinding[] {
  const result: HeaderFinding[] = [];

  for (const headerName of DISCLOSURE_HEADER_NAMES) {
    const value = headers[headerName]?.trim();
    if (value === undefined) continue;
    if (!BANNER_PATTERN.test(value) && !BARE_VERSION_PATTERN.test(value)) continue;

    result.push({
      category: 'information-disclosure-header',
      severity: 'low',
      confidence: 'definitive',
      explanation: `The ${headerName} header reveals a software version ("${value}").`,
    });
  }

  return result;
}

// Body-derived checks read the markup only: nothing here follows or fetches a
// referenced subresource, and no JavaScript is executed, so a defect inserted at
// runtime is invisible to them by design.
function detectBodyFindings(doc: PageDocument): HeaderFinding[] {
  const result: HeaderFinding[] = [];
  const { $, url } = doc;

  // Only meaningful on an https page: an http page referencing http is not "mixed".
  if (url.protocol === 'https:') {
    const insecure = $('script[src], link[href], iframe[src]')
      .toArray()
      .map((el) => $(el).attr('src') ?? $(el).attr('href') ?? '')
      .filter((ref) => /^http:\/\//i.test(ref));

    if (insecure.length > 0) {
      result.push({
        category: 'mixed-content',
        severity: 'medium',
        confidence: 'definitive',
        explanation: `The page is served over HTTPS but references ${insecure.length} subresource(s) over plaintext HTTP, e.g. "${insecure[0]}".`,
      });
    }
  }

  // A form's action is resolved against the page URL first: a relative action on an
  // http page submits over plaintext just as surely as an absolute http:// one, and
  // a form with no action at all submits back to the page itself.
  const insecureActions = $('form')
    .toArray()
    .map((el) => {
      const action = $(el).attr('action');
      try {
        return new URL(action === undefined || action === '' ? url.href : action, url);
      } catch {
        return null;
      }
    })
    .filter((resolved): resolved is URL => resolved !== null && resolved.protocol === 'http:');

  if (insecureActions.length > 0) {
    result.push({
      category: 'insecure-form-action',
      severity: 'high',
      confidence: 'definitive',
      explanation: `A form submits to "${insecureActions[0]?.href}" over plaintext HTTP, exposing whatever is typed into it.`,
    });
  }

  // `possible`, not `definitive`: the field is definitely unannotated, but whether
  // that matters depends on the form — hence the low severity too. Only the two
  // password-manager-aware values count; `off` is not a substitute, browsers
  // increasingly ignore it.
  const unannotatedPasswords = $('input')
    .toArray()
    .filter((el) => ($(el).attr('type') ?? '').trim().toLowerCase() === 'password')
    .filter((el) => !['current-password', 'new-password'].includes(($(el).attr('autocomplete') ?? '').trim().toLowerCase()));

  if (unannotatedPasswords.length > 0) {
    result.push({
      category: 'password-field-autocomplete',
      severity: 'low',
      confidence: 'possible',
      explanation: `${unannotatedPasswords.length} password field(s) set no autocomplete="current-password"/"new-password", leaving the browser to guess how to handle them.`,
    });
  }

  // The autoindex pages of Apache, nginx, IIS and lighttpd all announce themselves
  // in the title or the first heading ("Index of /path", "Directory listing for /").
  // Matching that, rather than the link shapes in the body, is what keeps an
  // ordinary page that happens to link to a directory out of the results — hence
  // `possible`: a hand-written page is free to carry the same title.
  const listingText = [$('title').first().text(), $('h1').first().text()].join(' ');
  if (/\b(index of|directory listing (for|of))\s*\//i.test(listingText)) {
    result.push({
      category: 'directory-listing',
      severity: 'medium',
      confidence: 'possible',
      explanation: 'The response looks like an automatically generated directory listing, which exposes file names the server was not asked to publish.',
    });
  }

  return result;
}

export function detectHeaderFindings(
  headers: Record<string, string>,
  setCookies: string[] = [],
  doc: PageDocument | null = null,
): HeaderFinding[] {
  const result: HeaderFinding[] = MISSING_HEADER_FINDINGS.filter(({ header }) => !(header in headers)).map(
    ({ category, severity }) => ({ category, severity, confidence: 'definitive' }),
  );

  result.push(...detectCookieFindings(setCookies));
  result.push(...detectCspFindings(headers));
  result.push(...detectHstsFindings(headers));
  result.push(...detectCorsFindings(headers));
  result.push(...detectDisclosureFindings(headers));
  if (doc !== null) result.push(...detectBodyFindings(doc));

  return result;
}

export type TlsInfo = { version: string; certExpiresAt: Date };
export type TlsFinding = { category: string; severity: FindingSeverity; confidence: FindingConfidence };

const OUTDATED_TLS_VERSIONS = new Set(['TLSv1', 'TLSv1.1']);
const CERT_EXPIRY_WARNING_DAYS = 30;
const MS_PER_DAY = 1000 * 60 * 60 * 24;

export const NO_TLS_FINDING: TlsFinding = { category: 'no-tls', severity: 'high', confidence: 'definitive' };

export function detectTlsFindings(info: TlsInfo, now: Date = new Date()): TlsFinding[] {
  const result: TlsFinding[] = [];

  if (OUTDATED_TLS_VERSIONS.has(info.version)) {
    result.push({ category: 'outdated-tls', severity: 'high', confidence: 'definitive' });
  }

  const daysUntilExpiry = (info.certExpiresAt.getTime() - now.getTime()) / MS_PER_DAY;
  if (daysUntilExpiry <= CERT_EXPIRY_WARNING_DAYS) {
    result.push({ category: 'cert-expiring-soon', severity: 'medium', confidence: 'definitive' });
  }

  return result;
}

export type VersionBanner = { software: string; version: string };

// Neither the PRD nor the issue pins an exact banner source, so this is a judgment
// call: `name/version` is the de-facto convention for both the Server and
// X-Powered-By headers (e.g. `nginx/1.18.0`, `PHP/7.4.3`), and some software repeats
// that same convention in a robots.txt comment. Headers are checked first since
// they're the more reliable signal; robots.txt is only consulted if neither matches.
const BANNER_HEADER_NAMES = ['server', 'x-powered-by'];
// The quantifiers are bounded, not open-ended: `[\w.-]*` before a required `/` makes
// this quadratic on a long run of non-matching characters, and this pattern is run
// over an attacker-controlled robots.txt. No real banner approaches 64 characters.
const BANNER_PATTERN = /([A-Za-z][\w.-]{0,63})\/(\d[\w.-]{0,63})/;

// A generator tag writes its version with a space, not a slash ("WordPress 6.4.1"),
// so BANNER_PATTERN alone would miss it. It deliberately produces a banner rather
// than a finding of its own: the version then flows through the one existing OSV
// correlation path and surfaces as `known-vulnerability`, instead of opening a
// second, parallel CVE pathway.
const GENERATOR_PATTERN = /^([A-Za-z][\w.-]*(?:\s[A-Za-z][\w.-]*)*?)[\s/]v?(\d[\w.-]*)/;

function generatorBanner(doc: PageDocument): VersionBanner | null {
  const content = doc.$('meta[name="generator"]').first().attr('content')?.trim();
  if (content === undefined) return null;

  const match = GENERATOR_PATTERN.exec(content);
  if (match?.[1] === undefined || match[2] === undefined) return null;
  return { software: match[1], version: match[2] };
}

export function extractVersionBanner(
  headers: Record<string, string>,
  robotsBody: string | null,
  doc: PageDocument | null = null,
): VersionBanner | null {
  for (const headerName of BANNER_HEADER_NAMES) {
    const value = headers[headerName];
    if (value === undefined) continue;
    const match = BANNER_PATTERN.exec(value);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { software: match[1], version: match[2] };
    }
  }

  // The page's own generator tag outranks a robots.txt comment: it is emitted by
  // the software itself, where a robots.txt banner is often a stale copied template.
  if (doc !== null) {
    const banner = generatorBanner(doc);
    if (banner !== null) return banner;
  }

  if (robotsBody !== null) {
    const match = BANNER_PATTERN.exec(robotsBody);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { software: match[1], version: match[2] };
    }
  }

  return null;
}
