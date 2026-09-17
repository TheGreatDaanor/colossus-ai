import * as cheerio from 'cheerio';
import type { FindingConfidence, FindingSeverity } from '../db/schema.js';

// The detector boundary receives an already-parsed document, not a raw string, so the
// several body-derived consumers (tag/attribute checks, generator-tag banners, later
// link/form harvesting) don't each re-parse the same up-to-2 MB hostile body. cheerio
// is parse5 underneath — spec-compliant parsing — without hand-walking the tree.
export type PassiveDocument = cheerio.CheerioAPI;

export function parsePassiveDocument(html: string): PassiveDocument {
  return cheerio.load(html);
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

// Resolves a markup-supplied URL against the page; an unparseable value is ignored
// rather than guessed at.
function resolveAgainst(value: string | undefined, pageUrl: URL): URL | null {
  if (value === undefined || value.trim() === '') return null;
  try {
    return new URL(value, pageUrl);
  } catch {
    return null;
  }
}

// Only subresources a browser would block or that can rewrite the page are counted;
// passive content (images, media) is out of scope for this check.
const MIXED_CONTENT_SOURCES: { selector: string; attr: string }[] = [
  { selector: 'script[src]', attr: 'src' },
  { selector: 'link[rel~="stylesheet" i][href]', attr: 'href' },
  { selector: 'iframe[src]', attr: 'src' },
];

// Body checks report once per page, with the count in the explanation: a page with
// forty insecure scripts has one defect to fix, not forty findings to triage.
function detectMixedContent(document: PassiveDocument, pageUrl: URL): HeaderFinding[] {
  if (pageUrl.protocol !== 'https:') return [];

  let count = 0;
  for (const { selector, attr } of MIXED_CONTENT_SOURCES) {
    document(selector).each((_, el) => {
      if (resolveAgainst(document(el).attr(attr), pageUrl)?.protocol === 'http:') count++;
    });
  }
  if (count === 0) return [];

  return [
    {
      category: 'mixed-content',
      severity: 'medium',
      confidence: 'definitive',
      explanation: `This HTTPS page loads ${count} script, stylesheet, or iframe resource(s) over plain http.`,
    },
  ];
}

// A form with no action submits to the page itself, which `no-tls` already covers on
// an http page, so only an explicit action is judged here.
function detectInsecureFormAction(document: PassiveDocument, pageUrl: URL): HeaderFinding[] {
  const count = document('form[action]').filter(
    (_, el) => resolveAgainst(document(el).attr('action'), pageUrl)?.protocol === 'http:',
  ).length;
  if (count === 0) return [];

  return [
    {
      category: 'insecure-form-action',
      severity: 'high',
      confidence: 'definitive',
      explanation: `${count} form(s) on this page submit to a plain http URL, exposing whatever is entered.`,
    },
  ];
}

const PASSWORD_AUTOCOMPLETE_HINTS = new Set(['new-password', 'current-password']);

// Without an explicit hint, password managers guess at the field's role (and `off` is
// widely ignored), so this is a usability-to-security nudge rather than a hard defect.
function detectPasswordAutocomplete(document: PassiveDocument): HeaderFinding[] {
  const count = document('input')
    .filter((_, el) => document(el).attr('type')?.trim().toLowerCase() === 'password')
    .filter((_, el) => {
      const tokens = (document(el).attr('autocomplete') ?? '').toLowerCase().split(/\s+/);
      return !tokens.some((token) => PASSWORD_AUTOCOMPLETE_HINTS.has(token));
    }).length;
  if (count === 0) return [];

  return [
    {
      category: 'password-field-autocomplete',
      severity: 'low',
      confidence: 'possible',
      explanation: `${count} password field(s) lack an autocomplete="new-password" or "current-password" hint.`,
    },
  ];
}

// Apache and nginx autoindex pages both title themselves `Index of /path` and repeat
// it in the h1; requiring the path slash keeps prose titles ("Index of recipes") out.
const DIRECTORY_LISTING_HEADING = /^\s*index of \//i;

function detectDirectoryListing(document: PassiveDocument): HeaderFinding[] {
  const title = document('title').first().text();
  const heading = document('h1').first().text();
  if (!DIRECTORY_LISTING_HEADING.test(title) || !DIRECTORY_LISTING_HEADING.test(heading)) return [];

  return [
    {
      category: 'directory-listing',
      severity: 'medium',
      confidence: 'possible',
      explanation: 'The response looks like an auto-generated directory index, which exposes every file in the directory.',
    },
  ];
}

// `pageUrl` anchors relative references; without it, body checks that depend on the
// page's scheme or on resolving a link cannot be decided, so they are skipped.
function detectBodyFindings(document: PassiveDocument | null, pageUrl: URL | null): HeaderFinding[] {
  if (document === null) return [];

  const result = [...detectPasswordAutocomplete(document), ...detectDirectoryListing(document)];
  if (pageUrl !== null) {
    result.push(...detectMixedContent(document, pageUrl), ...detectInsecureFormAction(document, pageUrl));
  }
  return result;
}

// `document` is the target's parsed response body, or null when there was no readable
// HTML body (non-HTML content type, empty body, or a read that failed mid-stream). It
// is optional so header/TLS analysis stays independent of body availability.
// `pageUrl` is the URL the document was served from.
export function detectHeaderFindings(
  headers: Record<string, string>,
  setCookies: string[] = [],
  document: PassiveDocument | null = null,
  pageUrl: URL | null = null,
): HeaderFinding[] {
  const result: HeaderFinding[] = MISSING_HEADER_FINDINGS.filter(({ header }) => !(header in headers)).map(
    ({ category, severity }) => ({ category, severity, confidence: 'definitive' }),
  );

  result.push(...detectCookieFindings(setCookies));
  result.push(...detectCspFindings(headers));
  result.push(...detectHstsFindings(headers));
  result.push(...detectCorsFindings(headers));
  result.push(...detectDisclosureFindings(headers));
  result.push(...detectBodyFindings(document, pageUrl));

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
const BANNER_PATTERN = /([A-Za-z][\w.-]*)\/(\d[\w.-]*)/;

// Generator tags conventionally space-separate the version (`WordPress 6.2.1`,
// `Drupal 9 (https://www.drupal.org)`), and a tag naming only the software yields
// nothing, same as a versionless Server header.
const GENERATOR_BANNER_PATTERN = /^\s*([A-Za-z][\w.-]*(?:\s+[A-Za-z][\w.-]*)*)\s+v?(\d[\w.-]*)/;

function extractGeneratorBanner(document: PassiveDocument): VersionBanner | null {
  const content = document('meta[name="generator" i]').first().attr('content');
  if (content === undefined) return null;

  const match = BANNER_PATTERN.exec(content) ?? GENERATOR_BANNER_PATTERN.exec(content);
  if (match?.[1] === undefined || match[2] === undefined) return null;
  return { software: match[1], version: match[2] };
}

// The generator tag is not a finding category of its own: a version found there flows
// into the same OSV correlation as a header banner, so there is one CVE pathway. It
// ranks between headers and robots.txt — it describes the page actually served, where
// a robots.txt comment may be a leftover.
export function extractVersionBanner(
  headers: Record<string, string>,
  robotsBody: string | null,
  document: PassiveDocument | null = null,
): VersionBanner | null {
  for (const headerName of BANNER_HEADER_NAMES) {
    const value = headers[headerName];
    if (value === undefined) continue;
    const match = BANNER_PATTERN.exec(value);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { software: match[1], version: match[2] };
    }
  }

  const generatorBanner = document === null ? null : extractGeneratorBanner(document);
  if (generatorBanner !== null) return generatorBanner;

  if (robotsBody !== null) {
    const match = BANNER_PATTERN.exec(robotsBody);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { software: match[1], version: match[2] };
    }
  }

  return null;
}
