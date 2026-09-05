import type { FindingConfidence, FindingSeverity } from '../db/schema.js';

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

export function detectHeaderFindings(headers: Record<string, string>, setCookies: string[] = []): HeaderFinding[] {
  const result: HeaderFinding[] = MISSING_HEADER_FINDINGS.filter(({ header }) => !(header in headers)).map(
    ({ category, severity }) => ({ category, severity, confidence: 'definitive' }),
  );

  result.push(...detectCookieFindings(setCookies));

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

export function extractVersionBanner(
  headers: Record<string, string>,
  robotsBody: string | null,
): VersionBanner | null {
  for (const headerName of BANNER_HEADER_NAMES) {
    const value = headers[headerName];
    if (value === undefined) continue;
    const match = BANNER_PATTERN.exec(value);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { software: match[1], version: match[2] };
    }
  }

  if (robotsBody !== null) {
    const match = BANNER_PATTERN.exec(robotsBody);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { software: match[1], version: match[2] };
    }
  }

  return null;
}
