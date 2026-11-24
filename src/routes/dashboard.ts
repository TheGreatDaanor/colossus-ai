import { Hono } from 'hono';
import type { Finding, Scan, ScanTarget, ScannerService } from '../services/scanner.js';
import type { SsrfEvidence } from '../services/ssrf-probe.js';

function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function page(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head><body>${body}</body></html>`;
}

function scanListTable(scanList: Scan[]): string {
  const rows = scanList
    .map(
      (scan) => `<tr>
        <td>${scan.id}</td>
        <td><a href="/dashboard/scans/${scan.id}">${escapeHtml(scan.name)}</a></td>
        <td>${escapeHtml(scan.status)}</td>
        <td>${escapeHtml(scan.createdAt.toISOString())}</td>
      </tr>`,
    )
    .join('');

  return `<table>
    <thead><tr><th>id</th><th>name</th><th>status</th><th>created_at</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function definitionList(fields: [string, string | undefined][]): string {
  const items = fields
    .filter((field): field is [string, string] => field[1] !== undefined)
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`)
    .join('');
  return `<dl>${items}</dl>`;
}

// SSRF proof reads as labeled fields, never raw JSON. It is body-free by
// construction, so there is no response body here to leak.
function ssrfEvidence(evidence: SsrfEvidence): string {
  const list = definitionList([
    ['param', evidence.param],
    ['protocols', evidence.protocols.length > 0 ? evidence.protocols.join(', ') : undefined],
    ['caller egress IP', evidence.callerSourceIp],
    ['tier', evidence.tier],
    ['matched signature', evidence.matchedSignature],
  ]);
  const note = evidence.internalRead === 'not-demonstrated' ? '<p>metadata read: not demonstrated</p>' : '';
  return list + note;
}

const isOptionalString = (value: unknown) => value === undefined || typeof value === 'string';

// Only a row with the full SsrfEvidence shape renders as labeled fields; anything
// else falls back to escaped raw JSON so one bad row never fails the page.
function parseSsrfEvidence(raw: string | null): SsrfEvidence | null {
  if (raw === null) return null;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || parsed.kind !== 'ssrf') return null;
  const wellFormed =
    typeof parsed.param === 'string' &&
    (parsed.tier === 'oob' || parsed.tier === 'internal-read') &&
    Array.isArray(parsed.protocols) &&
    parsed.protocols.every((p) => typeof p === 'string') &&
    isOptionalString(parsed.callerSourceIp) &&
    isOptionalString(parsed.matchedSignature) &&
    isOptionalString(parsed.internalRead);
  return wellFormed ? (parsed as unknown as SsrfEvidence) : null;
}

function findingCell(finding: Finding, col: string): string {
  if (col === 'structuredEvidence') {
    const ssrf = parseSsrfEvidence(finding.structuredEvidence);
    if (ssrf !== null) return ssrfEvidence(ssrf);
  }
  return escapeHtml((finding as unknown as Record<string, unknown>)[col]);
}

// A param whose internal read confirmed was tested, even if its callback drain failed.
function untestedSsrfAttempts(target: ScanTarget) {
  const ssrf = (target.injectionAttempts ?? []).filter((attempt) => attempt.check === 'ssrf');
  const confirmed = new Set(ssrf.filter((a) => a.outcome === 'confirmed').map((a) => a.injectionPoint));
  return ssrf.filter((attempt) => attempt.outcome === 'unavailable' && !confirmed.has(attempt.injectionPoint));
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

// Scan-level roll-up of the per-param indicator, so an operator sees at the top
// that SSRF coverage has gaps before reading a single target row.
function ssrfNotTestedSummary(targets: ScanTarget[]): string {
  const perTarget = targets.map(untestedSsrfAttempts).filter((attempts) => attempts.length > 0);
  if (perTarget.length === 0) return '';

  const byReason = new Map<string, number>();
  for (const attempt of perTarget.flat()) {
    const reason = attempt.error ?? 'unknown reason';
    byReason.set(reason, (byReason.get(reason) ?? 0) + 1);
  }
  const reasons = [...byReason]
    .map(([reason, count]) => `<li>${escapeHtml(reason)}: ${count}</li>`)
    .join('');
  const total = perTarget.flat().length;
  return `<section><p><strong>SSRF: not tested on ${plural(total, 'parameter')} across ${plural(perTarget.length, 'target')}</strong></p><ul>${reasons}</ul></section>`;
}

// An `unavailable` SSRF attempt means the param was never probed. Saying so per
// param keeps a clean report from reading as "no SSRF".
function ssrfNotTested(target: ScanTarget): string {
  return untestedSsrfAttempts(target)
    .map(
      (attempt) =>
        `<p>SSRF: not tested (${escapeHtml(attempt.error ?? 'unknown reason')}) — param ${escapeHtml(attempt.injectionPoint)}</p>`,
    )
    .join('');
}

function findingsTable(findingList: Finding[]): string {
  if (findingList.length === 0) return '<p>no findings</p>';

  const columns = Object.keys(findingList[0] ?? {});
  const header = columns.map((col) => `<th>${escapeHtml(col)}</th>`).join('');
  const rows = findingList
    .map(
      (finding) =>
        `<tr>${columns
          .map((col) => `<td>${findingCell(finding, col)}</td>`)
          .join('')}</tr>`,
    )
    .join('');

  return `<table><thead><tr>${header}</tr></thead><tbody>${rows}</tbody></table>`;
}

// Where a target came from: the operator's own submission, a host the program's
// inventory turned up, or a link the crawl followed. An operator reading results
// needs to tell them apart — they never typed most of these URLs.
function targetSource(target: ScanTarget): string {
  if (target.enumeratedHostId !== null) return 'inventory';
  if (target.discoveredFrom !== null) return 'discovered';
  return 'submitted';
}

function targetsTable(targets: (ScanTarget & { findings: Finding[] })[]): string {
  const rows = targets
    .map(
      (target) => `<tr>
        <td>${escapeHtml(target.url)}</td>
        <td>${targetSource(target)}</td>
        <td>${escapeHtml(target.status)}</td>
        <td>${target.statusCode ?? ''}</td>
        <td>${target.responseTimeMs ?? ''}</td>
        <td>${escapeHtml(target.redirectLocation ?? '')}</td>
        <td>${escapeHtml(target.error ?? '')}</td>
        <td>${ssrfNotTested(target)}${findingsTable(target.findings)}</td>
      </tr>`,
    )
    .join('');

  return `<table>
    <thead><tr><th>url</th><th>source</th><th>status</th><th>status_code</th><th>response_time_ms</th><th>redirect_location</th><th>error</th><th>findings</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

export function createDashboardRoutes(service: ScannerService): Hono {
  const app = new Hono();

  app.get('/dashboard', async (c) => {
    const scanList = await service.listScans();
    return c.html(page('Scans', `<h1>Scans</h1>${scanListTable(scanList)}`));
  });

  app.get('/dashboard/scans/:id', async (c) => {
    const id = Number(c.req.param('id'));
    if (!Number.isInteger(id)) return c.text('scan id must be an integer', 400);

    const scan = await service.getScan(id);
    if (!scan) return c.text('scan not found', 404);

    const body = `<h1>${escapeHtml(scan.name)}</h1><p>status: ${escapeHtml(scan.status)}</p>${ssrfNotTestedSummary(scan.targets)}${targetsTable(scan.targets)}`;
    return c.html(page(scan.name, body));
  });

  return app;
}
