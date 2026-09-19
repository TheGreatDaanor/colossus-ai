import { Hono } from 'hono';
import type { Finding, Scan, ScanTarget, ScannerService } from '../services/scanner.js';

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

function findingsTable(findingList: Finding[]): string {
  if (findingList.length === 0) return '<p>no findings</p>';

  const columns = Object.keys(findingList[0] ?? {});
  const header = columns.map((col) => `<th>${escapeHtml(col)}</th>`).join('');
  const rows = findingList
    .map(
      (finding) =>
        `<tr>${columns
          .map((col) => `<td>${escapeHtml((finding as unknown as Record<string, unknown>)[col])}</td>`)
          .join('')}</tr>`,
    )
    .join('');

  return `<table><thead><tr>${header}</tr></thead><tbody>${rows}</tbody></table>`;
}

function targetsTable(targets: (ScanTarget & { findings: Finding[] })[]): string {
  const rows = targets
    .map(
      (target) => `<tr>
        <td>${escapeHtml(target.url)}</td>
        <td>${escapeHtml(target.status)}</td>
        <td>${target.statusCode ?? ''}</td>
        <td>${target.responseTimeMs ?? ''}</td>
        <td>${escapeHtml(target.redirectLocation ?? '')}</td>
        <td>${escapeHtml(target.error ?? '')}</td>
        <td>${findingsTable(target.findings)}</td>
      </tr>`,
    )
    .join('');

  return `<table>
    <thead><tr><th>url</th><th>status</th><th>status_code</th><th>response_time_ms</th><th>redirect_location</th><th>error</th><th>findings</th></tr></thead>
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

    const body = `<h1>${escapeHtml(scan.name)}</h1><p>status: ${escapeHtml(scan.status)}</p>${targetsTable(scan.targets)}`;
    return c.html(page(scan.name, body));
  });

  return app;
}
