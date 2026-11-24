import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createDb } from './client.js';
import { findings, scanTargets, scans } from './schema.js';

describe('createDb', () => {
  let dir: string;
  let path: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'colossus-db-'));
    path = join(dir, 'colossus.db');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('carries legacy access-control proof into structured evidence, tagged with its kind', () => {
    // A finding written before structured evidence existed: proof only in the old column.
    const proof = {
      url: 'https://example.com/invoices/1',
      owner: { label: 'alice', status: 200, digest: 'aaa' },
      unauthorized: { label: 'bob', status: 200, digest: 'aaa' },
      noAuth: { status: 401, digest: 'bbb' },
    };
    const before = createDb(path);
    const [scan] = before
      .insert(scans)
      .values({ name: 'legacy', status: 'completed', urls: ['https://example.com'], createdAt: new Date() })
      .returning()
      .all();
    const [target] = before
      .insert(scanTargets)
      .values({ scanId: scan!.id, url: proof.url, status: 'ok' })
      .returning()
      .all();
    before
      .insert(findings)
      .values({
        scanTargetId: target!.id,
        category: 'idor',
        severity: 'high',
        confidence: 'definitive',
        accessControlEvidence: JSON.stringify(proof),
      })
      .run();

    const after = createDb(path);
    const [finding] = after.select().from(findings).all();

    expect(JSON.parse(finding!.structuredEvidence ?? 'null')).toEqual({ kind: 'access-control', ...proof });
  });
});
