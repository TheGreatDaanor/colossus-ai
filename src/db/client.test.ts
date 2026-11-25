import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createDb } from './client.js';

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

  it('drops the legacy access-control evidence column, keeping structured evidence as the only proof column', () => {
    createDb(path);
    const columns = new Database(path)
      .prepare('SELECT name FROM pragma_table_info(?)')
      .all('findings')
      .map((c) => (c as { name: string }).name);

    expect(columns).toContain('structured_evidence');
    expect(columns).not.toContain('access_control_evidence');
  });
});
