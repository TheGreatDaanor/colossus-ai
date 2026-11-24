import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import * as schema from './schema.js';

export type Db = BetterSQLite3Database<typeof schema>;

export function createDb(path: string): Db {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const sqlite = new Database(path);
  const db = drizzle(sqlite, { schema });
  migrate(db, { migrationsFolder: './src/db/migrations' });
  carryLegacyAccessControlEvidence(sqlite);
  return db;
}

// Data move that drizzle-kit can't generate: access-control proof written before
// `structured_evidence` existed lives only in `access_control_evidence`. Copy it
// across, tagged with its `kind`. Idempotent (touches only rows not yet copied), so
// it is safe on every start. Remove together with the follow-up migration that
// drops `access_control_evidence`.
function carryLegacyAccessControlEvidence(sqlite: Database.Database): void {
  sqlite.exec(`
    UPDATE findings
       SET structured_evidence = json_patch('{"kind":"access-control"}', access_control_evidence)
     WHERE access_control_evidence IS NOT NULL
       AND structured_evidence IS NULL
  `);
}
