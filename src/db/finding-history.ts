import { eq, lt } from 'drizzle-orm';
import type { Db } from './client.js';
import { findings, scanTargets } from './schema.js';

// The columns that identify a finding across scans, for every finding recorded by
// a scan older than `scanId` (by id, so re-reading an old scan never changes its
// answer). Reads only the identity columns, not whole rows.
export function findingsBeforeScan(db: Db, scanId: number) {
  return db
    .select({
      url: scanTargets.url,
      category: findings.category,
      injectionPoint: findings.injectionPoint,
      cveId: findings.cveId,
      explanation: findings.explanation,
      structuredEvidence: findings.structuredEvidence,
    })
    .from(findings)
    .innerJoin(scanTargets, eq(findings.scanTargetId, scanTargets.id))
    .where(lt(scanTargets.scanId, scanId))
    .all();
}
