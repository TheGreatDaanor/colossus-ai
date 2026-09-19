// Prints the takeover evidence for one hostname, or reports its CNAME chain is
// healthy. Reporting only: nothing is persisted, and the only outbound request
// is a plain GET of the hostname itself (https, then http if that fails) — no
// provider resource is ever claimed.
//
//   npx tsx scripts/check-takeover.ts <hostname>
import { checkTakeover } from '../src/services/takeover.js';

const hostname = process.argv[2];
if (hostname === undefined || hostname === '') {
  console.error('usage: npx tsx scripts/check-takeover.ts <hostname>');
  process.exit(2);
}

const evidence = await checkTakeover(hostname);

if (evidence === null) {
  console.warn(`${hostname}: no dangling CNAME — the chain is healthy or the host has no CNAME.`);
  process.exit(0);
}

console.warn(`${evidence.hostname}: DANGLING CNAME -> ${evidence.cnameTarget}`);
console.warn(`  provider:   ${evidence.provider ?? 'unknown (no fingerprint matched)'}`);
console.warn(`  confidence: ${evidence.confidence}`);
console.warn(`  remediation: ${evidence.remediation}`);
console.warn('  The CNAME target does not resolve. Whoever claims that provider resource');
console.warn('  serves content under this hostname.');
