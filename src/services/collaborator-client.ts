import { mintSignedToken } from '../collaborator/token.js';
import type { BodyFetchImpl } from './active-scanner.js';
import type { CollaboratorClient, CollaboratorHit, SelfTestResult } from './ssrf-probe.js';

// The real `CollaboratorClient`: mints tokens under the deployment's NS-delegated
// collaborator zone and polls the standalone listener's query API
// (`src/collaborator/`) for hits. The wire format is shared with the daemon's
// `query-api.ts`: `POST queryUrl` with `{ tokens }` and `Authorization: Bearer
// <secret>`, answered with `{ hits: [{ token, protocol, callerSourceIp, observedAt }] }`.
export type HttpCollaboratorConfig = {
  baseDomain: string;
  queryUrl: string;
  secret: string;
  fetchImpl?: typeof fetch;
  // A poll the listener never answers fails after this long, so a wedged listener
  // reads as `unavailable` instead of leaving the scan `running` forever.
  pollTimeoutMs?: number;
  // How long the self-test waits for its own callback to show up at the listener.
  selfTestTiming?: { attempts: number; intervalMs: number; sleep?: (ms: number) => Promise<void> };
};

// The listener is trusted to be ours, but its answer is still parsed defensively: a
// hit that is not well-formed is dropped rather than turned into a finding.
function parseHit(raw: unknown): CollaboratorHit | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const { token, protocol, callerSourceIp, observedAt } = raw as Record<string, unknown>;
  if (typeof token !== 'string' || typeof callerSourceIp !== 'string' || typeof observedAt !== 'string') return null;
  if (protocol !== 'dns' && protocol !== 'http') return null;
  const at = new Date(observedAt);
  if (Number.isNaN(at.getTime())) return null;
  return { token, protocol, callerSourceIp, observedAt: at };
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function makeHttpCollaboratorClient(config: HttpCollaboratorConfig): CollaboratorClient {
  const fetchImpl = config.fetchImpl ?? fetch;
  const timing = config.selfTestTiming ?? { attempts: 10, intervalMs: 1_000 };
  const sleep = timing.sleep ?? defaultSleep;

  const client: CollaboratorClient = {
    mint() {
      const token = mintSignedToken(config.secret);
      return { token, url: `http://${token}.${config.baseDomain}/` };
    },

    // Throws on any refusal or transport error: the probe turns a failed poll into
    // `unavailable`, never into "no callbacks".
    async poll(tokens) {
      if (tokens.length === 0) return [];
      const response = await fetchImpl(config.queryUrl, {
        method: 'POST',
        headers: { authorization: `Bearer ${config.secret}`, 'content-type': 'application/json' },
        body: JSON.stringify({ tokens }),
        signal: AbortSignal.timeout(config.pollTimeoutMs ?? 5_000),
      });
      if (!response.ok) throw new Error(`collaborator query api answered ${response.status}`);
      const { hits } = (await response.json()) as { hits?: unknown };
      if (!Array.isArray(hits)) throw new Error('collaborator query api answered without a hits array');
      return hits.map(parseHit).filter((hit): hit is CollaboratorHit => hit !== null);
    },

    // Colossus fetches a fresh token URL itself. An HTTP hit for it proves NS
    // delegation (the name resolved), the HTTP listener, and the query API at once.
    // Only HTTP callers are learned as Colossus's own egress: a DNS hit's caller is a
    // recursive resolver that targets may share (e.g. a public resolver), and
    // discarding it would silently hide their blind SSRF.
    async selfTest(colossusFetch: BodyFetchImpl): Promise<SelfTestResult> {
      const { token, url } = client.mint();
      let fetchError: string | null = null;
      try {
        await colossusFetch(url);
      } catch (err) {
        // The request may still have reached the listener; the poll decides.
        fetchError = err instanceof Error ? err.message : String(err);
      }
      for (let attempt = 0; attempt < timing.attempts; attempt++) {
        let hits: CollaboratorHit[];
        try {
          hits = await client.poll([token]);
        } catch (err) {
          return { ok: false, reason: `query api: ${err instanceof Error ? err.message : String(err)}` };
        }
        const httpCallers = [...new Set(hits.filter((h) => h.protocol === 'http').map((h) => h.callerSourceIp))];
        if (httpCallers.length > 0) return { ok: true, ownEgressIps: httpCallers };
        await sleep(timing.intervalMs);
      }
      const suffix = fetchError === null ? '' : ` (self-test fetch failed: ${fetchError})`;
      return { ok: false, reason: `no http callback for the self-test token after ${timing.attempts} polls${suffix}` };
    },
  };
  return client;
}

const COLLABORATOR_SETTINGS = ['COLLABORATOR_BASE_DOMAIN', 'COLLABORATOR_QUERY_URL', 'COLLABORATOR_SECRET'] as const;

// Deploy config, never per-scan input. All three set: the real client. None set: no
// collaborator, and active scans report SSRF `unavailable`. Some set: also none — a
// half-configured listener is a deploy mistake, so the caller gets a warning to log
// rather than a client that fails at the first scan.
export function collaboratorFromEnv(env: Record<string, string | undefined>): {
  client: CollaboratorClient | null;
  warning: string | null;
} {
  const missing = COLLABORATOR_SETTINGS.filter((key) => (env[key] ?? '') === '');
  if (missing.length === COLLABORATOR_SETTINGS.length) return { client: null, warning: null };
  if (missing.length > 0) {
    return { client: null, warning: `SSRF collaborator disabled: ${missing.join(', ')} not set` };
  }
  return {
    client: makeHttpCollaboratorClient({
      baseDomain: env['COLLABORATOR_BASE_DOMAIN']!,
      queryUrl: env['COLLABORATOR_QUERY_URL']!,
      secret: env['COLLABORATOR_SECRET']!,
    }),
    warning: null,
  };
}
