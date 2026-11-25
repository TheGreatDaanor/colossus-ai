// The listener's memory of inbound callbacks: every DNS query and HTTP request whose
// hostname carries a token, kept for a bounded time and count. Never persisted — a
// scan drains within ~30s, so a restart loses only callbacks nobody is waiting on.

export type RecordedHit = {
  token: string;
  protocol: 'dns' | 'http';
  callerSourceIp: string;
  observedAt: string;
};

// The token is the label directly under the collaborator base domain, lower-cased
// (DNS is case-insensitive, and resolvers may randomise case). A target may prepend
// labels of its own, so only the one under the base counts. A trailing root dot or
// a `:port` suffix (HTTP Host header) is ignored.
export function tokenFromHostname(hostname: string, baseDomain: string): string | null {
  const host = hostname.toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  const suffix = `.${baseDomain.toLowerCase()}`;
  if (!host.endsWith(suffix)) return null;
  const labels = host.slice(0, -suffix.length).split('.');
  const token = labels[labels.length - 1];
  return token === undefined || token === '' ? null : token;
}

export class HitBuffer {
  readonly #ttlMs: number;
  readonly #maxHits: number;
  readonly #now: () => number;
  readonly #accepts: (token: string) => boolean;
  // Oldest first: arrival order is time order, so pruning is a prefix cut.
  readonly #hits: { at: number; hit: RecordedHit }[] = [];

  // `accepts` gates which tokens are worth keeping (the daemon passes the signed-token
  // check); a rejected hit never takes a slot, so junk cannot evict real callbacks.
  constructor(options: { ttlMs: number; maxHits: number; now?: () => number; accepts?: (token: string) => boolean }) {
    this.#ttlMs = options.ttlMs;
    this.#maxHits = options.maxHits;
    this.#now = options.now ?? Date.now;
    this.#accepts = options.accepts ?? (() => true);
  }

  get size(): number {
    return this.#hits.length;
  }

  record(hit: Omit<RecordedHit, 'observedAt'>): void {
    if (!this.#accepts(hit.token)) return;
    const at = this.#now();
    this.#hits.push({ at, hit: { ...hit, observedAt: new Date(at).toISOString() } });
    this.#prune(at);
  }

  query(tokens: string[]): RecordedHit[] {
    this.#prune(this.#now());
    const wanted = new Set(tokens);
    return this.#hits.filter(({ hit }) => wanted.has(hit.token)).map(({ hit }) => hit);
  }

  #prune(now: number): void {
    let drop = Math.max(0, this.#hits.length - this.#maxHits);
    while (drop < this.#hits.length && now - this.#hits[drop]!.at > this.#ttlMs) drop += 1;
    if (drop > 0) this.#hits.splice(0, drop);
  }
}
