import { and, asc, eq, inArray, sql } from 'drizzle-orm';
import psl from 'psl';
import type { Db } from '../db/client.js';
import { enumeratedHosts, programs, scopeEntries, type HostSource, type ScanMode, type ScopeList, type ScopeStatus } from '../db/schema.js';
import { EnumerationError, type ObservedHost } from './enumeration.js';

export class ProgramValidationError extends Error {}

export type Program = typeof programs.$inferSelect;
export type EnumeratedHost = typeof enumeratedHosts.$inferSelect;
export type ScopeEntry = typeof scopeEntries.$inferSelect;
export type ProgramWithScope = Program & { scopeEntries: ScopeEntry[] };

// The patterns of one program, split by list. Classification needs nothing else,
// which is what keeps it a pure function with no database behind it.
export type Scope = { in: string[]; out: string[] };

export type CreateProgramOptions = {
  url?: string;
  name?: string;
  passiveHostCap?: number;
  activeHostCap?: number;
};

export type AddScopeEntryOptions = { list: ScopeList; pattern: string };

// What this service needs from the enumeration side: given an apex, what hosts
// exist, and given a host, where it answers. Injected so scope rules stay
// testable without a network. `resolveEndpoint` is optional — a source that only
// names hosts is still usable, and the inventory simply carries no endpoints.
export type EnumerationImpl = {
  enumerate(apex: string): Promise<ObservedHost[]>;
  resolveEndpoint?(hostname: string): Promise<string | null>;
};

// `now` is injected because the inventory's "what appeared since last time" is
// read off the times rows were written, and a test needs those to be distinct.
export type ProgramsServiceOptions = { enumerationImpl?: EnumerationImpl; now?: () => Date };

// An inventory host together with whether it appeared in the most recent
// enumeration. `isNew` is deliberately not a finding and carries no severity: a
// host that has just appeared is something to look at, not a defect.
export type InventoryHost = EnumeratedHost & { isNew: boolean };

// The program's inventory, with the newly appeared hosts marked. `newSince` is
// when the previous enumeration ran — the point the new hosts appeared after —
// and is null on a program that has only ever been enumerated once, where there
// is no earlier inventory for anything to have appeared since.
export type Inventory = { hosts: InventoryHost[]; newSince: Date | null };

export type EnumerateDueOptions = { cadenceMs: number };

export type { ScopeList, ScopeStatus };

const WILDCARD_PREFIX = '*.';

// SQLite binds a limited number of parameters per statement and each row here
// binds five, so a large inventory goes in as several statements inside one
// transaction rather than one statement that would be refused.
const UPSERT_BATCH_SIZE = 100;

// One failed probe is a blip — a resolver hiccup or a moment of downtime. Three
// consecutive ones is a host that has gone dark, and scanning it would spend the
// run's budget on nothing. The row is kept either way.
const DORMANT_AFTER_FAILED_RESOLUTIONS = 3;

// How many inventory hosts one scan may reach, per mode. Active is an order of
// magnitude lower than passive because an active target additionally drives a
// headless browser and injects payloads: one flat cap would either throttle
// passive pointlessly or let active run wild. A program may override either.
const MODE_HOST_CAPS: Record<ScanMode, number> = { passive: 250, active: 50 };

export function hostCapFor(program: Program, mode: ScanMode): number {
  const override = mode === 'active' ? program.activeHostCap : program.passiveHostCap;
  return override ?? MODE_HOST_CAPS[mode];
}

// A host nothing has answered for in three consecutive probes. Exported because
// the inventory shows it to the operator as well as withholding it from scans.
export function isDormant(host: EnumeratedHost): boolean {
  return host.failedResolutions >= DORMANT_AFTER_FAILED_RESOLUTIONS;
}

// DNS names are case-insensitive and a trailing dot only marks the root, so both
// hosts and patterns are folded to one form before any comparison.
function normaliseHostname(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, '');
}

function isHostname(candidate: string): boolean {
  return psl.isValid(candidate);
}

// The registrable domain — the apex — computed from the Public Suffix List
// rather than by counting labels, which gets `example.co.uk` wrong. Returns null
// for anything nobody can register: a bare public suffix, or a non-hostname.
export function apexOf(hostname: string): string | null {
  const normalised = normaliseHostname(hostname);
  if (!isHostname(normalised)) return null;
  return psl.get(normalised);
}

function isSubdomainOf(hostname: string, parent: string): boolean {
  return hostname.endsWith(`.${parent}`);
}

// An in-scope pattern is an apex when it is its own registrable domain, and an
// exact host otherwise. That distinction is the whole difference between
// authorizing a domain and authorizing one partner host inside it.
function matchesEntry(hostname: string, pattern: string): boolean {
  if (pattern.startsWith(WILDCARD_PREFIX)) {
    // A `*.`-prefixed subtree covers its own root as well as everything under
    // it: an operator excluding `*.internal.example.com` means the subtree.
    const root = pattern.slice(WILDCARD_PREFIX.length);
    return hostname === root || isSubdomainOf(hostname, root);
  }

  if (hostname === pattern) return true;
  return psl.get(pattern) === pattern && isSubdomainOf(hostname, pattern);
}

function matchesAny(hostname: string, patterns: string[]): boolean {
  return patterns.some((pattern) => matchesEntry(hostname, normaliseHostname(pattern)));
}

// One ordered rule, first match wins. Out-of-scope is evaluated first so that an
// exclusion is never overridden by a more specific inclusion — an operator who
// writes an exclusion can read it and know it holds.
export function classifyHost(hostname: string, scope: Scope): ScopeStatus {
  const normalised = normaliseHostname(hostname);
  if (!isHostname(normalised)) return 'unscoped';

  if (matchesAny(normalised, scope.out)) return 'out_of_scope';
  if (matchesAny(normalised, scope.in)) return 'in_scope';
  return 'unscoped';
}

function toScope(entries: ScopeEntry[]): Scope {
  return {
    in: entries.filter((e) => e.list === 'in').map((e) => e.pattern),
    out: entries.filter((e) => e.list === 'out').map((e) => e.pattern),
  };
}

function apexFromUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ProgramValidationError(`\`${raw}\` is not a valid URL`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ProgramValidationError('program url must be http or https');
  }

  const apex = apexOf(parsed.hostname);
  if (apex === null) throw new ProgramValidationError(`\`${parsed.hostname}\` has no registrable apex`);
  return apex;
}

// Validated against the grammar the PRD pins: apex or exact host on either list,
// plus `*.`-prefixed subtrees on the out list only. A wildcard inclusion is
// rejected rather than silently widened.
function validatePattern(list: ScopeList, raw: string): string {
  const pattern = normaliseHostname(raw);
  if (pattern === '') throw new ProgramValidationError('scope pattern must not be empty');

  if (pattern.startsWith(WILDCARD_PREFIX)) {
    if (list === 'in') throw new ProgramValidationError('wildcard patterns are only allowed on the out-of-scope list');
    const root = pattern.slice(WILDCARD_PREFIX.length);
    if (!isHostname(root)) throw new ProgramValidationError(`\`${raw}\` is not a valid scope pattern`);
    return pattern;
  }

  if (!isHostname(pattern)) throw new ProgramValidationError(`\`${raw}\` is not a valid scope pattern`);
  return pattern;
}

export class ProgramsService {
  #db: Db;
  #enumerationImpl: EnumerationImpl | null;
  #now: () => Date;

  constructor(db: Db, options: ProgramsServiceOptions = {}) {
    this.#db = db;
    this.#enumerationImpl = options.enumerationImpl ?? null;
    this.#now = options.now ?? (() => new Date());
  }

  async createProgram(options: CreateProgramOptions): Promise<ProgramWithScope> {
    const { url, name, passiveHostCap, activeHostCap } = options;
    if (url === undefined && name === undefined) {
      throw new ProgramValidationError('program requires a `url` or a `name`');
    }

    const apex = url === undefined ? null : apexFromUrl(url);
    const row = this.#db
      .insert(programs)
      .values({
        name: name ?? apex ?? '',
        passiveHostCap: passiveHostCap ?? null,
        activeHostCap: activeHostCap ?? null,
        createdAt: this.#now(),
      })
      .returning()
      .get();
    if (!row) throw new Error('failed to insert program');

    // An apex inferred from a URL is left unconfirmed: inferring one widens
    // authorization from a single host to a whole domain, so the operator
    // confirms it before enumeration runs against it.
    if (apex !== null) {
      this.#db.insert(scopeEntries).values({ programId: row.id, list: 'in', pattern: apex, confirmedAt: null }).run();
    }

    return { ...row, scopeEntries: this.#scopeEntriesOf(row.id) };
  }

  async getProgram(id: number): Promise<ProgramWithScope | null> {
    const row = this.#db.select().from(programs).where(eq(programs.id, id)).get();
    if (!row) return null;
    return { ...row, scopeEntries: this.#scopeEntriesOf(row.id) };
  }

  async addScopeEntry(programId: number, options: AddScopeEntryOptions): Promise<ScopeEntry> {
    const { list, pattern: rawPattern } = options;
    this.#requireProgram(programId);
    const pattern = validatePattern(list, rawPattern);

    const existing = this.#db
      .select()
      .from(scopeEntries)
      .where(and(eq(scopeEntries.programId, programId), eq(scopeEntries.list, list), eq(scopeEntries.pattern, pattern)))
      .get();
    if (existing) throw new ProgramValidationError(`\`${pattern}\` is already on the ${list} list`);

    // Typed by an operator rather than inferred by a parser, so it needs no
    // separate confirmation step.
    const row = this.#db
      .insert(scopeEntries)
      .values({ programId, list, pattern, confirmedAt: this.#now() })
      .returning()
      .get();
    if (!row) throw new Error('failed to insert scope entry');
    return row;
  }

  async removeScopeEntry(programId: number, entryId: number): Promise<void> {
    this.#requireProgram(programId);

    const removed = this.#db
      .delete(scopeEntries)
      .where(and(eq(scopeEntries.programId, programId), eq(scopeEntries.id, entryId)))
      .returning()
      .get();
    if (!removed) throw new ProgramValidationError(`scope entry ${entryId} not found on program ${programId}`);
  }

  // The scope lists as one value, for a caller that classifies many hostnames
  // in a row (the crawler, every link on every page) and must not pay a query
  // each time.
  async scopeOf(programId: number): Promise<Scope> {
    this.#requireProgram(programId);
    return toScope(this.#scopeEntriesOf(programId));
  }

  async classify(programId: number, hostname: string): Promise<ScopeStatus> {
    this.#requireProgram(programId);
    return classifyHost(hostname, toScope(this.#scopeEntriesOf(programId)));
  }

  // Records what a source observed, classifying each host as it lands. A host
  // is kept whatever its status: an `unscoped` host is what the operator needs
  // to see in order to widen scope deliberately, and is never scanned meanwhile.
  //
  // The program's passive/active host caps are deliberately not applied here:
  // they bound what a *scan* reaches (issue 037), not what the inventory may
  // know about. Capping the inventory would hide hosts from the operator.
  async recordHosts(programId: number, hosts: ObservedHost[]): Promise<EnumeratedHost[]> {
    this.#requireProgram(programId);
    const scope = toScope(this.#scopeEntriesOf(programId));
    const firstSeenAt = this.#now();

    // One CT answer for a busy apex names thousands of hosts, so the rows go in
    // as batched upserts rather than a select-then-write per host. The whole
    // batch is one transaction: a run that fails partway must not leave the
    // operator with an inventory that is neither the old one nor the new one.
    const rows = new Map<
      string,
      { programId: number; hostname: string; source: HostSource; scopeStatus: ScopeStatus; isWildcard: boolean; firstSeenAt: Date }
    >();
    for (const host of hosts) {
      const hostname = normaliseHostname(host.hostname);
      // Last mention of a hostname wins, which matters only for `source`; a
      // host already in the inventory keeps the source it was first seen with.
      rows.set(hostname, {
        programId,
        hostname,
        source: host.source,
        scopeStatus: classifyHost(hostname, scope),
        isWildcard: host.isWildcard === true,
        firstSeenAt,
      });
    }
    if (rows.size === 0) return [];

    const batched = [...rows.values()];
    this.#db.transaction((tx) => {
      for (let i = 0; i < batched.length; i += UPSERT_BATCH_SIZE) {
        tx.insert(enumeratedHosts)
          .values(batched.slice(i, i + UPSERT_BATCH_SIZE))
          // A host already in the inventory keeps its identity and the date it
          // was first seen; its scope status is refreshed because the operator
          // may have changed the lists since, and its wildcard flag because a
          // host first seen behind a `*.` may since have been seen bare.
          .onConflictDoUpdate({
            target: [enumeratedHosts.programId, enumeratedHosts.hostname],
            set: { scopeStatus: sql`excluded.scope_status`, isWildcard: sql`excluded.is_wildcard` },
          })
          .run();
      }
    });

    // Returned in the order the caller observed them, not the order they sit in
    // the table: the caller is reporting on the run it just made.
    const stored = new Map((await this.listHosts(programId)).map((row) => [row.hostname, row]));
    return [...rows.keys()].flatMap((hostname) => {
      const row = stored.get(hostname);
      if (!row) throw new Error(`failed to record enumerated host ${hostname}`);
      return [row];
    });
  }

  async listHosts(programId: number): Promise<EnumeratedHost[]> {
    this.#requireProgram(programId);
    return this.#db
      .select()
      .from(enumeratedHosts)
      .where(eq(enumeratedHosts.programId, programId))
      .orderBy(asc(enumeratedHosts.hostname))
      .all();
  }

  // The inventory as an operator reads it: every host, with the ones that
  // appeared in the most recent enumeration marked.
  //
  // Newness is derived from `firstSeenAt` rather than stored: one enumeration
  // stamps every host it records with the same time, so the distinct
  // `firstSeenAt` values *are* the runs that found something, and the hosts
  // carrying the latest one are the hosts that run added.
  //
  // A program enumerated only once has a single such value, and nothing is
  // marked: on a first run every host is new in the trivial sense, and saying so
  // would bury the signal the view exists to show.
  async listInventory(programId: number): Promise<Inventory> {
    const hosts = await this.listHosts(programId);
    const runs = [...new Set(hosts.map((host) => host.firstSeenAt.getTime()))].sort((a, b) => a - b);
    if (runs.length < 2) return { hosts: hosts.map((host) => ({ ...host, isNew: false })), newSince: null };

    const latest = runs[runs.length - 1]!;
    return {
      hosts: hosts.map((host) => ({ ...host, isNew: host.firstSeenAt.getTime() === latest })),
      newSince: new Date(runs[runs.length - 2]!),
    };
  }

  // One pass of the scheduler: enumerates every program whose inventory is older
  // than `cadenceMs`, and returns the ids of the ones it enumerated. A program
  // never enumerated is always due.
  //
  // Each program is enumerated independently. A source outage is already
  // non-fatal inside `enumerateProgram` — it is recorded on the program and the
  // existing inventory is left alone — and an unexpected failure is recorded the
  // same way here rather than being allowed to abandon the rest of the pass.
  async enumerateDuePrograms(options: EnumerateDueOptions): Promise<number[]> {
    const now = this.#now().getTime();
    const due = this.#db
      .select()
      .from(programs)
      .all()
      .filter((program) => {
        const last = program.lastEnumeratedAt;
        return last === null || now - last.getTime() >= options.cadenceMs;
      });

    const enumerated: number[] = [];
    for (const program of due) {
      try {
        await this.enumerateProgram(program.id);
        enumerated.push(program.id);
      } catch (err) {
        this.#db
          .update(programs)
          .set({ enumerationError: `scheduled enumeration failed: ${String(err)}` })
          .where(eq(programs.id, program.id))
          .run();
      }
    }
    return enumerated;
  }

  // The hosts a scan may reach: in scope, not a wildcard, and not dormant. A
  // dormant host stays in the inventory and stays eligible for takeover checks —
  // it is only scanning that has nothing left to talk to.
  async listScannableHosts(programId: number): Promise<EnumeratedHost[]> {
    return (await this.listHosts(programId)).filter(
      (host) => host.scopeStatus === 'in_scope' && !host.isWildcard && !isDormant(host),
    );
  }

  // The hosts one scan run reaches, in the order it should reach them: a host no
  // scan has touched since it first appeared comes ahead of one an earlier run
  // already covered, and among those, the longest-unscanned goes first. A cap
  // that bites is therefore a rotation rather than a permanently ignored tail.
  async selectHostsToScan(programId: number, limit: number): Promise<EnumeratedHost[]> {
    // A host with no known endpoint has nothing to send a request to: it was
    // never probed, or every probe found nothing. It stays in the inventory and
    // stays eligible for takeover checks; only scanning has no target for it.
    const scannable = (await this.listScannableHosts(programId)).filter((host) => host.endpointUrl !== null);
    // Already in hostname order, which a stable sort keeps as the tie-break
    // between two hosts last scanned at the same moment.
    return scannable
      .slice()
      .sort((a, b) => (a.lastScannedAt?.getTime() ?? -Infinity) - (b.lastScannedAt?.getTime() ?? -Infinity))
      .slice(0, limit);
  }

  // Stamps the hosts a scan just drew targets from, which is what moves them to
  // the back of the queue for the next run.
  async markHostsScanned(hostIds: number[]): Promise<void> {
    if (hostIds.length === 0) return;
    const scannedAt = this.#now();
    this.#db.update(enumeratedHosts).set({ lastScannedAt: scannedAt }).where(inArray(enumeratedHosts.id, hostIds)).run();
  }

  // Enumerates every apex on the in-scope list and records what comes back.
  // A source outage is recorded on the program rather than thrown: the operator
  // still gets the inventory they already had, plus the reason nothing is new.
  async enumerateProgram(programId: number): Promise<EnumeratedHost[]> {
    this.#requireProgram(programId);
    if (this.#enumerationImpl === null) throw new Error('programs service was built without an enumeration source');

    const apexes = this.#apexesOf(programId);
    const observed: ObservedHost[] = [];
    const errors: string[] = [];
    for (const apex of apexes) {
      try {
        observed.push(...(await this.#enumerationImpl.enumerate(apex)));
      } catch (err) {
        if (!(err instanceof EnumerationError)) throw err;
        errors.push(`${apex}: ${err.message}`);
      }
    }

    await this.recordHosts(programId, observed);
    await this.#probeEndpoints(programId);

    // `lastEnumeratedAt` answers "how fresh is this inventory", so it is stamped
    // only when a source was actually read. A run where every apex failed left
    // the inventory exactly as stale as it was, and must not claim otherwise.
    const readAnySource = errors.length < apexes.length;
    this.#db
      .update(programs)
      .set({
        ...(readAnySource ? { lastEnumeratedAt: this.#now() } : {}),
        enumerationError: errors.length === 0 ? null : errors.join('; '),
      })
      .where(eq(programs.id, programId))
      .run();

    return this.listHosts(programId);
  }

  // Probes each in-scope host for the scheme it answers on. A host that answers
  // has its endpoint and resolution time refreshed and its failure count
  // cleared; one that does not keeps its row, its last known endpoint and its
  // last resolution time, and has its failure count raised.
  //
  // Only in-scope hosts are probed. A probe is a live request, and an
  // `out_of_scope` or `unscoped` host is one the engagement does not authorize
  // traffic to — the inventory may know it exists without touching it.
  //
  // Wildcard hosts are skipped too: under a wildcard every name answers, so a
  // probe would record an endpoint for a host nobody has seen.
  async #probeEndpoints(programId: number): Promise<void> {
    const probedAt = this.#now();
    for (const host of await this.listHosts(programId)) {
      if (host.isWildcard || host.scopeStatus !== 'in_scope') continue;
      const endpointUrl = await this.#enumerationImpl?.resolveEndpoint?.(host.hostname);
      // A source that does not probe at all leaves the inventory as it is,
      // rather than counting a probe that never happened as a failure.
      if (endpointUrl === undefined) return;
      this.#db
        .update(enumeratedHosts)
        .set(
          endpointUrl === null
            ? { failedResolutions: host.failedResolutions + 1 }
            : { endpointUrl, lastResolvedAt: probedAt, failedResolutions: 0 },
        )
        .where(eq(enumeratedHosts.id, host.id))
        .run();
    }
  }

  // Confirms an inferred scope entry, authorizing enumeration against it. An
  // entry the operator typed was already confirmed on creation, so confirming it
  // again is a no-op that keeps its original time rather than resetting it.
  async confirmScopeEntry(programId: number, entryId: number): Promise<ScopeEntry> {
    this.#requireProgram(programId);
    const entry = this.#db
      .select()
      .from(scopeEntries)
      .where(and(eq(scopeEntries.programId, programId), eq(scopeEntries.id, entryId)))
      .get();
    if (!entry) throw new ProgramValidationError(`scope entry ${entryId} not found on program ${programId}`);
    if (entry.confirmedAt !== null) return entry;

    const updated = this.#db
      .update(scopeEntries)
      .set({ confirmedAt: this.#now() })
      .where(eq(scopeEntries.id, entryId))
      .returning()
      .get();
    if (!updated) throw new Error('failed to confirm scope entry');
    return updated;
  }

  // Only apexes are enumerated: an exact-host entry authorizes that one host,
  // and enumerating its domain would widen the engagement past what was agreed.
  //
  // Only *confirmed* entries are enumerated: an inferred apex the operator has
  // not confirmed carries no authorization to widen scope from one host to its
  // whole domain, so enumeration never runs against it (issue 033).
  #apexesOf(programId: number): string[] {
    const patterns = this.#scopeEntriesOf(programId)
      .filter((entry) => entry.list === 'in' && entry.confirmedAt !== null)
      .map((entry) => normaliseHostname(entry.pattern));
    return [...new Set(patterns.filter((pattern) => apexOf(pattern) === pattern))];
  }

  #requireProgram(id: number): Program {
    const row = this.#db.select().from(programs).where(eq(programs.id, id)).get();
    if (!row) throw new ProgramValidationError(`program ${id} not found`);
    return row;
  }

  #scopeEntriesOf(programId: number): ScopeEntry[] {
    return this.#db
      .select()
      .from(scopeEntries)
      .where(eq(scopeEntries.programId, programId))
      .orderBy(asc(scopeEntries.id))
      .all();
  }
}
