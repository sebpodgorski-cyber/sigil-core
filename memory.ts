/**
 * In-Memory Memory Store.
 *
 * Reference implementation of the MemoryStore interface. Uses plain
 * Maps — no persistence, no encryption. Suitable for tests, development,
 * and short-lived sessions.
 *
 * The SQLite-backed encrypted store that ships in Phase 1 implements
 * the same interface. Any Layer A module written against this store
 * will work unchanged against the production store.
 *
 * Semantics enforced here:
 *   - Signatures are verified on every write. Unsigned-or-invalid
 *     objects are rejected with an error.
 *   - Live queries exclude disputed and suppressed facts by default.
 *   - Fork semantics: old fact kept, marked disputed, new fact inserted.
 *   - Override flags stored in sidecar maps (preserves signature validity).
 */

import type {
  Event,
  Fact,
  Pattern,
  SigilDID,
} from '../types.js';
import type { FactQuery, MemoryStore, PatternQuery } from './interface.js';
import { verifyObject } from '../signing.js';

export class InMemoryStore implements MemoryStore {
  private events = new Map<string, Event>();
  private facts = new Map<string, Fact>();
  private patterns = new Map<string, Pattern>();

  // Sidecar tables for user-override flags. Stored separately from the
  // signed fact content so that overrides don't invalidate signatures.
  private suppressed = new Set<string>();
  private pinned = new Set<string>();

  private closed = false;

  private assertOpen(): void {
    if (this.closed) throw new Error('Store is closed');
  }

  /* ── Events ──────────────────────────────────────────────────── */

  async putEvent(event: Event): Promise<void> {
    this.assertOpen();
    if (!(await verifyObject(event))) {
      throw new Error(`Event ${event.id} signature verification failed`);
    }
    if (this.events.has(event.id)) {
      throw new Error(`Event ${event.id} already exists`);
    }
    this.events.set(event.id, event);
  }

  async getEvent(id: string): Promise<Event | null> {
    this.assertOpen();
    return this.events.get(id) ?? null;
  }

  /* ── Facts ───────────────────────────────────────────────────── */

  async putFacts(facts: Fact[]): Promise<void> {
    this.assertOpen();

    // Verify all signatures before any insertion (atomic batch).
    for (const f of facts) {
      if (!(await verifyObject(f))) {
        throw new Error(`Fact ${f.id} signature verification failed`);
      }
      if (this.facts.has(f.id)) {
        throw new Error(`Fact ${f.id} already exists (use forkFact for revisions)`);
      }
      // Verify that all referenced source events exist.
      for (const evtId of f.source_events) {
        if (!this.events.has(evtId)) {
          throw new Error(`Fact ${f.id} references unknown event ${evtId}`);
        }
      }
    }

    for (const f of facts) this.facts.set(f.id, f);
  }

  async getFact(id: string): Promise<Fact | null> {
    this.assertOpen();
    const f = this.facts.get(id);
    if (!f) return null;
    return this.applyOverrideFlags(f);
  }

  async queryFacts(query: FactQuery): Promise<Fact[]> {
    this.assertOpen();
    const {
      did,
      types,
      layers,
      since,
      until,
      includeDisputed = false,
      includeSuppressed = false,
      limit,
    } = query;

    const out: Fact[] = [];
    for (const raw of this.facts.values()) {
      if (raw.did !== did) continue;
      const f = this.applyOverrideFlags(raw);

      if (!includeDisputed && f.disputed_by_user) continue;
      if (!includeSuppressed && f.suppressed_by_user) continue;
      if (types && !types.includes(f.type)) continue;
      if (layers && !layers.includes(f.layer)) continue;
      if (since && f.created_at < since) continue;
      if (until && f.created_at > until) continue;

      out.push(f);
      if (limit && out.length >= limit) break;
    }

    // Deterministic order: oldest first.
    out.sort((a, b) => (a.created_at < b.created_at ? -1 : 1));
    return limit ? out.slice(0, limit) : out;
  }

  async forkFact(oldId: string, newFact: Fact): Promise<void> {
    this.assertOpen();
    const old = this.facts.get(oldId);
    if (!old) throw new Error(`Cannot fork: fact ${oldId} does not exist`);
    if (newFact.revision_of !== oldId) {
      throw new Error(
        `Fork invalid: newFact.revision_of (${newFact.revision_of}) must equal oldId (${oldId})`
      );
    }
    if (newFact.version !== old.version + 1) {
      throw new Error(
        `Fork invalid: newFact.version (${newFact.version}) must be old.version + 1 (${old.version + 1})`
      );
    }
    if (newFact.did !== old.did) {
      throw new Error('Fork invalid: DID must match across versions');
    }
    if (!(await verifyObject(newFact))) {
      throw new Error(`Fork invalid: newFact ${newFact.id} signature verification failed`);
    }

    // Mark old as disputed (override flag, not signed content change).
    // We use a signed-content-preserving update: write the old fact back
    // with the disputed flag flipped in the sidecar. However, since
    // disputed_by_user is a signed field, we must store it as a sidecar
    // override like suppressed/pinned. For v1 we persist the updated old
    // as a revised signed object — caller passes the re-signed version.
    // To keep this method self-contained and enforce immutability of
    // signed content, we model disputed_by_user the same way as
    // suppressed/pinned from this point forward.
    this.disputed.add(oldId);

    this.facts.set(newFact.id, newFact);
  }

  private disputed = new Set<string>();

  async setOverrideFlags(
    factId: string,
    flags: Partial<Pick<Fact, 'suppressed_by_user' | 'pinned_by_user'>>
  ): Promise<void> {
    this.assertOpen();
    if (!this.facts.has(factId)) {
      throw new Error(`Cannot set flags on unknown fact ${factId}`);
    }
    if (flags.suppressed_by_user !== undefined) {
      if (flags.suppressed_by_user) this.suppressed.add(factId);
      else this.suppressed.delete(factId);
    }
    if (flags.pinned_by_user !== undefined) {
      if (flags.pinned_by_user) this.pinned.add(factId);
      else this.pinned.delete(factId);
    }
  }

  private applyOverrideFlags(f: Fact): Fact {
    return {
      ...f,
      disputed_by_user: f.disputed_by_user || this.disputed.has(f.id),
      suppressed_by_user: f.suppressed_by_user || this.suppressed.has(f.id),
      pinned_by_user: f.pinned_by_user || this.pinned.has(f.id),
    };
  }

  /* ── Patterns ────────────────────────────────────────────────── */

  async putPattern(pattern: Pattern): Promise<void> {
    this.assertOpen();
    if (!(await verifyObject(pattern))) {
      throw new Error(`Pattern ${pattern.id} signature verification failed`);
    }
    this.patterns.set(pattern.id, pattern);
  }

  async getPattern(id: string): Promise<Pattern | null> {
    this.assertOpen();
    return this.patterns.get(id) ?? null;
  }

  async queryPatterns(query: PatternQuery): Promise<Pattern[]> {
    this.assertOpen();
    const out: Pattern[] = [];
    for (const p of this.patterns.values()) {
      if (p.did !== query.did) continue;
      if (query.phases && !query.phases.includes(p.phase)) continue;
      if (query.loopTypes && !query.loopTypes.includes(p.loop_type)) continue;
      if (query.layers && !query.layers.includes(p.layer)) continue;
      if (query.minStrength !== undefined && p.strength < query.minStrength) continue;
      out.push(p);
    }
    out.sort((a, b) => b.strength - a.strength);
    return query.limit ? out.slice(0, query.limit) : out;
  }

  /* ── Diagnostics ─────────────────────────────────────────────── */

  async count(did: SigilDID): Promise<{ events: number; facts: number; patterns: number }> {
    this.assertOpen();
    let events = 0, facts = 0, patterns = 0;
    for (const e of this.events.values()) if (e.did === did) events++;
    for (const f of this.facts.values()) {
      if (f.did !== did) continue;
      const effective = this.applyOverrideFlags(f);
      if (!effective.disputed_by_user && !effective.suppressed_by_user) facts++;
    }
    for (const p of this.patterns.values()) if (p.did === did) patterns++;
    return { events, facts, patterns };
  }

  async close(): Promise<void> {
    this.closed = true;
    this.events.clear();
    this.facts.clear();
    this.patterns.clear();
    this.suppressed.clear();
    this.pinned.clear();
    this.disputed.clear();
  }
}
