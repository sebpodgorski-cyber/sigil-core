/**
 * Normalization Layer.
 *
 * The single boundary between Layer B (Extraction Interface) and
 * Layer A (Cognitive Runtime). Every fact entering Layer A crosses
 * through here.
 *
 * Responsibilities:
 *   1. Validate: incoming FactCandidate[] is schema-checked. Malformed
 *      candidates are rejected (never partially ingested).
 *   2. Enrich: each candidate gets a ULID, owner DID, layer assignment,
 *      versioning, override flags, and empty-but-initialized fields.
 *   3. Sign: each fact is signed with the user's Ed25519 key.
 *   4. Return: a list of fully-formed, signed Fact objects ready to
 *      hand to the Memory Store.
 *
 * What this layer does NOT do:
 *   - It does not persist. Persistence is the Memory Store's job.
 *   - It does not compute weight. Weight Engine runs later.
 *   - It does not assign phase beyond 'emergence'. Time Engine runs later.
 *   - It does not detect duplicates. Deduplication is the Store's job.
 *
 * The layer assignment policy is explicit and conservative: by default
 * facts produced by extraction are assigned to the 'observed' layer.
 * Facts marked as declarative by upstream context (e.g., the mentor
 * registering an explicit user statement about themselves) can be
 * promoted to 'stated' via the `layerOverride` option.
 */

import { ulid } from 'ulid';
import type {
  ExtractionResult,
  FactCandidate,
} from '@sovereign/sigil-extractor-contract';
import { FactCandidateSchema } from '@sovereign/sigil-extractor-contract';
import type {
  Event,
  Fact,
  Layer,
  SigilDID,
  Unsigned,
} from './types.js';
import { signObject } from './signing.js';
import type { KeyProvider } from './signing.js';

export interface NormalizationOptions {
  /**
   * Layer to assign to produced facts.
   * Defaults to 'observed'. Pass 'stated' when the utterance is a
   * declarative user statement the mentor should treat as self-report.
   */
  layerOverride?: Layer;
  /**
   * Event IDs the produced facts derive from. Required — every Fact
   * MUST trace back to at least one Event for provenance.
   */
  sourceEventIds: string[];
}

export interface NormalizationResult {
  facts: Fact[];
  rejected: Array<{
    candidate: FactCandidate;
    reason: string;
  }>;
}

/**
 * Normalize and sign a batch of FactCandidates produced by an Extractor.
 *
 * This is the single entry point. Layer A code should never construct
 * Fact objects directly — they should always come through here.
 */
export async function normalize(
  extraction: ExtractionResult,
  options: NormalizationOptions,
  keys: KeyProvider
): Promise<NormalizationResult> {
  if (options.sourceEventIds.length === 0) {
    throw new Error(
      'Normalization requires at least one source event ID for provenance'
    );
  }

  const did = await keys.did();
  const layer: Layer = options.layerOverride ?? 'observed';
  const now = new Date().toISOString();

  const facts: Fact[] = [];
  const rejected: Array<{ candidate: FactCandidate; reason: string }> = [];

  for (const candidate of extraction.facts) {
    // Step 1: schema-validate the candidate.
    const parsed = FactCandidateSchema.safeParse(candidate);
    if (!parsed.success) {
      rejected.push({
        candidate,
        reason: `schema validation failed: ${parsed.error.message}`,
      });
      continue;
    }

    // Step 2: apply the low-confidence-fallback adjustment.
    // If the extractor fell back from cloud to local mid-flight, we
    // reduce confidence on every produced fact as the spec mandates.
    let confidence = parsed.data.confidence;
    if (extraction.low_confidence_fallback) {
      confidence = Math.max(0, confidence - 0.15);
    }

    // Step 3: construct the unsigned Fact.
    const unsigned: Unsigned<Fact> = {
      id: `fact_${ulid()}`,
      did,
      type: parsed.data.type,
      value: parsed.data.value,
      ...(parsed.data.context !== undefined
        ? { context: parsed.data.context }
        : {}),
      confidence,
      layer,
      // weight and phase are left unset here. The Weight Engine and Time
      // Engine populate them lazily on first access or during consolidation.
      source_events: [...options.sourceEventIds],
      version: 1,
      revision_of: null,
      disputed_by_user: false,
      suppressed_by_user: false,
      pinned_by_user: false,
      alternative_interpretations: [],
      created_at: now,
    };

    // Step 4: sign.
    const signed = await signObject<Fact>(unsigned, keys);
    facts.push(signed);
  }

  return { facts, rejected };
}

/**
 * Construct and sign a fresh Event. Events are the provenance anchor
 * for Facts; every Fact references one or more Events it derives from.
 *
 * Usage: the caller that is about to invoke an Extractor first creates
 * an Event representing the utterance, signs it, stores it, and then
 * passes the Event ID into `normalize` as the source.
 */
export async function signEvent(
  partial: Omit<Unsigned<Event>, 'id' | 'did'>,
  keys: KeyProvider
): Promise<Event> {
  const did = await keys.did();
  const unsigned: Unsigned<Event> = {
    id: `evt_${ulid()}`,
    did,
    ...partial,
  };
  return signObject<Event>(unsigned, keys);
}
