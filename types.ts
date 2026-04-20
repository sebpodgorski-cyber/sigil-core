/**
 * SIGIL Extractor Contract — Core Types
 *
 * Layer B (Extraction Interface) types.
 * These types define the boundary between raw utterances and structured facts.
 * Layer A (Cognitive Runtime) modules never import from src/extractors/*,
 * only from this file and src/extractor.ts.
 */

export type FactType =
  | 'emotion'
  | 'topic'
  | 'relation'
  | 'temporal'
  | 'identity_signal'
  | 'value'
  | 'goal';

export type ExtractorKind = 'cloud' | 'local';

/**
 * A raw utterance as it enters the Extraction Layer.
 * session_id is a rotating pseudonym, not a user-identifier.
 */
export interface RawUtterance {
  text: string;
  /** BCP-47 language tag. 'pl' is SoVereign's primary language. */
  language: string;
  /** ISO-8601 timestamp of utterance capture */
  timestamp: string;
  /** Rotating session pseudonym. Not user-identifying. */
  session_id: string;
}

/**
 * A fact candidate produced by an extractor.
 * Candidates are unsigned — signing happens in Normalization (Layer A).
 * This keeps signing keys out of Layer B entirely.
 */
export interface FactCandidate {
  type: FactType;
  value: string;
  context?: string;
  /** Extractor's confidence in this specific fact, [0..1] */
  confidence: number;
  /** The language this fact was extracted in, BCP-47 */
  language: string;
  /** Reference to the source utterance timestamp for provenance */
  source_timestamp: string;
}

/**
 * The result of an extraction call.
 * Returned from any Extractor.extract().
 */
export interface ExtractionResult {
  facts: FactCandidate[];
  /** Aggregate confidence across all extracted facts, [0..1] */
  confidence: number;
  extractor_kind: ExtractorKind;
  latency_ms: number;
  /** PII redaction types applied to input before extraction (e.g. ['email', 'phone']) */
  redactions_applied: string[];
  /** True when cloud was requested but fell back to local mid-flight */
  low_confidence_fallback: boolean;
}

/**
 * Declared capabilities of an extractor implementation.
 * Used by the RoutingClassifier to decide routing.
 */
export interface ExtractorCapabilities {
  supported_languages: string[];
  supported_fact_types: FactType[];
  max_input_length: number;
  offline_capable: boolean;
}

/**
 * The core extractor interface. The only pluggable module in SIGIL.
 */
export interface Extractor {
  readonly kind: ExtractorKind;
  extract(input: RawUtterance): Promise<ExtractionResult>;
  capabilities(): ExtractorCapabilities;
}

/**
 * A routing decision from the RoutingClassifier.
 * Recorded in the audit stream for every Hybrid-Mode extraction.
 */
export interface RoutingDecision {
  chosen: ExtractorKind;
  reason:
    | 'confidence_local'
    | 'confidence_cloud'
    | 'tie_break_local'
    | 'cloud_unavailable'
    | 'user_forced_local'
    | 'user_forced_cloud'
    | 'unsupported_language';
  /** Per-type local confidence estimates. */
  confidences: Partial<Record<FactType, number>>;
  /** Per-type thresholds in effect at decision time. */
  thresholds: Partial<Record<FactType, number>>;
  decided_at: string;
}

/**
 * Privacy modes. The mode governs which extractors are permitted.
 */
export type PrivacyMode = 'cloud_assisted' | 'hybrid' | 'strict_sovereignty';
