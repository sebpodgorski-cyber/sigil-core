/**
 * @sovereign/sigil-extractor-contract
 *
 * Public surface for Layer A consumers and Layer B implementors.
 */

// Interface and types — what Layer A imports.
export type {
  Extractor,
  ExtractorKind,
  ExtractorCapabilities,
  RawUtterance,
  FactCandidate,
  FactType,
  ExtractionResult,
  RoutingDecision,
  PrivacyMode,
} from './types.js';

// Schemas — for boundary validation.
export {
  FactTypeSchema,
  RawUtteranceSchema,
  FactCandidateSchema,
  ExtractionResultSchema,
  CloudFactArraySchema,
} from './schemas.js';

// Extractor implementations.
export { CloudExtractor } from './extractors/cloud.js';
export type { CloudExtractorConfig } from './extractors/cloud.js';
export { LocalExtractor } from './extractors/local.js';

// Routing.
export { RoutingClassifier, DEFAULT_THRESHOLDS } from './router.js';
export type { RoutingClassifierConfig } from './router.js';

// Redaction and audit.
export { redactPII, assertFullyRedacted } from './redaction.js';
export type { RedactionKind, RedactionResult } from './redaction.js';
export {
  FileAuditLogger,
  InMemoryAuditLogger,
  hashUtterance,
} from './audit.js';
export type { AuditLogger, AuditEvent, AuditEventType } from './audit.js';
