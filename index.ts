/**
 * @sovereign/sigil-core
 *
 * Public surface. Layer A modules consume this package.
 */

export type {
  Event,
  Fact,
  Pattern,
  FactType,
  Layer,
  Phase,
  SigilDID,
  Ed25519Signature,
  ISOTimestamp,
  Falsification,
  AlternativeInterpretation,
  Unsigned,
} from './types.js';

export {
  canonicalize,
  signObject,
  verifyObject,
  didFromPublicKey,
  publicKeyFromDid,
  InMemoryKeyProvider,
} from './signing.js';
export type { KeyProvider } from './signing.js';

export { normalize, signEvent } from './normalization.js';
export type {
  NormalizationOptions,
  NormalizationResult,
} from './normalization.js';

export type { MemoryStore, FactQuery, PatternQuery } from './memory.js';
export { InMemoryStore } from './memory.js';
