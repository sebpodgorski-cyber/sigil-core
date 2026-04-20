/**
 * SIGIL Signing Layer.
 *
 * Implements the signing and verification path for the did:sigil method.
 * Every Layer A object is signed here before it enters the Memory Store.
 *
 * Canonicalization follows RFC 8785 (JSON Canonicalization Scheme) in
 * spirit — we use a deterministic sort-keys-and-no-whitespace serializer
 * that is stable for the object shapes used by SIGIL. The full RFC 8785
 * implementation will replace this in a later phase; the signature format
 * and DID method do not depend on the specific canonicalization, so this
 * can be upgraded without breaking stored data.
 *
 * Key material never leaves this module. Callers pass in a KeyProvider
 * that gates access to the private key (device keychain, HSM, etc.).
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import type { Ed25519Signature, SigilDID, Unsigned } from './types.js';

// noble/ed25519 v2 requires synchronous hasher to be configured explicitly.
// We set sha512 once at module load. Safe because @noble/hashes is pure.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/**
 * A KeyProvider abstracts the source of signing keys. In production this
 * is backed by the OS keychain (iOS Secure Enclave, Android Keystore,
 * macOS Keychain, libsecret, etc.). For tests and development, the
 * InMemoryKeyProvider below is sufficient.
 */
export interface KeyProvider {
  /** The DID this provider represents. */
  did(): Promise<SigilDID>;
  /** Sign a canonical byte payload. Returns raw 64-byte signature. */
  sign(payload: Uint8Array): Promise<Uint8Array>;
  /** Return the public key for verification. */
  publicKey(): Promise<Uint8Array>;
}

/**
 * Deterministic JSON canonicalization.
 * Keys sorted recursively. No whitespace. UTF-8 output.
 *
 * Intentionally simple: no cycle detection, no special number handling.
 * Safe for the object shapes SIGIL uses (no cycles, only finite numbers,
 * no bigint, no undefined values — undefined keys are stripped).
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('Cannot canonicalize non-finite number');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    return (
      '{' +
      keys
        .map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k]))
        .join(',') +
      '}'
    );
  }
  throw new Error(`Cannot canonicalize value of type ${typeof value}`);
}

/**
 * Sign an unsigned object, returning the signed form.
 * The object's DID must match the KeyProvider's DID — enforced here.
 */
export async function signObject<T extends { did: SigilDID; signature: Ed25519Signature }>(
  unsigned: Unsigned<T>,
  keys: KeyProvider
): Promise<T> {
  const providerDid = await keys.did();
  if (unsigned.did !== providerDid) {
    throw new Error(
      `Refusing to sign: object's DID (${unsigned.did}) does not match provider's DID (${providerDid})`
    );
  }
  const canonical = canonicalize(unsigned);
  const payload = new TextEncoder().encode(canonical);
  const rawSig = await keys.sign(payload);
  const signature = `ed25519:${toBase64Url(rawSig)}` as Ed25519Signature;
  return { ...unsigned, signature } as T;
}

/**
 * Verify a signed object.
 * Returns true iff the signature is a valid Ed25519 signature over the
 * canonical form of the object (excluding the signature field) by the
 * public key identified by the object's DID.
 */
export async function verifyObject<T extends { did: SigilDID; signature: Ed25519Signature }>(
  signed: T
): Promise<boolean> {
  const { signature, ...rest } = signed as T & { signature: Ed25519Signature };
  if (!signature.startsWith('ed25519:')) return false;
  const sigBytes = fromBase64Url(signature.slice('ed25519:'.length));

  const publicKey = publicKeyFromDid(signed.did);
  if (!publicKey) return false;

  const canonical = canonicalize(rest);
  const payload = new TextEncoder().encode(canonical);
  try {
    return await ed.verifyAsync(sigBytes, payload, publicKey);
  } catch {
    return false;
  }
}

/* ─────────────────────────────────────────────────────────────────────
 * DID method: did:sigil
 *
 * Method-specific identifier format: z<base58btc-multibase>(0xed01 + pubkey)
 * The 0xed01 prefix is the multicodec tag for Ed25519 public key.
 * We use a simplified form here (raw base64url pubkey with 'z' prefix
 * acting as multibase sentinel) for Phase 0 and upgrade to full multibase
 * in Phase 1. The signature format itself is unchanged by the upgrade.
 * ───────────────────────────────────────────────────────────────────── */

export function didFromPublicKey(pubkey: Uint8Array): SigilDID {
  // Phase 0 simplification: 'z' + base64url(pubkey).
  return `did:sigil:z${toBase64Url(pubkey)}` as SigilDID;
}

export function publicKeyFromDid(did: SigilDID): Uint8Array | null {
  const prefix = 'did:sigil:z';
  if (!did.startsWith(prefix)) return null;
  try {
    return fromBase64Url(did.slice(prefix.length));
  } catch {
    return null;
  }
}

/* ─────────────────────────────────────────────────────────────────────
 * InMemoryKeyProvider — for tests and development.
 * NEVER use in production: the private key is held in heap memory.
 * Production providers MUST back to a hardware-isolated key store.
 * ───────────────────────────────────────────────────────────────────── */

export class InMemoryKeyProvider implements KeyProvider {
  private readonly _priv: Uint8Array;
  private readonly _pub: Uint8Array;
  private readonly _did: SigilDID;

  private constructor(priv: Uint8Array, pub: Uint8Array) {
    this._priv = priv;
    this._pub = pub;
    this._did = didFromPublicKey(pub);
  }

  static async generate(): Promise<InMemoryKeyProvider> {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    return new InMemoryKeyProvider(priv, pub);
  }

  static async fromPrivateKey(priv: Uint8Array): Promise<InMemoryKeyProvider> {
    if (priv.length !== 32) {
      throw new Error('Ed25519 private key must be 32 bytes');
    }
    const pub = await ed.getPublicKeyAsync(priv);
    return new InMemoryKeyProvider(priv, pub);
  }

  async did(): Promise<SigilDID> {
    return this._did;
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    return ed.signAsync(payload, this._priv);
  }

  async publicKey(): Promise<Uint8Array> {
    return this._pub;
  }
}

/* ─────────────────────────────────────────────────────────────────────
 * Base64URL helpers (no external dep).
 * ───────────────────────────────────────────────────────────────────── */

function toBase64Url(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return new Uint8Array(Buffer.from(b64, 'base64'));
}
