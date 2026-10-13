# Cryptographic constructions

This is a reviewable specification of ckmg's composition, not a security audit.
All primitives come from upstream crates. Application domain labels and custody
transcripts below are ckmg protocol choices and require independent review.

## PRF derivation (src/passkey.rs)

Use RustCrypto `hkdf`/`sha2` implementing [HKDF, RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).
For locator/wrapping/device output, IKM is the 32-byte opaque PRF secret; for
identity and holder output, IKM is the retained random common identity root.
The historical salt remains the exact
ASCII bytes `ckmg.passkey-prf.v1`, L = 32, and info is `label || UTF8(domain)`.
Each label ends with one zero byte. Domains are nonempty, at most 256 UTF-8 bytes,
and contain no control characters. They are byte-exact identifiers, not normalized
URLs; the owner must pin their canonical spelling. No entropy or mutable metadata
enters these derivations.

| Output | Label (the spelling `\0` means one zero byte) |
|---|---|
| Private vault locator | `ckmg.vault-location.v1\0` |
| Custody encryption key | `ckmg.keyring-key.v1\0` |
| Opaque cwst wrapping key | `ckmg.cwst-password.v1\0` (historical label; no password API) |
| Stable wallet identity Ed25519 seed | `ckmg.identity-root.v1\0` |
| Passport holder secret seed | `ckmg.passport-holder-seed.v1\0` |
| Logical device Ed25519 seed | `ckmg.device-lineage-seed.v1\0` |
| Historical lineage vector only (no production derivation) | `ckmg.member-lineage-seed.v1\0` |
| Common record-witness HPKE recipient input | `ckmg.record-witness-recipient.v1\0` |

A common identity root and each replacement epoch root come directly from injected
CSPRNG entropy through upstream `getrandom`. Every passkey retains the same common
identity root in its own PRF-wrapped checkpoint. Epoch roots are independent random
values, so a removed device cannot derive a replacement from old custody.
Historical deterministic lineage vectors remain test-only evidence; no production
recordless reconstruction path uses them.

Wallet roots are independent of all community key epochs. The passport output is
an opaque seed, not a BBS scalar or credential. No seed-to-scalar mapping, proof or
issuance primitive is invented here; that integration must use the existing
passport engine and keep its private scalar inside custody.

The fixed vectors in `tests/unit/passkey.rs` were independently evaluated with Node's
OpenSSL-backed `crypto.hkdfSync`; `tests/fixtures/prf-vectors.mjs` reproduces them.
Synthetic input is 32 copies of byte 27 and domain `a`.

## Signatures, typed values and hashes (src/vld0.rs, src/typed.rs)

[Ed25519, RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) is implemented by
[ed25519-dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/).
VLD0 prehashes the exact message with SHA-512 and uses Ed25519ph context `VLD0_SIGN`.
Plain Ed25519 has separate signing/verification APIs and is never relabeled VLD0.
Verification uses dalek's strict methods and rejects weak public keys.

Public keys, signatures and hashes encode as `VLD0:` plus unpadded base64url, or
four bytes `VLD0` plus the fixed-size value. Hashes and ciphertext CAS stamps use
unkeyed [BLAKE3](https://github.com/BLAKE3-team/BLAKE3). They authenticate nothing
by themselves. The independently authenticated lineage supplies authority.

## Purpose derivation (src/keys.rs)

Use upstream [BLAKE3 derive_key](https://docs.rs/blake3/latest/blake3/fn.derive_key.html),
with context `ckmg 2026-10 purpose signing v1` or
`ckmg 2026-10 purpose encryption v1`. Key material is the 32-byte parent seed followed
by the purpose-context transcript with empty caller context. The parent is the
member root or local device seed according to Scope. Signing/encryption keys are
separate; purpose label, generation, member binding and epoch are bound below.
No root or device seed is delegated through a public getter.

## Symmetric encryption (src/keyring.rs)

RustCrypto [chacha20poly1305](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/)
provides XChaCha20-Poly1305 (32-byte key, 24-byte random nonce, 16-byte tag).
XChaCha is the upstream construction, not the 12-byte-nonce cipher in RFC 8439.
Every seal obtains a fresh nonce from injected CSPRNG entropy and outputs
`nonce || ciphertext+tag`. AAD is never encrypted but must match exactly.

| Use | Header / AAD |
|---|---|
| Checkpoint | Output header `ckmg.checkpoint.v1\0`; AAD = header + 32-byte locator |
| Purpose data | Output header `ckmg.purpose.sealed.v1\0`; AAD = purpose-context transcript including caller context |
| cwst wrapping | No outer header; AAD = `ckmg.storage.wrap.v1\0` + bounded caller context |

Checkpoint plaintext is LE-u32 metadata length, metadata JSON, material format byte,
then the 32-byte device seed. Format 0 has no root; historical format 1 adds its
32-byte epoch root; format 2 adds epoch root[32] and common identity root[32]. Identity
and holder purpose seeds derive privately from that retained common random root.
The encrypted metadata includes revision, clock floor and exact pending receipt.
Secret byte buffers use `Zeroizing`; the memory-erasure limits still need review.

## Root transport (src/vld0.rs)

Use `hpke` [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) base mode,
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. Upstream dalek converts
the Ed25519 public key to Montgomery form. SHA-512(seed)'s first 32 bytes provide
the corresponding private input, with clamping left to upstream X25519.
Info is exactly `veilid-hpke/1VLD0`; output is `0x01 || VLD0 || enc[32] || ciphertext+tag`.
Historical version-1 root transfers contain one 32-byte epoch seed (85 bytes total).
Version-2 transfers contain epoch root[32] and common identity root[32] (117 bytes).
Version-3 transfers retain an opening history: epoch root[32], identity-present
byte (0 or 1), optional common identity root[32], then one or more ordered pairs
of epoch as little-endian u64 and root[32]. Epochs must be positive, strictly
increasing, and older than the authenticated current lineage. The original HPKE
suite/context is unchanged; the pairing/rotation AAD and signature transcript
labels advance to their next versions. Total bytes remain bounded by the existing
checkpoint budget. Checkpoint material format 3 is device seed[32] followed by
this transfer. Historical roots are used solely by current-authorized opening
operations; current writers/signers continue deriving from the current root.
Both use the unchanged upstream Veilid HPKE header/info; new owned AAD/signature
versions distinguish the plaintext layouts.

Base mode does not authenticate the sender. Pairing/rotation signatures plus
independent current authority supply that authentication. AAD binds the exact
recipient and transition as listed below. HPKE entropy uses upstream ChaCha20Rng
seeded with 32 fresh bytes from the injected entropy port.

The selected semantics follow [Veilid revision dd8e2cdd72b5bf817172ac31c20872b168c5c8fc](https://gitlab.com/veilid/veilid/-/tree/dd8e2cdd72b5bf817172ac31c20872b168c5c8fc),
`veilid-core-optimized/src/{sign,seal}.rs` and
`veilid-core/src/crypto/crypto_system/hpke.rs`. Test-only copied/adapted code is
isolated in `tests/unit/veilid_reference.rs` under MPL-2.0. The RFC 9180 A.2.1 fixture
is byte-identical to Veilid's fixture at that revision. These are composition/vector
checks, not a live Veilid integration test or independent implementation audit.

## Owned transcripts (src/lineage.rs, src/keys.rs, src/passkey.rs)

Encoding is domain bytes followed by serde_json's compact serialization of the
listed tuple, in fixed order. Struct fields follow declaration order. Byte arrays
are JSON integer arrays; typed public values use their serde encoding. No maps,
floats or transport JSON text are signed. Changes require a new format version.

| Domain | Tuple / value |
|---|---|
| `ckmg.lineage.v1\0` | historical version, binding, epoch, revision, root, sorted devices |
| `ckmg.lineage.v2\0` | version, binding, epoch, revision, root, sorted devices, common identity root public key |
| `ckmg.lineage.digest.v1\0` | complete Lineage, BLAKE3 hashed |
| `ckmg.pairing.request.v1\0` | version, binding, root, epoch, device, nonce, issued_at, expires_at |
| `ckmg.pairing.digest.v1\0` | complete PairingRequest, BLAKE3 hashed |
| `ckmg.pairing.root.v2\0` / `.v3\0` | request digest, granted lineage digest; old root-only / new common-root envelope AAD |
| `ckmg.pairing.grant.v1\0` / `.v2\0` | request, lineage, sealed_root |
| `ckmg.rotation.root.v1\0` / `.v2\0` | predecessor digest, previous root, revoked device, successor digest, recipient (HPKE AAD) |
| `ckmg.rotation.v1\0` / `.v2\0` | predecessor, previous_root, revoked, lineage, envelopes |
| `ckmg.rotation.digest.v1\0` | complete Rotation, BLAKE3 hashed |
| `ckmg.purpose.certificate.v1\0` | binding, epoch, device, purpose, key |
| `ckmg.purpose.context.v1\0` | binding, epoch, device-or-null, purpose, caller context |
| `ckmg.identity.proof.v1\0` | wallet domain, challenge bytes |

Lineage and pairing grants use the member-root signature; pairing requests and
purpose certificates use the device signature. Rotation uses the previous root
signature plus the new lineage's self-signature. Identity proofs use the isolated
identity root. Owner payload signatures remain the owner's exact bytes, checked
with a separately validated purpose certificate.

## Entropy and secret lifetime

[getrandom](https://docs.rs/getrandom/latest/getrandom/) backs SystemEntropy with
the native platform source or Web Crypto on wasm32. Randomness is used for HPKE,
AEAD nonces, session capabilities, operation IDs, pairing challenges, common roots
and epoch roots. Roots survive through retained encrypted custody, not the PRF alone. An entropy error publishes nothing.
[zeroize](https://docs.rs/zeroize/latest/zeroize/) wipes owned secret buffers on drop;
upstream copies, registers, allocator copies, browser input and crash dumps remain
part of the review boundary.

## Opaque passport holder adapter

Feature `passport` passes a private copy of the existing dedicated holder seed
straight to cwlt::PassportHolder::from_seed. Wallet owns the holder and cpsd owns the maintained ChaCha20 and
arkworks nonzero scalar recipe and wipes the passed seed buffer. No PRF/KDF label,
derivation primitive or BBS implementation is added. The Wallet-owned engine lends
its own PassportSession; Keys copies no operations and lends no mutable engine.

Installation also matches the separately selected wallet domain and the actual
PRF-derived device public key. Every call rechecks the current authority port.
Lock, revocation and failed authority drop and wipe the retained engine.

## Veilid record cipher custody

`with_vld0_record_cipher` composes RustCrypto chacha20 0.10 XChaCha20, with the
same 32-byte secret / 24-byte nonce / original-byte transformation as Veilid
`storage_manager/record_encryption.rs`. There is no AEAD tag in this format;
cdht must verify the original signed value before decryption and obtain a fresh
nonce for every encryption. This capability does not verify a record itself.

A new record-only secret is BLAKE3 derive_key with context exactly
`ckmg 2026-10 VLD0 record encryption v1` and key material the existing 32-byte
purpose-encryption derivation. This separates stream-cipher keys from AEAD keys.
Existing persisted purpose/checkpoint transcripts are unchanged. The derived
secret and capability exist only inside one freshly authorized callback. No
full record-key codec, raw read secret, or secret accessor is added.

## Opaque holder sealing

The stable common identity retained through equal-passkey pairing and root rotations
is also the input for a separate HKDF-SHA256 purpose. Reuse salt
`ckmg.passkey-prf.v1`, with info `ckmg.wallet-holder-seal.v1\0` followed by the
exact authenticated wallet domain. The 32-byte result stays private to Keys and
is transferred only into CPSD's key-bound constructor/open operation. It is never
derived from an individual authenticator PRF. Existing identity and holder-seed
labels/bytes are unchanged. The CPSD holder cannot receive a replacement sealing
key from Wallet. CPSD owns its maintained AEAD and original private codecs;
The wallet domain is also bound immutably as CPSD authenticated context at
construction. Wallet owns durable compound adoption of ciphertext through Storage receipts.

The internal original Wallet balance engine uses two additional HKDF-SHA256
labels under the existing salt `ckmg.passkey-prf.v1`: `ckmg.wallet-balance-seed.v1`
plus NUL and actual wallet domain, and `ckmg.wallet-balance-seal.v1` plus NUL and
that domain. Input is the retained random common identity root, never an individual
passkey PRF. Existing identity/passport labels and stored formats stay unchanged.
Both derived buffers stay private/zeroizing; the original engine constructor wipes
its temporary inputs and permanently binds the actual wallet context and cipher.
The engine owns its format, maintained AEAD and random nonces. Keys reexports its
original package types; upper Wallet must not mix them with a second local-path
instance. Qualification order is internal engine on real Wallet main, then Keys,
then upper Wallet Store integration, with no Cargo patch or source alias.

## Common-root compound wrapping

The current rotating random root is the input to the existing passkey HKDF
construction, with distinct info `ckmg.compound-store-root.v1\0 || community`.
The HKDF salt and SHA-256 construction are unchanged. This is distinct from the
stable Wallet identity seed and from the legacy per-PRF Store password label.
Every enrolled device at the same root derives the same compound wrapping key.
The original Store context/AEAD still authenticates scope and the wrapped random
data key; root transitions hand this opaque cipher to SecureStore in the same CAS.

Bootstrap compound records retain the original member-purpose KDF, epoch and
generation zero, using only `vault.checkpoint` and `vault.checkpoint.chunk.0`
through `.9` (DFLT32). No new record crypto or root export is introduced.

The independent `TransportSession` retains only two derived device-purpose
keys, using the existing purpose KDF with epoch 0 and generation 0. Transport
has no member-root epoch: the same PRF and exact community/member Binding
reconstitute the same node identity before Records can supply a root. Keep this
owner throughout the runtime; do not hand it off to lineage-epoch Keys handles.
The older Keys initializer derivation is unchanged and produces a different
identity (lineage epochs start at 1). This unpublished path makes no compatibility
claim for those older onion identities, or claim to inherit their runtime evidence.
Every signing/DH or initializer request requires fresh fixed-purpose authority;
refusal, clock regression or cancellation clears custody and stops its engines.
