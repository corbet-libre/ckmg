# ckmg contract

Status: implemented library contract; independent security review and downstream
G3 device-authority integration are required before production acceptance.

`Keys<S, C, R, A>` is one logical device in one community. It owns a community
root, PRF-derived device seed, purpose derivation, signed device lineage, pairing,
root replacement and encrypted custody checkpoints. It contains no global holder
secret, network, filesystem, membership evaluator, ledger or recovery service.
`Binding.member` is the externally verified cpsd pseudonym, never a root hash.

## API

| Operation | Input and result |
|---|---|
| `new`, `state`, `lock` | Inject SecureStore, Clock, Entropy and Authority; start locked; wipe decrypted keys on lock. |
| `create_scope` | Explicit new-member authorization, PRF, binding and private device metadata; atomically persist deterministic root/device and a Created receipt. Never overwrite an existing record. |
| `unlock` | PRF + community derive the locator and custody key; decrypt exactly the stored logical device, including pending outputs. Absence yields MissingCheckpoint; no implicit creation. |
| `restore_scope` | Authoritatively absent record, same PRF, exact current lineage, Restore authorization and optional retained root transfer; reconstruct the same logical device and commit a Restored receipt. |
| `request_pairing` | Confirmed lineage, fresh PRF and private metadata; persist a PRF-derived pending device and proof of possession before publishing the challenge. |
| `authorize_device`, `accept_pairing` | Check recipient proof, injected approval, community/pseudonym/root/epoch/challenge/deadline and exact recipient; commit signed lineage and sealed root before returning a grant. Accept once only. |
| `renew_pairing` | Renew an expired pending challenge with fresh authority; preserve the device key and require a fresh request/approval. |
| `rename_device` | Change only the encrypted local name, preserving device keys, public lineage and authority reference. |
| `adopt_lineage` | Root-signed additions in the same epoch; no rollback, equal-revision replacement or removals. |
| `prepare_rotation`, `commit`, `cancel_prepared` | Remove another device, derive the next epoch root from this credential's private lineage seed, increment epoch/revision, old-root-sign succession and seal the new root to every survivor. Publish only after durable commit. |
| `apply_rotation` | Verify exact predecessor and both root signatures. Surviving devices import only their own envelope; the removed device erases its root. |
| `key` | Opaque session-bound purpose handle + device-signed public certificate. No raw key getters. |
| `sign`, `sign_ed25519` | Sign exact owner transcripts under a purpose capability. VLD0 Ed25519ph and plain Ed25519 have separate APIs and return types. |
| `seal`, `open` | Purpose encryption with context as AAD. Member scope works across paired devices; device scope is independent. |
| `lineage`, `device_info` | Fresh authorized access to public lineage or local private name/authority reference. Names/references never enter public outputs. |
| `pending_output`, `acknowledge` | Replay the exact durable receipt; clear only its operation ID after idempotent publication. One outstanding output bounds memory and prevents overwriting unfinished publication. |
| `passkey::vault_location`, `store_cipher` | PRF-derived community-local locator and a separate opaque wrapping capability for a storage adapter. No wrapping-key getter. |

Device-side **cpky Passkeys** is the only code that talks to WebAuthn; server-side
**ckyh Keyhole** verifies authentication. Keys never builds options, acquires PRF,
or touches RP IDs, credentials or assertions. See [the adapter move](PASSKEYS.md).
`PrfOutput::from_bytes` is trusted opaque input, not proof of a ceremony. The
caller must wipe its own source buffer and keep the PRF out of server payloads.
`cwst` receives only an opaque `StoreCipher` capability. No password/key getter exists.

Wallet custody is separate: `passkey::identity_roots` derives the identity root
and passport holder seed with independent labels. It offers only public identity
verification material and domain-bound possession proofs; the holder seed stays
internal. The existing passport engine must be integrated without exporting it.
No issuer credential, membership decision or global identifier is fabricated here.

## States and publication

Locked → Authorized or PendingDevice on successful unlock; missing storage →
MissingCheckpoint. Explicit authorized restoration, creation or pairing preparation → Prepared → committed
Authorized/PendingDevice. PendingDevice → Authorized only through the exact grant.
Authorized → Prepared → Authorized on root rotation. Applying removal → Revoked.
Lock from any state wipes decrypted material. Uncertain/conflicting/cancelled write
→ Reconcile with no decrypted state. Unlock reconciles the actual stored winner.

Every mutation validates and seals a candidate before a compare/exchange. The
replacement includes the exact output and operation ID. No output is returned
before Committed. Failed/unknown writes must never be retried by generating keys;
load the current checkpoint and replay its pending output instead. A cancellation
during the store future has the same rule. A known failure before writing leaves
the old checkpoint intact. A cancelled prepared rotation has no storage effect.

Receipt publication and acknowledgement belong to the vault. Publication must be
idempotent by operation ID. On crash after publication but before acknowledgement,
the same receipt is published again. Acknowledgement itself is a CAS mutation.
No multi-domain atomicity is claimed by this leaf: the cwst/cmsg adapter must place
its ciphertext and pending output in the enclosing composite checkpoint.

## Trusted ports

- SecureStore supplies authoritative, bounded reads and durable atomic CAS by the
  BLAKE3 digest of the exact previous ciphertext. It must prevent rollback/ABA and
  must not acknowledge volatile writes as durable. It sees no root/device plaintext.
  No production Memory/file/IndexedDB/network store is hidden inside ckmg.
- Authority authenticates the binding, origin, current root/epoch, device and exact
  live passkey authority. Pairing proof of possession alone is insufficient. Pair
  approval binds the request digest/recipient; rotation approval binds predecessor
  digest and revoked device. Use must refuse stale/revoked authority or unavailable
  freshness. Restore must bind the exact current lineage digest, reject stale
  revisions and authenticate the derived device as currently unrevoked. Adopt checks the independently authenticated transition. This is an
  explicit trusted port, not an unchecked `Verified*` constructor or membership API.
- Clock supplies current Unix seconds. Regressions against the session and stored
  mutation floor fail closed. Pairing uses a half-open window of at most 300 seconds.
- Entropy must fill from a CSPRNG or fail. SystemEntropy uses getrandom/Web Crypto.
  Deterministic entropy exists only in tests. No secret generation uses wall time.

Independent devices may propose concurrent lineage additions. This leaf refuses
stale/equivocating predecessors; cdht/cvlt must serialize or explicitly reconcile
those proposals. It does not merge authority or decide device-removal policy.

## Wire/storage boundaries and limits

- Typed public keys/signatures/hashes: `VLD0:<base64url-no-pad>`, binary `VLD0 || raw`.
- All owned transcripts have explicit v1 domain labels; canonical tuples serialized
  by serde_json in fixed field order. Integers only, no floating point or maps. Input
  transport whitespace does not change the canonical signed transcript. Transport
  adapters must bound encoded input before serde allocates; all semantic operations
  validate shape, key kind, count, lengths and signatures again.
- KeyCertificate authenticates community, pseudonym, epoch, device, purpose and key.
  Verifiers must check it against independently authenticated **current** lineage and
  their expected purpose, then verify the exact owner payload signature. A lineage
  self-signature alone is not a trust anchor, revocation feed or freshness proof.
- HPKE root envelope: Veilid v1 `0x01 || VLD0 || enc[32] || ciphertext+tag`; context
  binds the complete pairing request/lineage or predecessor/successor/recipient.
- Custody checkpoint: `ckmg.checkpoint.v1\0 || nonce[24] || ciphertext+tag`.
  Plaintext is LE-u32 metadata length, versioned metadata JSON, root-present byte,
  device seed[32], optional root seed[32]. AAD binds header and PRF-derived locator.
- Purpose ciphertext: `ckmg.purpose.sealed.v1\0 || nonce[24] || ciphertext+tag`;
  AAD binds binding/epoch/purpose, device for Device scope, and exact caller context.
- Maximum checkpoint 256 KiB, 128 devices, owner payload/plaintext 1 MiB, context or
  authority evidence 4096 bytes, name 128 bytes, authority reference 1024 bytes,
  binding components 256 bytes, purpose label 64 ASCII bytes. Checked counters never
  wrap. These are implementation resource ceilings, not product eligibility policy.

Purpose generations are owner-managed labels. Bumping a generation derives another
key but does not remotely revoke older signatures. Root epochs invalidate all old
handles/certificates when verifiers adopt current lineage. `lock`/`unlock` also
invalidate local handles, while deriving the same authorized keys after restore.

## Acceptance and limits

Native and browser Wasm execute the same real crypto/state tests, including storage
CAS, clock regression, tampering, consent signatures, pairing, rotation, corruption,
unknown outcomes and cancellation. Tests need no external accounts or services.
This pure leaf has no network port to fake and no Tor acceptance claim.

Root rotation preserves the exact member binding and does not touch accounting
state, so it cannot reset an account through this API. The composite cblc/cwst test
that also preserves obligations belongs to the downstream integration gate.

An injected adapter can lie, and a holder who copies secrets from compromised
process memory can still sign with old keys. Current-epoch enforcement is required
at recipients. A stale encrypted record alone cannot prove current device authority.
Storage availability, network retention, passport renewal and actual membership
restoration are downstream integration gates. There is no operator recovery,
plaintext root export or backup service.

## Restoration boundaries

The same PRF and stable domain regenerate all personal root inputs even without
vault records. Authenticated membership binding and current authority metadata are
still needed: determinism does not prove freshness or authorize a member. The
original credential regenerates its initial shared root; a credential that last
rotated the root regenerates its current epoch directly (`RestoreRoot::Derived`).
No identity or member binding is replaced, and all existing devices in the anchor
remain unchanged. Checkpoints made before deterministic derivation cannot acquire
this property retroactively; no migration or fallback is provided for development
checkpoints containing independently random roots.

A distinct paired PRF derives an independent device key; it cannot derive someone
else's shared root. `RestoreRoot::Paired` opens its authenticated retained grant.
After another credential rotates, `RestoreRoot::Rotated` opens the surviving
device's envelope. These signed/ciphertext transfers contain no lineage seed and
must be retained with authority metadata outside disposable vault data by cvlt.
Historical pairing expiry does not revoke an already authorized device: restoring
it requires fresh Restore authority and current inclusion. A stale transfer cannot
restore a different current root or epoch.

If every copy of a transferred root envelope is gone, a non-originating credential
still derives its personal identity/device seeds, but cannot reconstruct that
shared root. Keys fails closed rather than replacing the member or bypassing
revocation. The product must resolve transfer retention/reenrollment and the real
passport-engine integration before claiming the complete all-passkey restore
promise. See [SECURITY-REVIEW](SECURITY-REVIEW.md).
