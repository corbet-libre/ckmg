# ckmg contract

Status: implemented library contract; independent security review and downstream
G3 device-authority integration are required before production acceptance.

`Keys<S, C, R, A>` is one logical device in one community. It owns a community
root, PRF-derived device seed, purpose derivation, signed device lineage, pairing,
root replacement and encrypted custody checkpoints. It contains no network,
filesystem, membership evaluator, ledger or recovery service. Optional global
holder custody is installed only in its separately selected wallet scope.
`Binding.member` is the externally verified cpsd pseudonym, never a root hash.

## API

| Operation | Input and result |
|---|---|
| `new`, `state`, `lock` | Inject SecureStore, Clock, Entropy and Authority; start locked; wipe decrypted keys on lock. |
| `create_scope` | Explicit new-member authorization, PRF, binding and private device metadata; atomically persist a random common root and PRF-derived device and a Created receipt. Never overwrite an existing record. |
| `unlock` | PRF + community derive the locator and custody key; decrypt exactly the stored logical device, including pending outputs. Absence yields MissingCheckpoint; no implicit creation. |
| `restore_scope` | Authoritatively absent record, same PRF, exact current lineage, Restore authorization and a retained authenticated root transfer; reconstruct the same logical device and commit a Restored receipt. |
| `request_pairing` | Confirmed lineage, fresh PRF and private metadata; persist a PRF-derived pending device and proof of possession before publishing the challenge. |
| `authorize_device`, `accept_pairing` | Check recipient proof, injected approval, community/pseudonym/root/epoch/challenge/deadline and exact recipient; commit signed lineage and sealed root before returning a grant. Accept once only. |
| `renew_pairing` | Renew an expired pending challenge with fresh authority; preserve the device key and require a fresh request/approval. |
| `rename_device` | Change only the encrypted local name, preserving device keys, public lineage and authority reference. |
| `adopt_lineage` | Root-signed additions in the same epoch; no rollback, equal-revision replacement or removals. |
| `prepare_rotation`, `commit`, `cancel_prepared` | Remove another device, generate a fresh random epoch root while preserving the common identity root, increment epoch/revision, old-root-sign succession and seal the new root to every survivor. Publish only after durable commit. |
| `apply_rotation` | Verify exact predecessor and both root signatures. Surviving devices import only their own envelope; the removed device erases its root. |
| `key` | Opaque session-bound purpose handle + device-signed public certificate. No raw key getters. |
| `sign`, `sign_ed25519` | Sign exact owner transcripts under a purpose capability. VLD0 Ed25519ph and plain Ed25519 have separate APIs and return types. |
| `with_ed25519_signer` | Fresh asynchronous authority check, then a synchronous, borrowed plain-Ed25519 signer for an upstream engine. Only public key/sign operations; the purpose seed stays inside Keys and the signer cannot escape the callback. |
| `with_vld0_signer` | Borrow a distinct synchronous VLD0 purpose signer after fresh authorization; retain the original descriptor/value transcript bytes and VLD0_SIGN context. |
| `with_device_ed25519_signer` | Borrow the actual lineage device signer after fresh authorization for owner formats such as profile publication. Its public key matches Lineage.devices; a purpose key is not a device substitute. |
| `with_holder_seed` | With feature passport, lend a one-use opaque holder initializer after fresh current authorization. Wallet consumes it and owns the resulting maintained engine; no byte/RNG getter or raw callback exists. |
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

Wallet custody uses the retained random common identity root, isolated from each
community's scope. Keys lends `HolderSeed` after current authority checks. Its only
consumer operation, `into_passport_holder`, initializes the maintained
`cpsd::OpaqueHolder` with a temporary zeroizing derived seed; it returns no seed,
RNG, credential or existing engine borrow. Wallet wraps and owns that new engine,
its sessions, installed passport, and encrypted checkpoint. Keys never depends on
Wallet or keeps a Wallet instance. The composing Vault must drop Wallet on lock or
revocation and authorize each subsequent operation. Durable Wallet checkpoint and
real Foyer/global-service flow remain separate acceptance obligations.

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
- All owned transcripts have explicit versioned domain labels; canonical tuples serialized
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
  Plaintext is LE-u32 metadata length, versioned metadata JSON, material format byte,
  device seed[32], optional epoch root[32] and common identity root[32]. Formats 0/1
  preserve historical empty/root-only material; format 2 retains both roots. AAD
  binds the unchanged header and PRF-derived locator. Historical transcript labels
  are never silently reinterpreted; new lineage/transfer shapes use new versions.
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

The common identity root is random. No passkey has privileged recordless recovery.
Every enrolled passkey needs its own retained encrypted copy, either a custody
checkpoint or an authenticated pairing/current-epoch envelope. Devices refresh
member-owned DHT records during ordinary use; no operator copy or recovery service
exists. A network outage is not evidence that every copy is permanently gone.

`RestoreRoot::Paired` opens the exact retained transfer for the current lineage.
`RestoreRoot::Rotated` opens a surviving device's current epoch envelope. Both carry
the common identity root under existing upstream HPKE and are then committed under
the recipient's PRF-derived checkpoint key. Pairing expiry does not invalidate a
retained enrolled device; fresh authority must still authenticate the exact current
lineage and refuse revoked devices. Root rotation never changes the common identity.

Historical root-only checkpoints/transcripts remain readable without relabeling or
inventing lost material. They cannot silently acquire a new common identity.
`RestoreRoot::Derived` is retained as a refusing compatibility spelling and always
returns MissingCheckpoint after the ordinary authority checks. The obsolete public
PRF-to-identity factory is removed. No migration policy is implied by decoding old
records; full migration and downstream compound retention require owner integration.

If long absence and loss of every device copy also leave no DHT records, identity
and data are lost with equal implications for every passkey. The active-member
restore promise still requires actual Keys/Wallet/Records/Vault round trips and
network retention measurements. See [SECURITY-REVIEW](SECURITY-REVIEW.md).

Purpose capabilities bind the current epoch. Rotation retains the authenticated
earlier epoch roots inside encrypted custody before replacing the current root.
Version-3 transfers also carry this ordered opening history to surviving and newly
paired devices. Existing version-1/2 bytes retain their original meanings. There is
no pruning policy: the existing checkpoint size limit refuses a rotation that
cannot retain the complete history. Removed devices erase this local history.
`open_historical` and `with_historical_vld0_reader` require a fresh current handle
and live device authority; neither exposes a root or historical signer. Old handles
remain invalid. Original domain/epoch/purpose/context and record nonce are preserved.
These APIs open archived application data. They do not clone MLS ratchets or claim
that a different device can resume a Threads session. Full owner-record network
restore and current server G3 authority still need integration qualification.

The native-records feature transfers only purpose-derived owner/read material into cvln RecordInitializer; there is no raw key getter or network I/O in Keys. Passkey bootstrap derives distinct owner and read keys from the PRF and community under independent HKDF labels, with fixed owner-only DFLT(1). Its schema-derived Veilid locator is never the local checkpoint Locator. A current-authorized purpose handle initializes a vault record with the same VLD0 owner and read cipher as the existing scoped Tor operations. The composing runtime closes opened native records on lock/revocation; retained engines do not prove later G3. This initializes record custody only; it does not implement root-record payload retention or claim remote restore.

The thread-confined intent_channel has separate Door admission and Authority verification halves, neither clonable/serializable/debuggable. The Door reserves exact authenticated command scope plus origin and exclusive deadline; the guard spans child awaits and transport cancellation. Verification consumes one attempt, even on mismatch/expiry/clock regression. Successful intent consumption is not G3: the composer must first verify actual live Foyer authority and independently authenticated current Records lineage, recheck deadlines after awaits, then consume before permitting Keys. Explicit cancellation and generation-safe guard drop cannot revoke later admissions. No signature/token protocol or accepting authority implementation is added.

Every new durable Keys Receipt additionally carries a VLD0 device attestation over the exact operation ID and complete Change. The signature is created internally before checkpoint encryption and committed atomically with that output. Receipt::attested_lineage checks that signature, original root-signed lineage and author inclusion; it deliberately grants no active-passkey/currentness authority. Vault must additionally verify an original passkey assertion over Receipt::passkey_challenge against the Policy-authenticated credential descriptor and current offline passkey revocations, then apply the reviewed higher-epoch/smaller-hash rule among valid observations. A delegated device signature does not satisfy that requirement. Historical receipts remain readable but an absent attestation cannot authorize a new lineage publication. Keys State, DeviceInfo, Binding and Lineage expose owner Serde/JsonSchema metadata for the Door, with public cryptographic types described as their actual serialized strings (never raw arrays).

Keys::retained_checkpoint exports only the exact already-durable PRF-encrypted Keys checkpoint after current authority and generation verification. RestoreRoot::Checkpoint reuses that existing format and AEAD; it requires authoritative local absence plus independently authenticated current lineage/device authority, validates all retained material, refuses wrong PRF/scope, revoked/pending devices, root/epoch/identity mismatch and clock rollback. It can restore the original passkey's random root just like every enrolled passkey, but cannot restore without a retained copy. Vault may place this opaque wrapped payload in its passkey record after compression/padding; packed-size refusal is a retention failure, never pruning or a new identity. No MLS ratchet or Wallet state is copied by this Keys operation.
