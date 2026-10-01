# Passkey boundary and adapter move

The passkey is the member's key. **cpky Passkeys runs on the device** and owns
WebAuthn registration, sign-in, adding a passkey and acquiring the PRF secret.
**ckyh Keyhole runs on the server**, stores the public half and verifies whether
the key fits. `ckmg` Keys receives only opaque PRF input and derives custody.

The former `ckmg::passkey::browser` adapter has been removed. Its
`navigator.credentials` calls, `RelyingParty`, `RegistrationRequest`, `LoginRequest`,
`Registration`, `Assertion`, `COSE_ALGORITHMS`, `unlock_prf_input` and browser-only
errors belong in device-side **cpky**, not in Keys. The removed code is available
in Git history for the cpky implementation; this change does not claim to have
implemented or browser-tested cpky. There are no credentials APIs in ckmg's Wasm
build. Web Crypto remains the platform entropy source through `getrandom`.

The adapter move must preserve a versioned PRF input. The historical adapter used
`blake3::derive_key("ckmg 2026-09 passkey PRF input for vault store unlock v1", b"")`.
That is compatibility evidence for cpky, not a PRF-input API retained in Keys.
Changing the PRF evaluation input changes every derived root. cpky must qualify
synced-provider, native and browser behavior, refuse member registration without
PRF, use server ceremony options, and strip PRF results from outbound responses.
Keyhole must reject responses containing PRF output. Root/admin exceptions are
policy outside Keys.

The local adapter copies the 32-byte result into `PrfOutput::from_bytes`, then
wipes its own source buffers. Keys has no way to verify how those bytes were
obtained: a local constructor is not authentication. The injected Authority port
must verify live membership/device authority separately. `cwst` receives only the
opaque `StoreCipher` from `passkey::store_cipher`, never the input or any key bytes.

`identity_roots` is wallet custody, separate from each community's `Keys`. The
application must use a stable wallet domain and the wallet's own passkey. Never
publish a wallet identity key, holder seed or cross-community locator as a member
identifier. A community binding uses the existing verified pseudonym.
