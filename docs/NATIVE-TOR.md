# Native onion custody

Enable `native-tor` for the original native Arti adapter. The trusted Vault
composer obtains a freshly authorized `Scope::Device` / `tor.onion` purpose
handle and calls `Keys::native_tor_initializer`. Only that narrow purpose crosses
into the engine. The initializer consumes itself directly into a stopped
`ctrn::Node`; it exposes no key getter or serialization. Arti uses its existing
Ed25519 expansion and ephemeral onion keystore. Community, device and root epoch
separation remains the original Keys purpose derivation.

Scope is an opaque capability namespace selected by the Vault composer, never
an action body. Limits, Tor configuration and explicit state/cache directories
are trusted deployment data. Constructing a Node performs no network I/O and
does not establish readiness. The runtime must actually start it, publish its
onion listener, retain the Mesh receive owner and handle disconnection.

Keys owns weak references to at most eight engine leases. Lock, failed authority,
checkpoint reconciliation, commit/rotation and Keys drop wipe their unused
purpose seeds and stop their registered Nodes. Initializers retained across
those transitions refuse construction; no native key provider is public.
The runtime must still close Mesh and enforce current authority on every domain
operation. A running anonymous transport does not grant membership, G2/G3,
Records availability, message acceptance or delivery.

`tests/it/native_tor.rs` covers actual stopped Arti construction and original Keys
refusals with the existing signed test-only Authority. Unit tests compare the
maintained Arti public key to the original Keys purpose public key and exercise
scope/invalidation. They are not production Authority or live-network evidence.
Execution, feature resolution and live private-Tor composition are pending CI.
