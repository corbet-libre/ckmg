# Reference fixture

`rfc9180_a2_base.json` is copied unchanged from Veilid
`veilid-core/src/crypto/tests_crypto/rfc9180_a2_base.json`, revision
`dd8e2cdd72b5bf817172ac31c20872b168c5c8fc`. It reproduces RFC 9180 A.2.1.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.

The companion reference composition lives in the separate MPL-2.0 file
`tests/unit/veilid_reference.rs`. It checks VLD0 signatures, typed keys, hash,
Ed25519→X25519 conversion, HPKE info/header and decryption in both directions.
It does not claim a live Veilid network or full veilid-core integration test.

`lineage-v1.json` preserves the historical lineage transcript independently of
the current encoder. Its public keys come from libsodium's
`crypto_sign_seed_keypair` with synthetic repeated-byte seeds 7 and 8. Python's
standard JSON encoder assembled the original tuple after the unchanged
`ckmg.lineage.v1\0` domain. Native and browser tests require exact bytes and a
real signature, omit the newly optional field from legacy serialization, and
reject identity-field/version substitution in the new retained-root format.
