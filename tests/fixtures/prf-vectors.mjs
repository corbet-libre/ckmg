// Independent reproduction of the fixed synthetic vectors in src/passkey.rs.
// Uses Node's OpenSSL-backed HKDF, not ckmg's Rust implementation.
import { hkdfSync } from 'node:crypto';
const derive = (ikm, salt, info) => Buffer.from(hkdfSync('sha256', ikm, salt, info, 32));
for (const name of [
  'vault-location', 'keyring-key', 'cwst-password', 'identity-root',
  'passport-holder-seed', 'device-lineage-seed', 'member-lineage-seed',
]) {
  const seed = derive(Buffer.alloc(32, 27), 'ckmg.passkey-prf.v1', `ckmg.${name}.v1\0a`);
  console.log(name, seed.toString('hex'));
  if (name === 'member-lineage-seed') {
    const epoch = Buffer.alloc(8);
    epoch.writeBigUInt64BE(1n);
    console.log('epoch-1-root', derive(seed, 'ckmg.lineage-root.v1', epoch).toString('hex'));
  }
}
