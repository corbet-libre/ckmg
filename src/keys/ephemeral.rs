//! Ephemeral transport custody for one registration's bootstrap Tor client.
//!
//! A fresh registration publishes its first lineages before any member vault, and so any
//! passkey-derived transport identity, exists. This custody holds a random node key and a
//! random onion key in memory only: no PRF, no binding, no root, device or purpose key, no
//! store. Nothing here can be persisted or exported; dropping it (at registration `Done`)
//! wipes both keys and stops every engine they started. The keys authorize nothing beyond the
//! transport of the one scope they were made for: every scope gets its own custody.
use super::*;

/// Random, in-memory transport keys for one scope of one registration.
pub struct EphemeralTransport {
    node: Option<Secret>,
    onion: Option<Secret>,
    label: String,
    #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
    native: crate::native_tor::Custody,
    #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
    browser: crate::browser_tor::Custody,
}

impl EphemeralTransport {
    /// Fresh keys from `entropy`. `label` names the scope for the engine (for example
    /// `registration.wallet`); it is public and never a member identifier.
    pub fn new(entropy: &mut impl Entropy, label: &str) -> Result<Self, Error> {
        if label.is_empty() || label.len() > 128 {
            return Err(Error::Limit);
        }
        let mut fresh = || -> Result<Secret, Error> {
            let mut secret = Zeroizing::new([0u8; 32]);
            entropy.fill(secret.as_mut())?;
            if *secret == [0; 32] {
                return Err(Error::Randomness);
            }
            Ok(secret)
        };
        let node = fresh()?;
        let onion = fresh()?;
        if *node == *onion {
            return Err(Error::Randomness);
        }
        Ok(Self {
            node: Some(node),
            onion: Some(onion),
            label: label.to_owned(),
            #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
            native: crate::native_tor::Custody::default(),
            #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
            browser: crate::browser_tor::Custody::default(),
        })
    }

    /// Public node identity of this scope.
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        self.node
            .as_ref()
            .map(vld0::public_key)
            .ok_or(Error::Locked)
    }

    /// Lend node signing/DH for one envelope. No member authority exists to check: the key
    /// is random and belongs to this transport only.
    pub fn with_node<T>(
        &self,
        use_node: impl for<'key> FnOnce(Vld0Signer<'key>, crate::Vld0NodeCipher<'key>) -> T,
    ) -> Result<T, Error> {
        let secret = self.node.as_ref().ok_or(Error::Locked)?;
        let public_key = *vld0::public_key(secret).value();
        Ok(use_node(
            Vld0Signer(Ed25519Signer { secret, public_key }),
            crate::Vld0NodeCipher { secret, public_key },
        ))
    }

    /// Transfer the onion key into the native engine.
    #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
    pub fn native_initializer(
        &mut self,
        scope: ctrn::Scope,
    ) -> Result<crate::NativeTorInitializer, Error> {
        let onion = self.onion.as_ref().ok_or(Error::Locked)?.clone();
        self.native
            .initializer(scope, onion, self.label.clone(), true)
    }

    /// Transfer the onion key into the browser engine.
    #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
    pub fn browser_initializer(
        &mut self,
        scope: ctrn::Scope,
    ) -> Result<crate::BrowserTorInitializer, Error> {
        let onion = self.onion.as_ref().ok_or(Error::Locked)?.clone();
        self.browser
            .initializer(scope, onion, self.label.clone(), true)
    }

    /// Wipe both keys and stop every engine they started.
    pub fn lock(&mut self) {
        self.node = None;
        self.onion = None;
        #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
        self.native.close();
        #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
        self.browser.close();
    }
}

impl Drop for EphemeralTransport {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts every byte asked for; the only input the custody may use.
    struct Counted(u64, usize);
    impl Entropy for Counted {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
            for byte in output.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (self.0 >> 56) as u8;
            }
            self.1 += output.len();
            Ok(())
        }
    }

    #[test]
    fn keys_come_from_entropy_alone_and_differ_per_scope() {
        let mut entropy = Counted(1, 0);
        // No PRF, binding, store or backend is an input: the constructor takes entropy only.
        let wallet = EphemeralTransport::new(&mut entropy, "registration.wallet").expect("wallet");
        assert_eq!(entropy.1, 64, "exactly two fresh keys");
        let community =
            EphemeralTransport::new(&mut entropy, "registration.community").expect("community");
        assert_ne!(
            wallet.public_key().expect("wallet key"),
            community.public_key().expect("community key"),
            "two scopes never share a transport identity"
        );
        let signed = wallet
            .with_node(|signer, _| (*signer.public_key(), signer.sign(b"x").expect("sign")))
            .expect("node");
        assert_eq!(&signed.0, wallet.public_key().expect("key").value());
    }

    #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
    #[test]
    fn its_engine_dials_only_and_locks_with_it() {
        let mut transport =
            EphemeralTransport::new(&mut Counted(3, 0), "registration.wallet").expect("transport");
        let initializer = transport
            .native_initializer(ctrn::Scope([4; 32]))
            .expect("initializer");
        assert!(
            initializer.client_only,
            "an ephemeral identity never publishes an onion service"
        );
        transport.lock();
        assert!(transport.native_initializer(ctrn::Scope([4; 32])).is_err());
    }

    #[test]
    fn a_locked_custody_lends_nothing() {
        let mut transport =
            EphemeralTransport::new(&mut Counted(7, 0), "registration.wallet").expect("transport");
        transport.lock();
        assert!(matches!(transport.public_key(), Err(Error::Locked)));
        assert!(matches!(transport.with_node(|_, _| ()), Err(Error::Locked)));
    }

    #[test]
    fn broken_entropy_and_bad_labels_are_refused() {
        struct Zero;
        impl Entropy for Zero {
            fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
                output.fill(0);
                Ok(())
            }
        }
        assert!(matches!(
            EphemeralTransport::new(&mut Zero, "registration.wallet"),
            Err(Error::Randomness)
        ));
        assert!(EphemeralTransport::new(&mut Counted(1, 0), "").is_err());
        assert!(EphemeralTransport::new(&mut Counted(1, 0), &"x".repeat(129)).is_err());
    }
}
