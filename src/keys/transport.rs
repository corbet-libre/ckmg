//! Independent fixed-purpose transport custody; no root or member key is held.
use super::*;

/// Session custody for Tor before and during member-lineage reads. Only derived
/// onion/node keys are retained. Its independent Authority uses fresh HTTPS
/// membership and shared observed-removal state, never a recursive lineage read.
pub struct TransportSession<C, A> {
    binding: Binding,
    device: PublicKey,
    onion: Option<Secret>,
    node: Option<Secret>,
    clock: C,
    authority: A,
    last_time: u64,
    #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
    native: crate::native_tor::Custody,
    #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
    browser: crate::browser_tor::Custody,
}
impl<C: Clock, A: Authority> TransportSession<C, A> {
    /// Derive only fixed-purpose custody from the unlocked passkey session.
    /// No authority or readiness is granted. Epoch zero denotes transport
    /// custody independent of member root epochs; the original purpose KDF and
    /// generation zero are unchanged. No device seed survives this constructor.
    pub fn new(prf: &PrfOutput, binding: Binding, clock: C, authority: A) -> Result<Self, Error> {
        let seed = passkey::device_seed(prf, binding.community())?;
        let device = vld0::public_key(&seed);
        let derive = |node: NodePurpose| -> Result<Secret, Error> {
            let purpose = node.purpose(0)?;
            let context = encode(
                b"ckmg.purpose.context.v1\0",
                &(&binding, 0u64, Some(device), &purpose, &[] as &[u8]),
            )?;
            Ok(derive_purpose_secret(&seed, &context, false))
        };
        Ok(Self {
            onion: Some(derive(NodePurpose::TorOnion)?),
            node: Some(derive(NodePurpose::Vld0)?),
            binding,
            device,
            clock,
            authority,
            last_time: 0,
            #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
            native: crate::native_tor::Custody::default(),
            #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
            browser: crate::browser_tor::Custody::default(),
        })
    }
    async fn check(&mut self, purpose: NodePurpose) -> Result<(), Error> {
        if self.node.is_none() || self.onion.is_none() {
            return Err(Error::Locked);
        }
        // Cancellation is a refusal too: do not leave a previously started
        // onion engine alive when an in-flight fresh check is abandoned.
        let mut guard = CheckGuard {
            session: self,
            accepted: false,
        };
        guard.session.check_current(purpose).await?;
        guard.accepted = true;
        Ok(())
    }
    async fn check_current(&mut self, purpose: NodePurpose) -> Result<(), Error> {
        let now = self.clock.now()?;
        if now < self.last_time {
            return Err(Error::Clock);
        }
        self.last_time = now;
        self.authority
            .check(Authorization {
                binding: &self.binding,
                root: None,
                device: self.device,
                epoch: 0,
                action: Action::UseTransport(purpose),
                target: None,
                statement: None,
                signing: None,
                now,
                evidence: &[],
            })
            .await?;
        let after = self.clock.now()?;
        if after < now {
            return Err(Error::Clock);
        }
        self.last_time = after;
        Ok(())
    }
    /// Public node identity. Signing/DH always requires fresh transport authority.
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        self.node
            .as_ref()
            .map(vld0::public_key)
            .ok_or(Error::Locked)
    }
    /// Lend node signing/DH without a member Keys borrow or Store mutex. Only
    /// owned original envelope output may cross the following network await.
    pub async fn with_node<T>(
        &mut self,
        use_node: impl for<'key> FnOnce(Vld0Signer<'key>, crate::Vld0NodeCipher<'key>) -> T,
    ) -> Result<T, Error> {
        self.check(NodePurpose::Vld0).await?;
        let secret = self.node.as_ref().ok_or(Error::Locked)?;
        let public_key = *vld0::public_key(secret).value();
        Ok(use_node(
            Vld0Signer(Ed25519Signer { secret, public_key }),
            crate::Vld0NodeCipher { secret, public_key },
        ))
    }
    /// Transfer the fixed onion purpose into the original native engine.
    #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
    pub async fn native_initializer(
        &mut self,
        scope: ctrn::Scope,
    ) -> Result<crate::NativeTorInitializer, Error> {
        self.check(NodePurpose::TorOnion).await?;
        self.native.initializer(
            scope,
            self.onion.as_ref().ok_or(Error::Locked)?.clone(),
            self.binding.community().to_owned(),
        )
    }
    /// Transfer the fixed onion purpose into the original browser engine.
    #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
    pub async fn browser_initializer(
        &mut self,
        scope: ctrn::Scope,
    ) -> Result<crate::BrowserTorInitializer, Error> {
        self.check(NodePurpose::TorOnion).await?;
        self.browser.initializer(
            scope,
            self.onion.as_ref().ok_or(Error::Locked)?.clone(),
            self.binding.community().to_owned(),
        )
    }
}
struct CheckGuard<'a, C, A> {
    session: &'a mut TransportSession<C, A>,
    accepted: bool,
}
impl<C, A> Drop for CheckGuard<'_, C, A> {
    fn drop(&mut self) {
        if !self.accepted {
            self.session.lock();
        }
    }
}
impl<C, A> TransportSession<C, A> {
    /// Wipe custody and stop all initialized onion engines immediately.
    pub fn lock(&mut self) {
        self.onion = None;
        self.node = None;
        #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
        self.native.close();
        #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
        self.browser.close();
    }
}
impl<C, A> Drop for TransportSession<C, A> {
    fn drop(&mut self) {
        self.lock();
    }
}
