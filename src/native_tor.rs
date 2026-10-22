//! Consume-only purpose custody for the existing Arti adapter. No network I/O.
use crate::Secret;
use std::sync::{Arc, Mutex, Weak};
use tor_hscrypto::pk::HsIdKeypair;
use tor_llcrypto::pk::ed25519;

/// Only an original, freshly authorized Keys purpose handle can construct this
/// capability. It has no key getter, Clone, Debug or serialization. Consumption
/// installs its private provider directly inside the maintained Arti adapter.
///
/// This is native engine custody, not a membership or network-readiness grant.
/// Original Keys invalidation/drop stops registered Nodes and wipes unused
/// purpose custody. The runtime must still close Mesh and enforce live authority.
pub struct NativeTorInitializer {
    scope: ctrn::Scope,
    lease: Arc<Lease>,
    community: String,
    /// An ephemeral registration identity dials only: its Node never publishes an onion
    /// service (`ctrn::ClientOnly`).
    pub(crate) client_only: bool,
}

const MAX_ENGINES: usize = 8;
#[derive(Default)]
pub(crate) struct Custody(Vec<Weak<Lease>>);
impl Custody {
    pub(crate) fn initializer(
        &mut self,
        scope: ctrn::Scope,
        secret: Secret,
        community: String,
        client_only: bool,
    ) -> Result<NativeTorInitializer, crate::Error> {
        self.0.retain(|entry| entry.strong_count() != 0);
        if self.0.len() >= MAX_ENGINES {
            return Err(crate::Error::Limit);
        }
        let lease = Arc::new(Lease(Mutex::new(Held {
            secret: Some(secret),
            node: None,
        })));
        self.0.push(Arc::downgrade(&lease));
        Ok(NativeTorInitializer {
            scope,
            lease,
            community,
            client_only,
        })
    }
    pub(crate) fn close(&mut self) {
        for lease in self.0.drain(..).filter_map(|entry| entry.upgrade()) {
            lease.close();
        }
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        self.close();
    }
}

struct Held {
    secret: Option<Secret>,
    node: Option<Weak<ctrn::Node>>,
}
struct Lease(Mutex<Held>);
fn closed() -> ctrn::Error {
    ctrn::Error::new(ctrn::ErrorKind::Closed, "onion custody closed")
}
impl Lease {
    fn close(&self) {
        // Cleanup must wipe/stop even after an interrupted critical section.
        let node = {
            let mut held = self.0.lock().unwrap_or_else(|error| error.into_inner());
            held.secret = None;
            held.node.take().and_then(|node| node.upgrade())
        };
        if let Some(node) = node {
            node.stop();
        }
    }
    fn bind(&self, node: &Arc<ctrn::Node>) -> Result<(), ctrn::Error> {
        let mut held = self.0.lock().map_err(|_| closed())?;
        if held.secret.is_none() || held.node.is_some() {
            return Err(closed());
        }
        held.node = Some(Arc::downgrade(node));
        Ok(())
    }
}

// This type is private so the engine's necessary key-supplying trait cannot
// become a general key getter on the exported Keys capability.
struct Identity {
    scope: ctrn::Scope,
    lease: Arc<Lease>,
}
impl ctrn::arti::Identity for Identity {
    fn onion_key(&self, scope: &ctrn::Scope) -> Result<HsIdKeypair, ctrn::Error> {
        if scope != &self.scope {
            return Err(ctrn::Error::new(
                ctrn::ErrorKind::Protocol,
                "onion custody scope mismatch",
            ));
        }
        // Exactly Arti's maintained Ed25519 expansion, as used by ctrn. No
        // private encoding, curve conversion or onion-address derivation here.
        let held = self.lease.0.lock().map_err(|_| closed())?;
        let secret = held.secret.as_ref().ok_or_else(closed)?;
        let pair = ed25519::Keypair::from_bytes(secret);
        Ok(HsIdKeypair::from(ed25519::ExpandedKeypair::from(&pair)))
    }
}

impl NativeTorInitializer {
    /// Public community scope authenticated by the original Keys owner. The
    /// trusted Door checks this before attaching the engine to its own scope.
    pub fn community(&self) -> &str {
        &self.community
    }

    /// Build the original stopped Tor Node, consuming this capability once.
    /// Arti enforces explicit state/cache paths and an ephemeral onion keystore.
    /// Node::start and listen must actually finish before claiming readiness.
    pub fn initialize<R: tor_rtcompat::Runtime>(
        self,
        runtime: R,
        configuration: arti_client::config::TorClientConfigBuilder,
        directories: ctrn::arti::Directories,
        clock: Arc<dyn ctrn::Clock>,
        limits: ctrn::Limits,
    ) -> Result<Arc<ctrn::Node>, ctrn::Error> {
        let scope = self.scope;
        let network = ctrn::arti::ArtiNetwork::new(
            runtime,
            configuration,
            directories,
            Arc::new(Identity {
                scope: scope.clone(),
                lease: self.lease.clone(),
            }),
        )?;
        let network: Arc<dyn ctrn::Network> = if self.client_only {
            Arc::new(ctrn::ClientOnly::new(Arc::new(network)))
        } else {
            Arc::new(network)
        };
        let node = Arc::new(ctrn::Node::new(network, clock, scope, limits)?);
        self.lease.bind(&node)?;
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctrn::arti::Identity as _;

    #[test]
    fn original_arti_expansion_keeps_the_keys_public_purpose_and_refuses_other_scope() {
        let secret = Secret::new([37; 32]);
        let expected = crate::vld0::public_key(&secret);
        let mut custody = Custody::default();
        let initializer = custody
            .initializer(ctrn::Scope([9; 32]), secret, "garden".into(), false)
            .unwrap();
        let identity = Identity {
            scope: initializer.scope,
            lease: initializer.lease,
        };
        let key = identity.onion_key(&ctrn::Scope([9; 32])).unwrap();
        let public = tor_hscrypto::pk::HsIdKey::from(&key);
        let public: &ed25519::PublicKey = public.as_ref();
        assert_eq!(public.as_bytes(), expected.value());
        assert!(identity.onion_key(&ctrn::Scope([10; 32])).is_err());
        custody.close();
        assert!(identity.onion_key(&ctrn::Scope([9; 32])).is_err());
    }

    #[test]
    fn outstanding_engine_custody_is_bounded_and_dropped_capabilities_release_capacity() {
        let mut custody = Custody::default();
        let mut pending = Vec::new();
        for index in 0..MAX_ENGINES {
            pending.push(
                custody
                    .initializer(
                        ctrn::Scope([index as u8; 32]),
                        Secret::new([1; 32]),
                        "garden".into(),
                        false,
                    )
                    .unwrap(),
            );
        }
        assert!(matches!(
            custody.initializer(
                ctrn::Scope([33; 32]),
                Secret::new([2; 32]),
                "garden".into(),
                false
            ),
            Err(crate::Error::Limit)
        ));
        pending.pop();
        assert!(
            custody
                .initializer(
                    ctrn::Scope([33; 32]),
                    Secret::new([2; 32]),
                    "garden".into(),
                    false
                )
                .is_ok()
        );
    }
}
