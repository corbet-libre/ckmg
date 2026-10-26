//! Private browser engine custody for the original device onion purpose.
use crate::Secret;
use js_sys::{Function, Object, Reflect, Uint8Array};
use std::{
    rc::{Rc, Weak},
    sync::{Arc, Mutex, Weak as NodeWeak},
};
use wasm_bindgen::{JsCast, prelude::*};

/// Consume-only capability installed in the trusted browser Tor engine. It
/// exposes no secret getter, Clone, Debug or serialization. Keys invalidation
/// wipes the held purpose seed and stops its original Node immediately.
pub struct BrowserTorInitializer {
    scope: ctrn::Scope,
    lease: Rc<Lease>,
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
    ) -> Result<BrowserTorInitializer, crate::Error> {
        self.0.retain(|entry| entry.strong_count() != 0);
        if self.0.len() >= MAX_ENGINES {
            return Err(crate::Error::Limit);
        }
        let lease = Rc::new(Lease(Mutex::new(Held {
            secret: Some(secret),
            node: None,
        })));
        self.0.push(Rc::downgrade(&lease));
        Ok(BrowserTorInitializer {
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
    node: Option<NodeWeak<ctrn::Node>>,
}
struct Lease(Mutex<Held>);
fn closed() -> ctrn::Error {
    ctrn::Error::new(ctrn::ErrorKind::Closed, "onion custody closed")
}
fn js_closed() -> JsValue {
    JsValue::from_str("ctrn:Closed")
}
impl Lease {
    fn close(&self) {
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
        let mut held = self.0.lock().map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "closed", closed(), &__cause)
        })?;
        if held.secret.is_none() || held.node.is_some() {
            return Err(closed());
        }
        held.node = Some(Arc::downgrade(node));
        Ok(())
    }
}

// Retain wasm closures for exactly the driver lifetime. Dropping them makes any
// illicitly retained JS callback unusable; revocation also empties its lease.
struct Network {
    inner: ctrn::browser::BrowserNetwork,
    _factory: Closure<dyn Fn(JsValue) -> Result<JsValue, JsValue>>,
    _identity: Closure<dyn Fn(Uint8Array) -> Result<Uint8Array, JsValue>>,
}
#[ctrn::async_trait(?Send)]
impl ctrn::Network for Network {
    async fn start(&self, scope: &ctrn::Scope) -> Result<(), ctrn::Error> {
        self.inner.start(scope).await
    }
    async fn listen(&self) -> Result<Box<dyn ctrn::Listener>, ctrn::Error> {
        self.inner.listen().await
    }
    async fn dial(&self, endpoint: &ctrn::OnionEndpoint) -> Result<ctrn::BoxStream, ctrn::Error> {
        self.inner.dial(endpoint).await
    }
    fn ready(&self) -> bool {
        self.inner.ready()
    }
    fn stop(&self) {
        self.inner.stop();
    }
}

impl BrowserTorInitializer {
    /// Public community binding authenticated by Keys, checked by the Door.
    pub fn community(&self) -> &str {
        &self.community
    }

    /// Install private identity custody and construct the original stopped Node.
    /// The trusted factory must call `createTorJsBackend` with these options,
    /// scoped storage, Snowflake enabled and no gateway. Its maintained browser
    /// engine consumes and wipes the temporary 32-byte onion seed; this factory
    /// must never be an application-provided or generated-API callback.
    pub fn initialize(
        self,
        factory: Function,
        clock: Arc<dyn ctrn::Clock>,
        limits: ctrn::Limits,
    ) -> Result<Arc<ctrn::Node>, ctrn::Error> {
        let lease = self.lease.clone();
        let scope = self.scope.clone();
        let identity = Closure::<dyn Fn(Uint8Array) -> Result<Uint8Array, JsValue>>::new(
            move |supplied: Uint8Array| {
                if supplied.length() != 32 || supplied.to_vec() != scope.0 {
                    return Err(js_closed());
                }
                let held = lease.0.lock().map_err(|__cause| {
                    crate::cause::emit(file!(), line!(), "js_closed", js_closed(), &__cause)
                })?;
                let secret = held.secret.as_ref().ok_or_else(js_closed)?;
                // Copy only this purpose seed into the engine's transient JS
                // transfer buffer, never a root or a device master secret.
                Ok(Uint8Array::from(secret.as_slice()))
            },
        );
        let provider = Object::new();
        Reflect::set(&provider, &"onionKey".into(), identity.as_ref()).map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "closed", closed(), &__cause)
        })?;
        let wrapped =
            Closure::<dyn Fn(JsValue) -> Result<JsValue, JsValue>>::new(move |options: JsValue| {
                Reflect::set(&options, &"identity".into(), &provider).map_err(|__cause| {
                    crate::cause::emit(file!(), line!(), "js_closed", js_closed(), &__cause)
                })?;
                factory
                    .call1(&JsValue::UNDEFINED, &options)
                    .map_err(|__cause| {
                        crate::cause::emit(file!(), line!(), "js_closed", js_closed(), &__cause)
                    })
            });
        let network = Network {
            inner: ctrn::browser::BrowserNetwork::new(
                wrapped.as_ref().unchecked_ref::<Function>().clone(),
                self.scope.clone(),
            ),
            _factory: wrapped,
            _identity: identity,
        };
        // The original cross-platform Node API uses Arc. Its browser trait
        // bounds deliberately permit local JS owners; no Send claim is made.
        #[allow(clippy::arc_with_non_send_sync)]
        let network: Arc<dyn ctrn::Network> = if self.client_only {
            Arc::new(ctrn::ClientOnly::new(Arc::new(network)))
        } else {
            Arc::new(network)
        };
        let node = Arc::new(ctrn::Node::new(network, clock, self.scope, limits)?);
        self.lease.bind(&node)?;
        Ok(node)
    }
}
