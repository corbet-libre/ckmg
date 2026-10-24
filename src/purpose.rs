//! Validated purpose labels; secret derivation stays inside the key machine.

use crate::Error;
use serde::{Deserialize, Serialize};

/// Maximum length of a purpose label.
pub const MAX_LABEL_BYTES: usize = 64;

/// Parent from which a purpose key derives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    /// Same purpose key on authorized devices holding the same community root.
    Member,
    /// Independent key on each device, also bound to the current root epoch.
    Device,
}

/// Scope, owner-defined label and generation. The owner chooses generations;
/// removing a device rotates the authority epoch and invalidates every old handle.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "PurposeWire", into = "PurposeWire")]
pub struct Purpose {
    scope: Scope,
    label: String,
    version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurposeWire {
    scope: Scope,
    label: String,
    version: u32,
}

impl TryFrom<PurposeWire> for Purpose {
    type Error = Error;
    // Wire purposes are facts inside certificates (a peer's `tor.node` key, say), so the
    // decoder checks only the label shape. Deriving a reserved purpose is refused where keys
    // are derived (`Keys::key`, `Keys::check_handle`), not here.
    fn try_from(value: PurposeWire) -> Result<Self, Error> {
        let purpose = Self {
            scope: value.scope,
            label: value.label,
            version: value.version,
        };
        purpose.validate_shape()?;
        Ok(purpose)
    }
}
impl From<Purpose> for PurposeWire {
    fn from(value: Purpose) -> Self {
        Self {
            scope: value.scope,
            label: value.label,
            version: value.version,
        }
    }
}

/// Label namespaces only ckmg derives: the Vault's own records (`vault.`), the node and
/// onion identities (`tor.`) and ckmg's internal keys (`ckmg.`).
const RESERVED: [&str; 3] = ["vault.", "tor.", "ckmg."];

impl Purpose {
    /// Validate an ASCII letters/digits/`._-:` label outside the reserved namespaces
    /// (see [`Purpose::is_reserved`]).
    pub fn new(scope: Scope, label: &str, version: u32) -> Result<Self, Error> {
        let value = Self {
            scope,
            label: label.into(),
            version,
        };
        value.validate()?;
        Ok(value)
    }
    /// An internal purpose, which may use a reserved namespace. Never reachable with a
    /// caller-chosen label.
    pub(crate) fn reserved(scope: Scope, label: &str, version: u32) -> Result<Self, Error> {
        let value = Self {
            scope,
            label: label.into(),
            version,
        };
        value.validate_shape()?;
        Ok(value)
    }
    /// Whether the label lies in a namespace only ckmg derives (`vault.`, `tor.`, `ckmg.`).
    pub fn is_reserved(&self) -> bool {
        RESERVED.iter().any(|prefix| self.label.starts_with(prefix))
    }
    /// A caller purpose: the label shape and no reserved namespace.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.validate_shape()?;
        if self.is_reserved() {
            return Err(Error::InvalidPurpose);
        }
        Ok(())
    }
    pub(crate) fn validate_shape(&self) -> Result<(), Error> {
        if self.label.is_empty()
            || self.label.len() > MAX_LABEL_BYTES
            || !self
                .label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b))
        {
            return Err(Error::InvalidPurpose);
        }
        Ok(())
    }
    /// Next owner-managed purpose generation, without wrapping on overflow.
    pub fn next_version(&self) -> Result<Self, Error> {
        if self.is_reserved() {
            return Self::reserved(
                self.scope,
                &self.label,
                self.version.checked_add(1).ok_or(Error::Limit)?,
            );
        }
        Self::new(
            self.scope,
            &self.label,
            self.version.checked_add(1).ok_or(Error::Limit)?,
        )
    }
    /// Parent scope.
    pub fn scope(&self) -> Scope {
        self.scope
    }
    /// Purpose label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Owner-managed generation.
    pub fn version(&self) -> u32 {
        self.version
    }
}

crate::lineage::redacted!(Purpose);
