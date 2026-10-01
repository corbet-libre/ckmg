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
    fn try_from(value: PurposeWire) -> Result<Self, Error> {
        Self::new(value.scope, &value.label, value.version)
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

impl Purpose {
    /// Validate an ASCII letters/digits/`._-:` label.
    pub fn new(scope: Scope, label: &str, version: u32) -> Result<Self, Error> {
        let value = Self {
            scope,
            label: label.into(),
            version,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
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
