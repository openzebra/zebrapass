//! A deserialized string that wipes itself on drop.

use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

/// A JSON string moved straight into a zeroizing buffer.
#[derive(Default)]
pub struct Text(Zeroizing<String>);

impl Text {
    /// The string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
    }
}

/// The string of an optional [`Text`], empty when absent.
#[must_use]
pub fn text(value: Option<&Text>) -> &str {
    value.map_or("", Text::as_str)
}
