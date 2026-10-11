//! Focus order of the restore screen.

/// Focus on the phrase step, in Tab order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreField {
    /// The words.
    Phrase,
    /// Optional vault file path.
    Source,
    /// Optional address of another device.
    Address,
    /// Display name.
    Name,
    /// Optional 25th word.
    Passphrase,
}

impl RestoreField {
    const ORDER: [Self; 5] = [
        Self::Phrase,
        Self::Source,
        Self::Address,
        Self::Name,
        Self::Passphrase,
    ];

    pub(super) fn shift(self, forward: bool) -> Self {
        let at = Self::ORDER
            .iter()
            .position(|field| *field == self)
            .unwrap_or(0);
        let next = if forward {
            at + 1
        } else {
            at + Self::ORDER.len() - 1
        };
        Self::ORDER
            .get(next % Self::ORDER.len())
            .copied()
            .unwrap_or(Self::Phrase)
    }
}
