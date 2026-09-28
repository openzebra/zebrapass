//! CSV header recognition: which column holds what, and whose export it is.

use crate::item::Slot;

/// What a CSV column feeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A standard field.
    Field(Slot),
    /// A folder or group name (becomes a tag).
    Folder,
    /// Comma-separated tags.
    Tags,
    /// `1` / `true` / `yes` marks a favorite.
    Favorite,
    /// Bitwarden's `name: value` lines.
    BitwardenFields,
    /// Dropped.
    Ignore,
    /// A custom text field named after the header.
    Custom,
    /// A custom secret field named after the header.
    CustomSecret,
}

/// Whose export the header looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    /// Google Chrome / Chromium browsers.
    Chrome,
    /// Mozilla Firefox.
    Firefox,
    /// Apple Safari / Passwords.
    Safari,
    /// `LastPass`.
    LastPass,
    /// 1Password.
    OnePassword,
    /// Bitwarden CSV.
    Bitwarden,
    /// Proton Pass.
    Proton,
    /// Dashlane.
    Dashlane,
    /// Anything else, mapped by header names.
    Generic,
}

impl Preset {
    /// Display name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Firefox => "Firefox",
            Self::Safari => "Safari",
            Self::LastPass => "LastPass",
            Self::OnePassword => "1Password",
            Self::Bitwarden => "Bitwarden CSV",
            Self::Proton => "Proton Pass",
            Self::Dashlane => "Dashlane",
            Self::Generic => "CSV",
        }
    }
}

/// Header aliases, lower case. The first match wins.
const ALIASES: &[(&str, Target)] = &[
    ("title", Target::Field(Slot::Title)),
    ("name", Target::Field(Slot::Title)),
    ("url", Target::Field(Slot::Url)),
    ("login_uri", Target::Field(Slot::Url)),
    ("website", Target::Field(Slot::Url)),
    ("web site", Target::Field(Slot::Url)),
    ("origin", Target::Field(Slot::Url)),
    ("username", Target::Field(Slot::Username)),
    ("username2", Target::Field(Slot::Username)),
    ("username3", Target::Field(Slot::Username)),
    ("login_username", Target::Field(Slot::Username)),
    ("login", Target::Field(Slot::Username)),
    ("user", Target::Field(Slot::Username)),
    ("email", Target::Field(Slot::Email)),
    ("e-mail", Target::Field(Slot::Email)),
    ("password", Target::Field(Slot::Password)),
    ("login_password", Target::Field(Slot::Password)),
    ("notes", Target::Field(Slot::Notes)),
    ("note", Target::Field(Slot::Notes)),
    ("extra", Target::Field(Slot::Notes)),
    ("comments", Target::Field(Slot::Notes)),
    ("totp", Target::Field(Slot::Totp)),
    ("otpauth", Target::Field(Slot::Totp)),
    ("otp", Target::Field(Slot::Totp)),
    ("login_totp", Target::Field(Slot::Totp)),
    ("otpsecret", Target::Field(Slot::Totp)),
    ("one-time password", Target::Field(Slot::Totp)),
    ("folder", Target::Folder),
    ("grouping", Target::Folder),
    ("group", Target::Folder),
    ("vault", Target::Folder),
    ("category", Target::Folder),
    ("tags", Target::Tags),
    ("fav", Target::Favorite),
    ("favorite", Target::Favorite),
    ("fields", Target::BitwardenFields),
    ("type", Target::Ignore),
    ("reprompt", Target::Ignore),
    ("archived", Target::Ignore),
    ("guid", Target::Ignore),
    ("httprealm", Target::Ignore),
    ("formactionorigin", Target::Ignore),
    ("usernamefield", Target::Ignore),
    ("passwordfield", Target::Ignore),
    ("timecreated", Target::Ignore),
    ("timelastused", Target::Ignore),
    ("timepasswordchanged", Target::Ignore),
    ("createtime", Target::Ignore),
    ("modifytime", Target::Ignore),
];

/// Headers whose value is secret even when this table does not know them.
const SECRET_HINTS: [&str; 6] = ["password", "secret", "pin", "cvv", "cvc", "private"];

/// Column targets and the export they look like.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Detected preset.
    pub preset: Preset,
    /// One target per column.
    pub targets: Box<[Target]>,
}

impl Mapping {
    /// Map `headers` by name.
    #[must_use]
    pub fn detect(headers: &[&str]) -> Self {
        let lower: Vec<String> = headers
            .iter()
            .map(|header| header.trim().to_ascii_lowercase())
            .collect();
        let has = |name: &str| lower.iter().any(|header| header == name);
        let preset = if has("login_uri") {
            Preset::Bitwarden
        } else if has("httprealm") {
            Preset::Firefox
        } else if has("grouping") && has("extra") {
            Preset::LastPass
        } else if has("vault") && has("createtime") {
            Preset::Proton
        } else if has("otpsecret") {
            Preset::Dashlane
        } else if has("archived") && has("otpauth") {
            Preset::OnePassword
        } else if has("otpauth") && has("title") {
            Preset::Safari
        } else if has("name") && has("url") && has("password") && lower.len() <= 5 {
            Preset::Chrome
        } else {
            Preset::Generic
        };
        let targets = lower.iter().map(|header| target(header)).collect();
        Self { preset, targets }
    }

    /// Whether some column feeds a standard field.
    #[must_use]
    pub fn useful(&self) -> bool {
        self.targets
            .iter()
            .any(|target| matches!(target, Target::Field(_)))
    }
}

fn target(header: &str) -> Target {
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == header)
        .map_or_else(
            || {
                if SECRET_HINTS.iter().any(|hint| header.contains(hint)) {
                    Target::CustomSecret
                } else {
                    Target::Custom
                }
            },
            |(_, target)| *target,
        )
}

#[cfg(test)]
mod tests {
    use super::{Mapping, Preset, Target};
    use crate::item::Slot;

    #[test]
    fn presets_are_detected() {
        let cases: [(&[&str], Preset); 8] = [
            (
                &["name", "url", "username", "password", "note"],
                Preset::Chrome,
            ),
            (
                &[
                    "url",
                    "username",
                    "password",
                    "httpRealm",
                    "formActionOrigin",
                    "guid",
                    "timeCreated",
                    "timeLastUsed",
                    "timePasswordChanged",
                ],
                Preset::Firefox,
            ),
            (
                &["Title", "URL", "Username", "Password", "Notes", "OTPAuth"],
                Preset::Safari,
            ),
            (
                &[
                    "url", "username", "password", "totp", "extra", "name", "grouping", "fav",
                ],
                Preset::LastPass,
            ),
            (
                &[
                    "Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Archived",
                    "Tags", "Notes",
                ],
                Preset::OnePassword,
            ),
            (
                &[
                    "folder",
                    "favorite",
                    "type",
                    "name",
                    "notes",
                    "fields",
                    "reprompt",
                    "login_uri",
                    "login_username",
                    "login_password",
                    "login_totp",
                ],
                Preset::Bitwarden,
            ),
            (
                &[
                    "type",
                    "name",
                    "url",
                    "email",
                    "username",
                    "password",
                    "note",
                    "totp",
                    "createTime",
                    "modifyTime",
                    "vault",
                ],
                Preset::Proton,
            ),
            (
                &[
                    "username",
                    "username2",
                    "username3",
                    "title",
                    "password",
                    "note",
                    "url",
                    "category",
                    "otpSecret",
                ],
                Preset::Dashlane,
            ),
        ];
        for (headers, preset) in cases {
            assert_eq!(Mapping::detect(headers).preset, preset, "{headers:?}");
        }
    }

    #[test]
    fn unknown_columns_become_custom_and_secret_ones_stay_secret() {
        let mapping = Mapping::detect(&["Account", "Password", "Recovery PIN", "Owner"]);
        assert_eq!(mapping.preset, Preset::Generic);
        assert_eq!(
            &*mapping.targets,
            [
                Target::Custom,
                Target::Field(Slot::Password),
                Target::CustomSecret,
                Target::Custom
            ]
        );
        assert!(mapping.useful());
        assert!(!Mapping::detect(&["a", "b"]).useful());
    }
}
