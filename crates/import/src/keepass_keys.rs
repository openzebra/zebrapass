//! `KeePass` entry string keys into draft fields.

use zeroize::Zeroizing;

use crate::item::{Draft, Slot};

/// Keys holding one-time-password settings rather than data.
const OTP_SETTINGS: [&str; 5] = [
    "TOTP Settings",
    "TimeOtp-Length",
    "TimeOtp-Period",
    "TimeOtp-Algorithm",
    "TOTP Seed",
];

/// Map one entry string. `get` looks up sibling strings of the entry.
pub fn apply_string<'a>(
    draft: &mut Draft,
    key: &str,
    value: &str,
    protected: bool,
    get: impl Fn(&str) -> Option<&'a str>,
) {
    match key {
        "Title" => draft.put(Slot::Title, value),
        "UserName" => draft.put(Slot::Username, value),
        "Password" => draft.put(Slot::Password, value),
        "URL" => draft.put(Slot::Url, value),
        "Notes" => draft.put(Slot::Notes, value),
        "otp" => draft.put(Slot::Totp, value),
        "TimeOtp-Secret-Base32" => {
            let uri = otpauth(
                value,
                get("TimeOtp-Length"),
                get("TimeOtp-Period"),
                get("TimeOtp-Algorithm"),
            );
            draft.put(Slot::Totp, &uri);
        }
        key if OTP_SETTINGS.contains(&key) => {
            if key == "TOTP Seed" && get("otp").is_none() {
                let (period, digits) = legacy_settings(get("TOTP Settings"));
                draft.put(Slot::Totp, &otpauth(value, digits, period, None));
            }
        }
        other if protected => draft.secret(other, value),
        other => draft.text(other, value),
    }
}

/// `KeePassXC`'s legacy `period;digits` settings.
fn legacy_settings(settings: Option<&str>) -> (Option<&str>, Option<&str>) {
    settings
        .and_then(|text| text.split_once(';'))
        .map_or((None, None), |(period, digits)| {
            (Some(period), Some(digits))
        })
}

/// An `otpauth://` URI carrying only the parameters that differ from the
/// defaults, so a plain secret stays readable by every reader.
fn otpauth(
    secret: &str,
    digits: Option<&str>,
    period: Option<&str>,
    algorithm: Option<&str>,
) -> Zeroizing<String> {
    let secret: String = secret.chars().filter(|ch| !ch.is_whitespace()).collect();
    let secret = Zeroizing::new(secret);
    let algorithm = algorithm.map(|name| name.trim_start_matches("HMAC-").replace('-', ""));
    let extra: Vec<String> = [
        (
            "digits",
            digits
                .map(str::trim)
                .filter(|d| *d != "6")
                .map(str::to_owned),
        ),
        (
            "period",
            period
                .map(str::trim)
                .filter(|p| *p != "30")
                .map(str::to_owned),
        ),
        ("algorithm", algorithm.filter(|a| a != "SHA1")),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value
            .filter(|v| !v.is_empty())
            .map(|v| format!("&{name}={v}"))
    })
    .collect();
    if extra.is_empty() {
        return secret;
    }
    Zeroizing::new(format!(
        "otpauth://totp/Imported?secret={}{}",
        secret.as_str(),
        extra.concat()
    ))
}

#[cfg(test)]
mod tests {
    use super::otpauth;

    #[test]
    fn default_parameters_keep_the_bare_secret() {
        assert_eq!(
            otpauth("JBSW Y3DP", Some("6"), Some("30"), None).as_str(),
            "JBSWY3DP"
        );
        assert_eq!(
            otpauth("JBSWY3DP", Some("8"), Some("30"), Some("HMAC-SHA-256")).as_str(),
            "otpauth://totp/Imported?secret=JBSWY3DP&digits=8&algorithm=SHA256"
        );
    }
}
