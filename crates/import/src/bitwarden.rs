//! Bitwarden `.json` export (the unencrypted kind).

use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::item::{Draft, Item, ItemKind, Slot};
use crate::limits::MAX_ITEMS;
use crate::report::{Report, SkipReason};
use crate::text::{text, Text};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<Named>,
    #[serde(default)]
    collections: Vec<Named>,
    #[serde(default)]
    items: Vec<Cipher>,
}

#[derive(Deserialize)]
struct Named {
    id: Option<String>,
    name: Option<Text>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cipher {
    #[serde(rename = "type")]
    kind: u8,
    name: Option<Text>,
    notes: Option<Text>,
    #[serde(default)]
    favorite: bool,
    folder_id: Option<String>,
    collection_ids: Option<Vec<String>>,
    deleted_date: Option<IgnoredAny>,
    login: Option<Login>,
    card: Option<Card>,
    identity: Option<Identity>,
    ssh_key: Option<SshKey>,
    fields: Option<Vec<CustomField>>,
    password_history: Option<Vec<IgnoredAny>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    username: Option<Text>,
    password: Option<Text>,
    totp: Option<Text>,
    uris: Option<Vec<Uri>>,
    fido2_credentials: Option<Vec<IgnoredAny>>,
}

#[derive(Deserialize)]
struct Uri {
    uri: Option<Text>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    cardholder_name: Option<Text>,
    brand: Option<Text>,
    number: Option<Text>,
    exp_month: Option<Text>,
    exp_year: Option<Text>,
    code: Option<Text>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    title: Option<Text>,
    first_name: Option<Text>,
    middle_name: Option<Text>,
    last_name: Option<Text>,
    address1: Option<Text>,
    address2: Option<Text>,
    address3: Option<Text>,
    city: Option<Text>,
    state: Option<Text>,
    postal_code: Option<Text>,
    country: Option<Text>,
    company: Option<Text>,
    email: Option<Text>,
    phone: Option<Text>,
    ssn: Option<Text>,
    username: Option<Text>,
    passport_number: Option<Text>,
    license_number: Option<Text>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshKey {
    private_key: Option<Text>,
    public_key: Option<Text>,
    key_fingerprint: Option<Text>,
}

#[derive(Deserialize)]
struct CustomField {
    name: Option<Text>,
    value: Option<Text>,
    #[serde(rename = "type")]
    kind: u8,
}

/// Read a Bitwarden export.
///
/// # Errors
///
/// `password-protected export` for encrypted exports; `not a Bitwarden
/// export` when the JSON does not parse; `too many items`.
pub fn read(bytes: &[u8], folders_as_tags: bool, report: &mut Report) -> anyhow::Result<Vec<Item>> {
    let export: Export =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("not a Bitwarden export"))?;
    if export.encrypted {
        anyhow::bail!(
            "this is a password-protected export: export again as .json without a password"
        );
    }
    if export.items.len() > MAX_ITEMS {
        anyhow::bail!("too many items");
    }
    let mut items = Vec::with_capacity(export.items.len());
    for (index, cipher) in export.items.iter().enumerate() {
        if cipher.deleted_date.is_some() {
            report.skip(
                index,
                SkipReason::Trashed,
                text(cipher.name.as_ref()).into(),
            );
            continue;
        }
        let mut draft = map(cipher, report);
        if folders_as_tags {
            tag_groups(&mut draft, &export, cipher);
        }
        report.admit(&mut items, index, draft)?;
    }
    Ok(items)
}

fn map(cipher: &Cipher, report: &mut Report) -> Draft {
    let mut draft = Draft::new(match cipher.kind {
        1 => ItemKind::Login,
        3 => ItemKind::Card,
        4 => ItemKind::Identity,
        5 => ItemKind::SshKey,
        _ => ItemKind::Note,
    });
    draft.put(Slot::Title, text(cipher.name.as_ref()));
    draft.put(Slot::Notes, text(cipher.notes.as_ref()));
    draft.favorite(cipher.favorite);
    if cipher
        .password_history
        .as_ref()
        .is_some_and(|h| !h.is_empty())
    {
        report.history = report.history.saturating_add(1);
    }
    if let Some(login) = cipher.login.as_ref() {
        login_fields(&mut draft, login, report);
    }
    if let Some(card) = cipher.card.as_ref() {
        card_fields(&mut draft, card);
    }
    if let Some(identity) = cipher.identity.as_ref() {
        identity_fields(&mut draft, identity);
    }
    if let Some(key) = cipher.ssh_key.as_ref() {
        draft.secret("private key", text(key.private_key.as_ref()));
        draft.text("public key", text(key.public_key.as_ref()));
        draft.text("fingerprint", text(key.key_fingerprint.as_ref()));
    }
    for field in cipher.fields.iter().flatten() {
        let name = text(field.name.as_ref());
        let value = text(field.value.as_ref());
        match field.kind {
            1 => draft.secret(name, value),
            3 => report.linked_fields = report.linked_fields.saturating_add(1),
            _ => draft.text(name, value),
        }
    }
    draft
}

fn login_fields(draft: &mut Draft, login: &Login, report: &mut Report) {
    draft.put(Slot::Username, text(login.username.as_ref()));
    draft.put(Slot::Password, text(login.password.as_ref()));
    draft.put(Slot::Totp, text(login.totp.as_ref()));
    for uri in login.uris.iter().flatten() {
        draft.put(Slot::Url, text(uri.uri.as_ref()));
    }
    let passkeys = login.fido2_credentials.as_ref().map_or(0, Vec::len);
    report.passkeys = report
        .passkeys
        .saturating_add(u32::try_from(passkeys).unwrap_or(u32::MAX));
}

fn card_fields(draft: &mut Draft, card: &Card) {
    draft.text("cardholder", text(card.cardholder_name.as_ref()));
    draft.text("brand", text(card.brand.as_ref()));
    draft.secret("number", text(card.number.as_ref()));
    let (month, year) = (text(card.exp_month.as_ref()), text(card.exp_year.as_ref()));
    if !month.is_empty() || !year.is_empty() {
        draft.text("expires", &format!("{month}/{year}"));
    }
    draft.secret("security code", text(card.code.as_ref()));
}

fn identity_fields(draft: &mut Draft, identity: &Identity) {
    let name = [
        &identity.title,
        &identity.first_name,
        &identity.middle_name,
        &identity.last_name,
    ]
    .iter()
    .map(|part| text(part.as_ref()))
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" ");
    draft.text("full name", &name);
    draft.put(Slot::Username, text(identity.username.as_ref()));
    draft.put(Slot::Email, text(identity.email.as_ref()));
    let plain = [
        ("phone", &identity.phone),
        ("company", &identity.company),
        ("address", &identity.address1),
        ("address 2", &identity.address2),
        ("address 3", &identity.address3),
        ("city", &identity.city),
        ("state", &identity.state),
        ("postal code", &identity.postal_code),
        ("country", &identity.country),
    ];
    for (label, value) in plain {
        draft.text(label, text(value.as_ref()));
    }
    let secret = [
        ("ssn", &identity.ssn),
        ("passport number", &identity.passport_number),
        ("license number", &identity.license_number),
    ];
    for (label, value) in secret {
        draft.secret(label, text(value.as_ref()));
    }
}

/// Folder and collection names become tags.
fn tag_groups(draft: &mut Draft, export: &Export, cipher: &Cipher) {
    if let Some(folder) = cipher
        .folder_id
        .as_deref()
        .and_then(|id| name_of(&export.folders, id))
    {
        draft.tag(folder);
    }
    for id in cipher.collection_ids.iter().flatten() {
        if let Some(collection) = name_of(&export.collections, id) {
            draft.tag(collection);
        }
    }
}

fn name_of<'a>(groups: &'a [Named], id: &str) -> Option<&'a str> {
    groups
        .iter()
        .find(|group| group.id.as_deref() == Some(id))
        .map(|group| text(group.name.as_ref()))
}
