#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index"
)]

use local::SyncIdentity;
use memberlog::{Action, MemberLog, Role};
use secret::Secret;
use sharing::{
    account_fingerprint, vault_number, ContactCard, Invitation, Inviter, Offer, MAX_CARD_AGE_MS,
    MAX_INVITE_WIRE_LEN,
};

const NOW: u64 = 1_700_000_000_000;
const VAULT: [u8; 16] = [0x5A; 16];

struct Person {
    id: SyncIdentity,
}

fn person(n: u8) -> Person {
    let client_id = [n; 64];
    Person {
        id: SyncIdentity::enroll(&[n; 64], &client_id, [n; 16], u64::MAX).unwrap(),
    }
}

impl Person {
    fn card_at(&self, at: u64) -> ContactCard {
        let publics = self.id.share_publics().unwrap();
        ContactCard::issue(
            &self.id.sign_key(),
            &self.id.devices()[0],
            self.id.root_vk(),
            publics.ec_pub,
            &publics.kem_ek[..],
            at,
        )
        .unwrap()
    }

    fn card(&self) -> ContactCard {
        self.card_at(NOW)
    }

    fn new_vault(&self) -> MemberLog {
        MemberLog::genesis(
            VAULT,
            &self.id.sign_key(),
            &self.id.devices()[0],
            self.id.root_vk(),
            NOW,
        )
        .unwrap()
    }

    fn adds(&self, log: &mut MemberLog, other: &ContactCard, role: Role) {
        let action = Action::Add {
            client_id: other.cert.client_id,
            root_vk: other.root_vk.clone(),
            role,
        };
        let entry = log
            .propose(&self.id.sign_key(), &self.id.devices()[0], action, NOW)
            .unwrap();
        log.append(entry).unwrap();
    }

    fn invites(&self, log: &MemberLog, card: &ContactCard, seed: &Secret<[u8; 64]>) -> Invitation {
        self.issue_raw(
            log,
            card,
            seed,
            "Family",
            &[String::from("192.168.1.20:7447")],
        )
        .unwrap()
    }

    fn issue_raw(
        &self,
        log: &MemberLog,
        card: &ContactCard,
        seed: &Secret<[u8; 64]>,
        name: &str,
        hints: &[String],
    ) -> anyhow::Result<Invitation> {
        let key = self.id.sign_key();
        Invitation::issue(
            &Inviter {
                sign: &key,
                cert: &self.id.devices()[0],
            },
            log,
            card,
            &Offer { seed, name, hints },
            NOW,
        )
    }

    fn opens(&self, invitation: &Invitation) -> anyhow::Result<sharing::Opened> {
        invitation.open(
            &self.id.share_keys().ec_secret()?,
            self.id.share_keys().kem_seed(),
            &self.card_at(NOW + 1),
            NOW + 1,
        )
    }
}

const fn seed() -> Secret<[u8; 64]> {
    Secret::new([0xC7; 64])
}

#[test]
fn bob_shares_a_key_alice_adds_him_and_he_joins_with_the_vault_number() {
    let (alice, bob) = (person(1), person(2));

    let pasted = bob.card().to_text().unwrap();
    assert!(pasted.starts_with("zp-card1:"));
    let card = ContactCard::from_text(&pasted).unwrap();
    card.verify(NOW).unwrap();
    assert_eq!(
        card.fingerprint(),
        account_fingerprint(&[2; 64], bob.id.root_vk())
    );

    let mut log = alice.new_vault();
    alice.adds(&mut log, &card, Role::Writer);
    let invitation = alice.invites(&log, &card, &seed());

    let text = invitation.to_text().unwrap();
    assert!(text.starts_with("zp-invite1:"));
    let received = Invitation::from_text(&text).unwrap();
    assert_eq!(received, invitation);

    let opened = bob.opens(&received).unwrap();
    assert_eq!(opened.seed.expose(), seed().expose());
    assert_eq!(opened.name, "Family");
    assert_eq!(opened.number, vault_number(&VAULT));
    assert_eq!(opened.number, "5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A 5A5A");
    assert_eq!(opened.log.members().len(), 1);
    assert_eq!(opened.head, *log.head());
    assert_eq!(opened.inviter_id, [1; 64]);
    assert_eq!(
        opened.inviter,
        account_fingerprint(&[1; 64], alice.id.root_vk())
    );
}

#[test]
fn alice_can_add_as_many_people_as_she_likes() {
    let alice = person(1);
    let mut log = alice.new_vault();
    let guests: Vec<Person> = (2..6).map(person).collect();
    for guest in &guests {
        alice.adds(&mut log, &guest.card(), Role::Reader);
    }
    for guest in &guests {
        let invitation = alice.invites(&log, &guest.card(), &seed());
        let opened = guest.opens(&invitation).unwrap();
        assert_eq!(opened.seed.expose(), seed().expose());
        assert_eq!(opened.head, *log.head());
    }
}

#[test]
fn a_long_history_does_not_stop_an_invitation() {
    let (alice, bob) = (person(1), person(2));
    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Reader);
    for turn in 0..60 {
        let role = if turn % 2 == 0 {
            Role::Writer
        } else {
            Role::Reader
        };
        let entry = log
            .propose(
                &alice.id.sign_key(),
                &alice.id.devices()[0],
                Action::SetRole {
                    client_id: [2; 64],
                    role,
                },
                NOW,
            )
            .unwrap();
        log.append(entry).unwrap();
    }
    assert!(log.entries().len() > 60);
    let text = alice.invites(&log, &bob.card(), &seed()).to_text().unwrap();
    let opened = bob.opens(&Invitation::from_text(&text).unwrap()).unwrap();
    assert_eq!(opened.head, *log.head());
    assert!(
        text.len() < 32_000,
        "invitation text is {} characters",
        text.len()
    );
}

#[test]
fn a_swapped_head_or_inviter_key_does_not_verify() {
    let (alice, bob, carol) = (person(1), person(2), person(3));
    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Writer);
    let invitation = alice.invites(&log, &bob.card(), &seed());

    let mut head = invitation.clone();
    head.head[0] ^= 1;
    assert!(bob.opens(&head).is_err());

    let mut key = invitation;
    *key.inviter_vk = *carol.id.root_vk();
    assert!(bob.opens(&key).is_err());
}

#[test]
fn only_the_card_it_was_made_for_can_open_an_invitation() {
    let (alice, bob, carol) = (person(1), person(2), person(3));
    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Writer);
    alice.adds(&mut log, &carol.card(), Role::Writer);
    let for_bob = alice.invites(&log, &bob.card(), &seed());
    assert!(bob.opens(&for_bob).is_ok());
    assert!(carol.opens(&for_bob).is_err());
    let mut redirected = for_bob;
    redirected.card_id = carol.card().id();
    assert!(carol.opens(&redirected).is_err());
    assert!(bob.opens(&redirected).is_err());
}

#[test]
fn a_card_made_again_later_still_opens_the_same_invitation() {
    let (alice, bob) = (person(1), person(2));
    let first = bob.card_at(NOW - 5_000);
    let second = bob.card_at(NOW);
    assert_ne!(first.signature, second.signature);
    assert_eq!(first.id(), second.id());
    let mut log = alice.new_vault();
    alice.adds(&mut log, &first, Role::Writer);
    assert!(bob.opens(&alice.invites(&log, &first, &seed())).is_ok());
}

#[test]
fn issuing_refuses_people_who_are_not_in_the_log_and_signers_who_are_not_members() {
    let (alice, bob, mallory) = (person(1), person(2), person(9));
    let log = alice.new_vault();
    assert!(alice
        .issue_raw(&log, &bob.card(), &seed(), "x", &[])
        .is_err());

    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Writer);
    assert!(mallory
        .issue_raw(&log, &bob.card(), &seed(), "x", &[])
        .is_err());
    assert!(alice
        .issue_raw(&log, &bob.card(), &seed(), &"n".repeat(65), &[])
        .is_err());
}

#[test]
fn a_swapped_vault_opens_but_shows_a_different_inviter() {
    // The guard against a man in the middle is the fingerprint check, not the
    // cryptography: anyone holding Bob's card can wrap a seed to it.
    let (alice, bob, mallory) = (person(1), person(2), person(9));
    let mut fake = mallory.new_vault();
    mallory.adds(&mut fake, &bob.card(), Role::Writer);
    let forged = mallory.invites(&fake, &bob.card(), &seed());
    let opened = bob.opens(&forged).unwrap();
    assert_ne!(
        opened.inviter,
        account_fingerprint(&[1; 64], alice.id.root_vk())
    );
    assert_eq!(
        opened.inviter,
        account_fingerprint(&[9; 64], mallory.id.root_vk())
    );
}

#[test]
fn stale_future_forged_and_damaged_cards_are_refused() {
    let bob = person(2);
    assert!(bob.card_at(NOW - MAX_CARD_AGE_MS).verify(NOW).is_ok());
    assert!(bob.card_at(NOW - MAX_CARD_AGE_MS - 1).verify(NOW).is_err());
    assert!(bob.card_at(NOW + 24 * 3600 * 1000).verify(NOW).is_ok());
    assert!(bob.card_at(NOW + 24 * 3600 * 1000 + 1).verify(NOW).is_err());

    let card = bob.card();
    let bytes = card.encode().unwrap();
    for at in (0..bytes.len()).step_by(499) {
        let mut damaged = bytes.clone();
        damaged[at] ^= 1;
        if let Ok(parsed) = ContactCard::decode(&damaged) {
            assert!(parsed.verify(NOW).is_err(), "byte {at}");
        }
    }
    let mut swapped = card.clone();
    swapped.ec_pub[1] ^= 1;
    assert!(swapped.verify(NOW).is_err());
    let mut other_root = card;
    other_root.root_vk = person(7).card().root_vk;
    assert!(other_root.verify(NOW).is_err());
}

#[test]
fn damaged_or_truncated_invitations_never_open() {
    let (alice, bob) = (person(1), person(2));
    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Writer);
    let bytes = alice.invites(&log, &bob.card(), &seed()).encode().unwrap();
    assert!(bytes.len() <= MAX_INVITE_WIRE_LEN);
    for len in (0..bytes.len()).step_by(1999) {
        assert!(Invitation::decode(&bytes[..len]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Invitation::decode(&trailing).is_err());
    for at in (0..bytes.len()).step_by(1511) {
        let mut damaged = bytes.clone();
        damaged[at] ^= 1;
        let opened = Invitation::decode(&damaged).and_then(|parsed| bob.opens(&parsed));
        assert!(opened.is_err(), "byte {at}");
    }
}

#[test]
fn the_seed_is_never_visible_in_the_invitation() {
    let (alice, bob) = (person(1), person(2));
    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Writer);
    let bytes = alice.invites(&log, &bob.card(), &seed()).encode().unwrap();
    assert!(!bytes.windows(32).any(|window| window == [0xC7; 32]));
    assert!(!bytes.windows(6).any(|window| window == b"Family"));
}

#[test]
fn pasted_text_survives_line_wrapping() {
    let (alice, bob) = (person(1), person(2));
    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Writer);
    let text = alice.invites(&log, &bob.card(), &seed()).to_text().unwrap();
    let wrapped: String = text
        .as_bytes()
        .chunks(76)
        .map(|line| String::from_utf8(line.to_vec()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = Invitation::from_text(&wrapped).unwrap();
    assert!(bob.opens(&parsed).is_ok());
    assert!(Invitation::from_text(&text.replace("zp-invite1", "zp-card1")).is_err());
    assert!(ContactCard::from_text(&text).is_err());
}

#[test]
fn the_texts_people_copy_stay_a_pasteable_size() {
    let (alice, bob) = (person(1), person(2));
    let card = bob.card().to_text().unwrap();
    assert!(
        card.len() < 16_500,
        "card text is {} characters",
        card.len()
    );
    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Writer);
    let invite = alice.invites(&log, &bob.card(), &seed()).to_text().unwrap();
    assert!(
        invite.len() < 32_000,
        "invitation text is {} characters",
        invite.len()
    );
}

#[test]
fn the_inviters_address_hints_arrive_signed_and_bounded() {
    let (alice, bob) = (person(1), person(2));
    let mut log = alice.new_vault();
    alice.adds(&mut log, &bob.card(), Role::Writer);
    let invitation = alice.invites(&log, &bob.card(), &seed());
    let opened = bob.opens(&invitation).unwrap();
    assert_eq!(opened.hints, vec![String::from("192.168.1.20:7447")]);

    let mut swapped = invitation;
    swapped.hints = vec![String::from("203.0.113.9:7447")];
    assert!(
        bob.opens(&swapped).is_err(),
        "hints are covered by the signature"
    );

    let issue = |hints: &[String]| alice.issue_raw(&log, &bob.card(), &seed(), "Family", hints);
    assert!(issue(&vec![String::from("a:1"); 4]).is_ok());
    assert!(issue(&vec![String::from("a:1"); 5]).is_err());
    assert!(issue(&["x".repeat(65)]).is_err());
    assert!(issue(&[String::new()]).is_err());
    assert!(issue(&[String::from("naïve:1")]).is_err());
}
