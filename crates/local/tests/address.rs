#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    reason = "tests may unwrap and index"
)]

use local::parse_advertise;

#[test]
fn the_advertised_address_is_a_reachable_socket_address() {
    assert_eq!(
        parse_advertise(" 93.184.216.34:7447 ").unwrap().as_ref(),
        "93.184.216.34:7447"
    );
    assert_eq!(
        parse_advertise("[2606:2800:220:1::1]:8000")
            .unwrap()
            .as_ref(),
        "[2606:2800:220:1::1]:8000"
    );
    assert!(
        parse_advertise("192.168.1.5:7447").is_ok(),
        "a VPN or LAN address is allowed"
    );
    for refused in [
        "",
        "example.com:7447",
        "203.0.113.5",
        "203.0.113.5:0",
        "203.0.113.5:70000",
        "0.0.0.0:7447",
        "127.0.0.1:7447",
        "[::1]:7447",
        "169.254.169.254:80",
        "[fe80::1]:7447",
        "224.0.0.1:7447",
        "255.255.255.255:7447",
        "[::ffff:127.0.0.1]:7447",
        "203.0.113.5:7447",
        "[2001:db8::1]:8000",
    ] {
        assert!(parse_advertise(refused).is_err(), "{refused}");
    }
}

#[test]
fn a_dialed_address_follows_the_advertise_rules_except_for_loopback_on_request() {
    for same in [
        "93.184.216.34:7447",
        " 192.168.1.5:7447 ",
        "[2606:2800:220:1::1]:8000",
        "",
        "example.com:7447",
        "203.0.113.5:0",
        "0.0.0.0:7447",
        "169.254.169.254:80",
        "[fe80::1]:7447",
        "224.0.0.1:7447",
        "255.255.255.255:7447",
        "203.0.113.5:7447",
        "[2001:db8::1]:8000",
        "127.0.0.1:7447",
        "[::1]:7447",
    ] {
        assert_eq!(
            local::parse_peer_address(same, false),
            parse_advertise(same),
            "{same}"
        );
    }
    assert_eq!(
        local::parse_peer_address("127.0.0.1:7447", true)
            .unwrap()
            .as_ref(),
        "127.0.0.1:7447"
    );
    assert!(local::parse_peer_address("[::ffff:127.0.0.1]:7447", true).is_ok());
    for refused in [
        "127.0.0.1:0",
        "0.0.0.0:7447",
        "169.254.169.254:80",
        "[fe80::1]:7447",
        "224.0.0.1:7447",
        "203.0.113.5:7447",
    ] {
        assert!(
            local::parse_peer_address(refused, true).is_err(),
            "{refused} stays refused even with loopback allowed"
        );
    }
}

mod personal_peers {
    use local::{
        add_manual_peer, load_personal_entries, load_personal_peers, remember_personal_peer,
        remove_personal_peer, save_personal_peers, PERSONAL_PEERS_MAX,
    };
    use secret::Secret;

    fn dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zp-pp-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key(byte: u8) -> Secret<[u8; 32]> {
        Secret::new([byte; 32])
    }

    #[test]
    fn the_sealed_list_round_trips_newest_first_and_stays_bounded() {
        let path = dir("round").join("peers.store");
        let k = key(1);
        for n in 0..=PERSONAL_PEERS_MAX + 3 {
            remember_personal_peer(&path, &k, &format!("93.184.216.{n}:7447")).unwrap();
        }
        let found = load_personal_peers(&path, &k, false).unwrap();
        assert_eq!(found.len(), PERSONAL_PEERS_MAX);
        assert_eq!(
            found[0].as_ref(),
            format!("93.184.216.{}:7447", PERSONAL_PEERS_MAX + 3)
        );
        remember_personal_peer(&path, &k, "93.184.216.5:7447").unwrap();
        let again = load_personal_peers(&path, &k, false).unwrap();
        assert_eq!(again[0].as_ref(), "93.184.216.5:7447");
        assert_eq!(
            again
                .iter()
                .filter(|a| a.as_ref() == "93.184.216.5:7447")
                .count(),
            1
        );
        assert_eq!(again.len(), PERSONAL_PEERS_MAX);
    }

    #[test]
    fn corruption_the_wrong_key_and_a_missing_file_are_errors_not_panics() {
        let path = dir("bad").join("peers.store");
        let k = key(2);
        assert!(load_personal_peers(&path, &k, false).is_err());
        save_personal_peers(&path, &k, &[Box::from("93.184.216.34:7447")]).unwrap();
        assert!(load_personal_peers(&path, &key(3), false).is_err());
        let mut bytes = std::fs::read(&path).unwrap();
        for at in [0, bytes.len() / 2, bytes.len() - 1] {
            bytes[at] ^= 1;
            std::fs::write(&path, &bytes).unwrap();
            assert!(load_personal_peers(&path, &k, false).is_err(), "byte {at}");
            bytes[at] ^= 1;
        }
        std::fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();
        assert!(load_personal_peers(&path, &k, false).is_err());
        std::fs::write(&path, b"").unwrap();
        assert!(load_personal_peers(&path, &k, false).is_err());
        // A damaged file is replaced the next time an address is remembered.
        remember_personal_peer(&path, &k, "93.184.216.35:7447").unwrap();
        assert_eq!(load_personal_peers(&path, &k, false).unwrap().len(), 1);
    }

    #[test]
    fn a_stored_address_that_may_no_longer_be_dialed_drops_out_alone() {
        let path = dir("policy").join("peers.store");
        let k = key(4);
        save_personal_peers(
            &path,
            &k,
            &[
                Box::from("127.0.0.1:7447"),
                Box::from("93.184.216.34:7447"),
                Box::from("169.254.169.254:80"),
                Box::from("not an address"),
            ],
        )
        .unwrap();
        let strict = load_personal_peers(&path, &k, false).unwrap();
        assert_eq!(strict, vec![Box::<str>::from("93.184.216.34:7447")]);
        let local = load_personal_peers(&path, &k, true).unwrap();
        assert_eq!(local.len(), 2);
        assert!(save_personal_peers(&path, &k, &[Box::from("x".repeat(65))]).is_err());
    }

    fn format_one(addresses: &[&str]) -> Vec<u8> {
        let mut plain = u16::try_from(addresses.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        for address in addresses {
            plain.push(u8::try_from(address.len()).unwrap());
            plain.extend_from_slice(address.as_bytes());
        }
        let meta = frame::FrameMeta {
            kind: frame::KIND_REVISION,
            record_id: 0,
            revision: 1,
            origin_device: [1u8; 16],
            timestamp_ms: 0,
            alg: frame::ALG_CASCADE,
        };
        frame::seal(&key(7), &meta, &plain).unwrap()
    }

    #[test]
    fn a_format_one_file_loads_as_learned_entries_and_upgrades_on_write() {
        let path = dir("golden1").join("peers.store");
        let k = key(7);
        std::fs::write(
            &path,
            format_one(&["93.184.216.34:7447", "93.184.216.35:7447"]),
        )
        .unwrap();
        let entries = load_personal_entries(&path, &k, false).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| !entry.manual));
        add_manual_peer(&path, &k, "93.184.216.36:7447", false).unwrap();
        let entries = load_personal_entries(&path, &k, false).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].manual && &*entries[0].address == "93.184.216.36:7447");
        assert!(entries[1..].iter().all(|entry| !entry.manual));
    }

    #[test]
    fn manual_entries_round_trip_and_are_never_evicted_by_learned_ones() {
        let path = dir("manual").join("peers.store");
        let k = key(8);
        add_manual_peer(&path, &k, "93.184.216.1:7447", false).unwrap();
        for n in 10..10 + PERSONAL_PEERS_MAX + 3 {
            remember_personal_peer(&path, &k, &format!("93.184.216.{n}:7447")).unwrap();
        }
        let entries = load_personal_entries(&path, &k, false).unwrap();
        assert_eq!(entries.len(), PERSONAL_PEERS_MAX);
        assert!(entries[0].manual && &*entries[0].address == "93.184.216.1:7447");
        save_personal_peers(&path, &k, &[Box::from("93.184.216.99:7447")]).unwrap();
        let entries = load_personal_entries(&path, &k, false).unwrap();
        assert!(entries.iter().any(|entry| entry.manual));
        remember_personal_peer(&path, &k, "93.184.216.1:7447").unwrap();
        let entries = load_personal_entries(&path, &k, false).unwrap();
        assert!(entries
            .iter()
            .any(|e| e.manual && &*e.address == "93.184.216.1:7447"));
        remove_personal_peer(&path, &k, "93.184.216.1:7447").unwrap();
        let entries = load_personal_entries(&path, &k, false).unwrap();
        assert!(entries.iter().all(|entry| !entry.manual));
    }

    #[test]
    fn a_manual_address_is_refused_with_a_reason() {
        let path = dir("refuse").join("peers.store");
        let k = key(9);
        let why = |input: &str, loopback: bool| {
            add_manual_peer(&path, &k, input, loopback)
                .unwrap_err()
                .to_string()
        };
        assert!(why("not an address", false).contains("ip:port"));
        assert!(why("127.0.0.1:7447", false).contains("cannot reach"));
        assert!(why("169.254.169.254:80", true).contains("cannot reach"));
        add_manual_peer(&path, &k, "127.0.0.1:7447", true).unwrap();
        assert_eq!(why("127.0.0.1:7447", true), "Already added.");
        for n in 1..PERSONAL_PEERS_MAX {
            add_manual_peer(&path, &k, &format!("93.184.216.{n}:7447"), false).unwrap();
        }
        assert_eq!(why("93.184.216.200:7447", false), "Up to 8 addresses.");
    }
}

#[test]
fn an_observed_address_is_offered_only_when_it_could_be_advertised() {
    use local::{offer_observed, Offer};
    let seen = |text: &str| text.parse().unwrap();
    let public = |text: &str| Offer::Public(text.into());
    assert_eq!(
        offer_observed(seen("93.184.216.34:51234"), 7447),
        public("93.184.216.34:7447"),
        "the port is ours, not the one the peer saw"
    );
    assert_eq!(
        offer_observed(seen("[2606:2800:220:1::1]:40000"), 7447),
        public("[2606:2800:220:1::1]:7447")
    );
    assert_eq!(
        offer_observed(seen("[::ffff:93.184.216.34]:40000"), 7447),
        public("93.184.216.34:7447"),
        "a mapped address is judged as the IPv4 one"
    );
    assert_eq!(
        offer_observed(seen("192.168.1.9:40000"), 7447),
        public("192.168.1.9:7447"),
        "a LAN address passes the advertise rules"
    );
    for local in ["127.0.0.1:40000", "[::1]:40000", "[::ffff:127.0.0.1]:40000"] {
        assert!(
            matches!(offer_observed(seen(local), 7447), Offer::Local(_)),
            "{local}"
        );
    }
    for never in [
        "0.0.0.0:1",
        "169.254.169.254:1",
        "224.0.0.1:1",
        "255.255.255.255:1",
        "203.0.113.5:1",
        "198.18.0.1:1",
        "240.0.0.1:1",
        "[fe80::1]:1",
        "[ff02::1]:1",
        "[2001:db8::1]:1",
        "[::]:1",
    ] {
        assert_eq!(
            offer_observed(seen(never), 7447),
            Offer::Unusable,
            "{never}"
        );
    }
    assert_eq!(
        offer_observed(seen("93.184.216.34:51234"), 0),
        Offer::Unusable,
        "no listening port to pair it with"
    );
    assert_eq!(offer_observed(seen("127.0.0.1:5"), 0), Offer::Unusable);
}

#[test]
fn a_pasted_relay_slot_is_the_exact_form_of_a_reachable_relay() {
    use local::parse_relay_hint;
    let slot = "ab".repeat(16);
    let ok = |text: &str| parse_relay_hint(text).unwrap().to_string();
    assert_eq!(
        ok(&format!("93.184.216.34:7447/{slot}")),
        format!("93.184.216.34:7447/{slot}")
    );
    assert_eq!(
        ok(&format!("  [2606:2800:220:1::1]:7447/{slot} \n")),
        format!("[2606:2800:220:1::1]:7447/{slot}"),
        "surrounding space goes"
    );
    assert!(
        parse_relay_hint(&format!("127.0.0.1:7447/{slot}")).is_ok(),
        "loopback is the person's choice"
    );
    assert!(parse_relay_hint(&format!("192.168.1.5:7447/{slot}")).is_ok());
    for bad in [
        String::new(),
        "93.184.216.34:7447".to_owned(),
        format!("93.184.216.34/{slot}"),
        format!("93.184.216.34:0/{slot}"),
        format!("93.184.216.34:7447/{}", slot.to_uppercase()),
        format!("93.184.216.34:7447/{}", &slot[..30]),
        format!("93.184.216.34:7447/{slot}00"),
        format!("example.com:7447/{slot}"),
        format!("169.254.169.254:80/{slot}"),
        format!("0.0.0.0:7447/{slot}"),
        format!("224.0.0.1:7447/{slot}"),
        format!("[fe80::1]:7447/{slot}"),
        format!("203.0.113.9:7447/{slot}"),
        format!("93.184.216.34:7447/{slot}/{slot}"),
    ] {
        assert!(parse_relay_hint(&bad).is_err(), "{bad:?}");
    }
}
