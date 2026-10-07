#![allow(clippy::unwrap_used, reason = "tests may unwrap")]

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
