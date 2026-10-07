//! Fuzz target: whatever bytes arrive as a handshake message, the responder
//! and the initiator return an error or an answer, never panic. The first
//! byte picks which message is attacked: the first message, the finish, the
//! reply, or the routing and replay-id helpers.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use p2p_core::{Accept, Account, CookieSecret, Initiator, Load, Local, Responder};
use secret::Secret;
use session::{issue_device_cert, sync_verifying_key, DeviceCert, DeviceSignKey};

const NOW: u64 = 1_700_000_000_000;
const VAULT: [u8; 16] = [0x77; 16];
const ROOT: [u8; 32] = [0x07; 32];

struct Node {
    cert: DeviceCert,
    sign: DeviceSignKey,
    accounts: Vec<Account>,
    gate: Vec<Secret<[u8; 32]>>,
}

impl Node {
    fn new(id: u8) -> Self {
        let sign = DeviceSignKey::from_seed(&[id; 32]);
        let cert = issue_device_cert(
            &ROOT,
            &[1; 64],
            &[id; 16],
            &sign.verifying_key().unwrap(),
            u64::MAX,
            u64::from(id),
        )
        .unwrap();
        let root_vk = sync_verifying_key(&ROOT).unwrap().try_into().unwrap();
        Self {
            cert,
            sign,
            accounts: vec![Account {
                client_id: [1; 64],
                root_vk: Box::new(root_vk),
            }],
            gate: vec![kdf::p2p_gate_key(&[1; 32], &VAULT).unwrap()],
        }
    }

    fn local(&self) -> Local<'_> {
        Local {
            vault_id: VAULT,
            cert: &self.cert,
            sign: &self.sign,
            accounts: &self.accounts,
            revoked: &[],
            gate_keys: &self.gate,
        }
    }
}

struct Fixture {
    dialer: Node,
    listener: Node,
    cookies: CookieSecret,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| Fixture {
        dialer: Node::new(0xA1),
        listener: Node::new(0xB2),
        cookies: CookieSecret::generate().unwrap(),
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, message)) = data.split_first() else {
        return;
    };
    let fixture = fixture();
    let listener = fixture.listener.local();
    match mode % 4 {
        0 => {
            for load in [Load::default(), Load { difficulty: 8 }] {
                let _ = Responder::accept(&listener, &fixture.cookies, load, message, NOW);
            }
        }
        1 => {
            let (_, hello) = Initiator::start(&fixture.dialer.gate[0], NOW).unwrap();
            if let Ok(Accept::Reply(responder, _)) =
                Responder::accept(&listener, &fixture.cookies, Load::default(), &hello, NOW)
            {
                let _ = responder.finish(&listener, message, NOW);
            }
        }
        2 => {
            let (initiator, _) = Initiator::start(&fixture.dialer.gate[0], NOW).unwrap();
            let _ = initiator.finish(&fixture.dialer.local(), message, NOW);
        }
        _ => {
            let _ = Responder::route(&[listener], message, NOW);
            let _ = Responder::first_message_id(message);
            let (initiator, _) = Initiator::start(&fixture.dialer.gate[0], NOW).unwrap();
            let _ = initiator.solve(message);
        }
    }
});
