#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test helpers: not every test uses every helper"
)]

use p2p_core::{Accept, Account, CookieSecret, Established, Initiator, Load, Local, Responder};
use secret::Secret;
use session::{
    issue_device_cert, sync_verifying_key, DeviceCert, DeviceSignKey, Revocation, SYNC_VK_LEN,
};

pub const NOW: u64 = 1_700_000_000_000;
pub const VAULT: [u8; 16] = [0x77; 16];
pub const ROOT: [u8; 32] = [0x07; 32];

pub struct Dev {
    pub cert: DeviceCert,
    pub sign: DeviceSignKey,
}

pub fn root_vk(root_seed: &[u8; 32]) -> [u8; SYNC_VK_LEN] {
    sync_verifying_key(root_seed).unwrap().try_into().unwrap()
}

pub fn device(root_seed: &[u8; 32], client: u8, id: u8, not_after: u64) -> Dev {
    let sign = DeviceSignKey::from_seed(&[id; 32]);
    let cert = issue_device_cert(
        root_seed,
        &[client; 64],
        &[id; 16],
        &sign.verifying_key().unwrap(),
        not_after,
        u64::from(id),
    )
    .unwrap();
    Dev { cert, sign }
}

pub fn account(root_seed: &[u8; 32], client: u8) -> Account {
    Account {
        client_id: [client; 64],
        root_vk: Box::new(root_vk(root_seed)),
    }
}

pub fn gate_key(secret: u8) -> Secret<[u8; 32]> {
    kdf::p2p_gate_key(&[secret; 32], &VAULT).unwrap()
}

/// One device with everything it trusts.
pub struct Node {
    pub dev: Dev,
    pub accounts: Vec<Account>,
    pub gate: Vec<Secret<[u8; 32]>>,
    pub revoked: Vec<Revocation>,
    pub vault: [u8; 16],
}

impl Node {
    pub fn local(&self) -> Local<'_> {
        Local {
            vault_id: self.vault,
            cert: &self.dev.cert,
            sign: &self.dev.sign,
            accounts: &self.accounts,
            revoked: &self.revoked,
            gate_keys: &self.gate,
        }
    }
}

/// A device of account 1 under the shared test root, gated by secret 1.
pub fn node(id: u8) -> Node {
    Node {
        dev: device(&ROOT, 1, id, u64::MAX),
        accounts: vec![account(&ROOT, 1)],
        gate: vec![gate_key(1)],
        revoked: Vec::new(),
        vault: VAULT,
    }
}

pub fn run(dialer: &Node, listener: &Node) -> anyhow::Result<(Established, Established)> {
    run_under(dialer, listener, Load::default())
}

/// A full handshake; under load the dialer solves the puzzle first.
pub fn run_under(
    dialer: &Node,
    listener: &Node,
    load: Load,
) -> anyhow::Result<(Established, Established)> {
    let cookies = CookieSecret::generate()?;
    let (initiator, hello) = Initiator::start(&dialer.gate[0], NOW)?;
    let mut input = hello;
    let (responder, reply) = loop {
        match Responder::accept(&listener.local(), &cookies, load, &input, NOW)? {
            Accept::Reply(responder, reply) => break (responder, reply),
            Accept::Challenge(challenge) => input = initiator.solve(&challenge)?,
        }
    };
    let (finish, outbound) = initiator.finish(&dialer.local(), &reply, NOW)?;
    let inbound = responder.finish(&listener.local(), &finish, NOW)?;
    Ok((outbound, inbound))
}

/// The responder's answer to a first message, for tests that probe it.
pub fn accept(listener: &Node, load: Load, input: &[u8], now_ms: u64) -> anyhow::Result<Accept> {
    let cookies = CookieSecret::generate()?;
    Responder::accept(&listener.local(), &cookies, load, input, now_ms)
}
