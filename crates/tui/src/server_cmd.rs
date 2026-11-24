//! Self-hosted zero-knowledge PQ TLS 1.3 sync, live P2P relay, and mutually
//! authenticated mesh server entrypoint (`zebrapass --server ...`).

use std::path::Path;
use std::time::Duration;

use anyhow::anyhow;
use secret::Secret;
use session::{SYNC_VK_LEN, sync_verifying_key};
use zeroize::Zeroizing;
use zsync::{
    MeshAuthConfig, MeshPeer, ZebraServerConfig, format_mesh_vk_hex, parse_mesh_vk_hex,
    start_server,
};

use crate::cli::ServerArgs;

/// Run the standalone `zsync` server until the process exits.
///
/// # Errors
///
/// Certificate/key/CA/mesh-key read errors, storage failures, or bind failure.
pub fn run_server(args: &ServerArgs) -> anyhow::Result<()> {
    let cert_pem = std::fs::read(&args.cert)?;
    let key_pem = Secret::new(std::fs::read(&args.key)?);
    let extra_ca_pem = args.extra_ca.as_deref().map(std::fs::read).transpose()?;
    let data_dir = match &args.data_dir {
        Some(dir) => dir.clone(),
        None => local::base_dir()?.join("server"),
    };
    let mut peers = Vec::with_capacity(args.peers.len());
    for raw in &args.peers {
        peers.push(MeshPeer::parse(raw, args.allow_private)?);
    }
    let mesh = match args.mesh_key.as_deref() {
        Some(path) => {
            let seed = load_or_create_mesh_key(path)?;
            let own_vk: [u8; SYNC_VK_LEN] = sync_verifying_key(seed.expose())?
                .try_into()
                .map_err(|_| anyhow!("unexpected mesh verifying key length"))?;
            let mut allowed_vks = Vec::with_capacity(args.mesh_allow.len());
            for hex in &args.mesh_allow {
                let vk = *parse_mesh_vk_hex(hex)?;
                if !allowed_vks.contains(&vk) {
                    allowed_vks.push(vk);
                }
            }
            eprintln!("zebrapass-server mesh-vk {}", format_mesh_vk_hex(&own_vk));
            Some(MeshAuthConfig {
                seed,
                peers,
                allowed_vks,
            })
        }
        None => None,
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let handle = start_server(ZebraServerConfig {
            listen: args.listen,
            cert_pem,
            key_pem,
            extra_ca_pem,
            data_dir,
            mesh,
            mesh_interval: Duration::from_secs(3),
            allow_private: args.allow_private,
        })
        .await?;
        eprintln!("zebrapass-server listening on {}", handle.local_addr);
        std::future::pending::<()>().await;
        Ok(())
    })
}

fn load_or_create_mesh_key(path: &Path) -> anyhow::Result<Secret<[u8; 32]>> {
    if path.exists() {
        let raw = Zeroizing::new(std::fs::read(path)?);
        let bytes: &[u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("mesh key file must be exactly 32 bytes"))?;
        let mut seed = Secret::new([0u8; 32]);
        seed.expose_mut().copy_from_slice(bytes);
        return Ok(seed);
    }
    let mut seed = Secret::new([0u8; 32]);
    getrandom::fill(seed.expose_mut()).map_err(|_| anyhow!("os entropy failed"))?;
    local::write_atomic(path, seed.expose())?;
    Ok(seed)
}
