//! Self-hosted zero-knowledge PQ TLS 1.3 sync, live P2P relay, and parallel
//! mesh server entrypoint (`zebrapass --server ...`).

use std::time::Duration;

use zsync::{ZebraServerConfig, start_server};

use crate::cli::ServerArgs;

/// Run the standalone `zsync` server until the process exits.
///
/// # Errors
///
/// Certificate/key/CA read errors, storage failures, or bind failure.
pub fn run_server(args: &ServerArgs) -> anyhow::Result<()> {
    let cert_pem = std::fs::read(&args.cert)?;
    let key_pem = std::fs::read(&args.key)?;
    let extra_ca_pem = args.extra_ca.as_deref().map(std::fs::read).transpose()?;
    let data_dir = match &args.data_dir {
        Some(dir) => dir.clone(),
        None => local::base_dir()?.join("server"),
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
            peers: args.peers.clone(),
            mesh_interval: Duration::from_secs(3),
            allow_loopback: true,
        })
        .await?;
        eprintln!("zebrapass-server listening on {}", handle.local_addr);
        std::future::pending::<()>().await;
        Ok(())
    })
}
