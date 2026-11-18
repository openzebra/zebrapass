//! Self-hosted zero-knowledge PQ HTTPS/WSS + `SplitHTTP` sync & backup
//! server entrypoint (`zebrapass --server ...`).

use sync_https::{SyncServerConfig, start_server};

use crate::cli::ServerArgs;

/// Run the standalone sync server until the process exits.
///
/// # Errors
///
/// Certificate/key read errors, storage failures, invalid slug, or bind failure.
pub fn run_server(args: &ServerArgs) -> anyhow::Result<()> {
    let cert_pem = std::fs::read(&args.cert)?;
    let key_pem = std::fs::read(&args.key)?;
    let data_dir = match &args.data_dir {
        Some(dir) => dir.clone(),
        None => local::base_dir()?.join("server"),
    };
    let public_origin = args
        .public_origin
        .clone()
        .unwrap_or_else(|| format!("https://{}", args.listen).into_boxed_str());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let handle = start_server(SyncServerConfig {
            listen: args.listen,
            cert_pem,
            key_pem,
            data_dir,
            secret_slug: args.secret_path.clone(),
            public_origin,
        })
        .await?;
        eprintln!(
            "zebrapass-server listening on {} (origin {})",
            handle.local_addr, handle.origin
        );
        std::future::pending::<()>().await;
        Ok(())
    })
}
