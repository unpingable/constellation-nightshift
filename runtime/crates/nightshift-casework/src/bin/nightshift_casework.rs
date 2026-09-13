use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use nightshift_casework::{
    load_runs_at,
    server::{bind_loopback, serve, Api},
    static_ui::StaticUi,
};

#[derive(Debug, Parser)]
#[command(
    name = "nightshift-casework",
    about = "Serve exact Nightshift packet and receipt snapshots as read-only casework"
)]
struct Args {
    /// Explicit run directory containing packet.v1.json and run-receipts.v1.json.
    #[arg(long = "run-dir")]
    run_dirs: Vec<PathBuf>,
    /// Explicit directory containing exact Monitor, NQ, lineage, profile, and evaluation files.
    #[arg(long = "condition-dir")]
    condition_dirs: Vec<PathBuf>,

    /// Explicit existing foreman SQLite store. Pair by ordinal with --foreman-run-id.
    #[arg(long = "foreman-store")]
    foreman_stores: Vec<PathBuf>,

    /// Exact foreman run identity. It is never interpreted as a filesystem path.
    #[arg(long = "foreman-run-id")]
    foreman_run_ids: Vec<String>,

    /// Explicit compiled UI directory containing index.html, .vite/manifest.json, and assets.
    #[arg(long)]
    ui_dir: Option<PathBuf>,

    /// Loopback socket address. Non-loopback addresses are refused.
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,

    /// Optional deterministic currentness evaluation instant for qualification.
    #[arg(long)]
    evaluated_at: Option<DateTime<Utc>>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.foreman_stores.len() != args.foreman_run_ids.len() {
        anyhow::bail!("each --foreman-store requires one ordinal --foreman-run-id");
    }
    if args.run_dirs.is_empty() && args.foreman_stores.is_empty() && args.condition_dirs.is_empty()
    {
        anyhow::bail!("at least one sealed, live, or operational condition source is required");
    }
    let evaluated_now = args.evaluated_at.unwrap_or_else(Utc::now);
    let runs = load_runs_at(&args.run_dirs, evaluated_now).context("load casework runs")?;
    let sources = args
        .foreman_stores
        .into_iter()
        .zip(args.foreman_run_ids)
        .collect();
    let api = Api::new(runs)
        .with_live_sources(sources, args.evaluated_at)
        .map_err(anyhow::Error::msg)?
        .with_operational_conditions(&args.condition_dirs)
        .map_err(anyhow::Error::msg)?;
    let api = match args.ui_dir {
        Some(directory) => api
            .with_static_ui(StaticUi::load(&directory).context("load closed compiled UI assets")?),
        None => api,
    };
    let listener = bind_loopback(args.bind).context("bind read-only loopback API")?;
    println!(
        "nightshift-casework listening on http://{}",
        listener.local_addr()?
    );
    serve(listener, api).context("serve read-only loopback API")
}
