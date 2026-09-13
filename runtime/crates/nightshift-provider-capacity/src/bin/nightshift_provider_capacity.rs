use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use nightshift_provider_capacity::{
    decide_capacity, probe_codex_app_server, CapacityObservationV1, CapacityPolicyV1,
    CodexProbeOptions,
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration as StdDuration;

#[derive(Debug, Parser)]
#[command(about = "Read-only provider-capacity observation and deterministic policy tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Read supported Codex rate-limit testimony through App Server stdio.
    ProbeCodex {
        /// Canonical absolute path to the native Codex executable, not a wrapper.
        #[arg(long)]
        codex_executable: PathBuf,
        /// Exact raw SHA-256 digest of the native executable.
        #[arg(long)]
        expected_executable_digest: String,
        /// Exact Codex protocol version expected from initialize.userAgent.
        #[arg(long)]
        expected_protocol_version: String,
        #[arg(long, default_value = "local-codex-profile")]
        account_profile_locator: String,
        #[arg(long)]
        observed_at: Option<DateTime<Utc>>,
        #[arg(long, default_value_t = 15)]
        expires_after_minutes: i64,
        #[arg(long, default_value_t = 8)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 65_536)]
        maximum_response_bytes: usize,
    },
    /// Print the closed default reserve policy.
    DefaultPolicy,
    /// Project an exact observation and policy into a reproducible decision.
    Decide {
        #[arg(long)]
        observation: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        decision_at: DateTime<Utc>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::ProbeCodex {
            codex_executable,
            expected_executable_digest,
            expected_protocol_version,
            account_profile_locator,
            observed_at,
            expires_after_minutes,
            timeout_seconds,
            maximum_response_bytes,
        } => {
            anyhow::ensure!(expires_after_minutes > 0, "expiry must be positive");
            anyhow::ensure!(timeout_seconds > 0, "timeout must be positive");
            anyhow::ensure!(
                maximum_response_bytes > 0,
                "response bound must be positive"
            );
            let options = CodexProbeOptions {
                codex_executable,
                expected_executable_digest,
                expected_protocol_version,
                account_profile_locator,
                observed_at: observed_at.unwrap_or_else(Utc::now),
                expires_after: Duration::minutes(expires_after_minutes),
                timeout: StdDuration::from_secs(timeout_seconds),
                maximum_response_bytes,
            };
            print_json(&probe_codex_app_server(&options))?;
        }
        Commands::DefaultPolicy => print_json(&CapacityPolicyV1::default())?,
        Commands::Decide {
            observation,
            policy,
            decision_at,
        } => {
            let observation: CapacityObservationV1 = read_json(&observation)?;
            let policy: CapacityPolicyV1 = read_json(&policy)?;
            print_json(&decide_capacity(&observation, &policy, decision_at)?)?;
        }
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
