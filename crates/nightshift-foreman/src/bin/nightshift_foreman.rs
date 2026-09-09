use std::{
    fs::{self, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::PathBuf,
};

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use nightshift_foreman::{
    derive_provider_snapshot_evidence, ExecutionProfileV2, ForemanAdmissionV1,
    ForemanExecutionAvailabilityRequirementV1, ForemanStore, ProviderDispatchOccurrenceV1,
    ProviderDispositionEvidenceV1, SelfHostedBootstrapInputsV1,
};

const MAXIMUM_BOOTSTRAP_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[path = "../provider_cli_inputs.rs"]
mod provider_cli_inputs;

#[derive(Parser)]
#[command(
    name = "nightshift-foreman",
    about = "Durable non-authorizing local agent-compute scheduler"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Translate retained mapper evidence; store admission remains a separate gate.
    ProviderDeriveEvidence {
        #[arg(long)]
        requirement: PathBuf,
        #[arg(long)]
        dispatch: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        received_at: String,
        #[arg(long)]
        expires_at: String,
    },
    /// Canonicalize operator-authored contracts; does not admit or launch work.
    ProviderSealInputs {
        #[arg(long)]
        draft: PathBuf,
    },
    /// Admit exact existing provider-mechanism contracts; grants no target authority.
    ProviderAdmit {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        admission: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        requirement: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evaluated_at: String,
    },
    /// Atomically reserve one attempt and its exact provider dispatch, without launching.
    ProviderPrepare {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        work_item: String,
        #[arg(long)]
        dispatch: String,
        #[arg(long)]
        adapter_process: String,
        #[arg(long)]
        app_server_session: String,
        #[arg(long)]
        selected_model_ordinal: u16,
        #[arg(long)]
        recorded_at: String,
    },
    /// Retain independently derived provider evidence through the existing owner gate.
    ProviderRecord {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        work_item: String,
        #[arg(long)]
        attempt_id: String,
        #[arg(long)]
        observation: PathBuf,
        #[arg(long)]
        disposition: PathBuf,
        #[arg(long)]
        deferred: Option<PathBuf>,
        #[arg(long)]
        predecessor_disposition_digest: Option<String>,
    },
    SealAdmission {
        #[arg(long)]
        draft: PathBuf,
    },
    SealProfile {
        #[arg(long)]
        draft: PathBuf,
    },
    Admit {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        admission: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        evaluated_at: String,
    },
    BootstrapAdmit {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        bootstrap: PathBuf,
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        admission: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        capacity_requirement: PathBuf,
        #[arg(long)]
        capacity_policy: PathBuf,
        #[arg(long)]
        availability_requirement: PathBuf,
        #[arg(long)]
        availability_policy: PathBuf,
    },
    BootstrapStep {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        bootstrap_digest: String,
        #[arg(long)]
        expected_step_ordinal: u32,
        #[arg(long)]
        scheduler_process_occurrence_id: String,
        #[arg(long)]
        recorded_at: String,
    },
    BootstrapStatus {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
    },
    Run {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        work_item: String,
        #[arg(long)]
        recorded_at: String,
    },
    Brief {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        work_item: String,
    },
    Resume {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        work_item: String,
        #[arg(long)]
        attempt_id: String,
        #[arg(long)]
        recorded_at: String,
    },
    AcceptEvent {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        event: PathBuf,
    },
    AcceptReceipt {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
    AcceptNotStarted {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
    Status {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
    },
    Events {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
    },
    Replay {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
    },
    Close {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        updated_at: String,
    },
    ExportLive {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
    },
    ExportFinal {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ProviderDeriveEvidence {
            requirement,
            dispatch,
            snapshot,
            received_at,
            expires_at,
        } => {
            let requirement = ForemanExecutionAvailabilityRequirementV1::from_slice(
                &read_bounded_existing(&requirement)?,
            )?;
            let dispatch =
                ProviderDispatchOccurrenceV1::from_slice(&read_bounded_existing(&dispatch)?)?;
            let (disposition, observation) = derive_provider_snapshot_evidence(
                &requirement,
                &dispatch,
                &read_bounded_existing(&snapshot)?,
                instant(&received_at)?,
                instant(&expires_at)?,
            )?;
            print_json(
                &serde_json::json!({"disposition": disposition, "observation": observation}),
            )?;
        }
        Command::ProviderSealInputs { draft } => {
            write_raw(&provider_cli_inputs::seal(&read_bounded_existing(&draft)?)?)?;
        }
        Command::ProviderAdmit {
            db,
            packet,
            admission,
            profile,
            requirement,
            policy,
            evaluated_at,
        } => {
            let packet = read_bounded_existing(&packet)?;
            let admission = read_bounded_existing(&admission)?;
            let profile = read_bounded_existing(&profile)?;
            let requirement = read_bounded_existing(&requirement)?;
            let policy = read_bounded_existing(&policy)?;
            let run_id = ForemanStore::open(db)?.admit_with_execution_availability(
                &packet,
                &admission,
                &profile,
                &requirement,
                &policy,
                instant(&evaluated_at)?,
            )?;
            print_json(&serde_json::json!({"run_id": run_id}))?;
        }
        Command::ProviderPrepare {
            db,
            run_id,
            work_item,
            dispatch,
            adapter_process,
            app_server_session,
            selected_model_ordinal,
            recorded_at,
        } => {
            let opened = ForemanStore::open(db)?.prepare_provider_attempt(
                &run_id,
                &work_item,
                &dispatch,
                &adapter_process,
                &app_server_session,
                selected_model_ordinal,
                instant(&recorded_at)?,
            )?;
            print_json(&serde_json::json!({
                "worker_start_request": opened.worker_start_request,
                "dispatch": opened.dispatch,
            }))?;
        }
        Command::ProviderRecord {
            db,
            run_id,
            work_item,
            attempt_id,
            observation,
            disposition,
            deferred,
            predecessor_disposition_digest,
        } => {
            let observation = read_bounded_existing(&observation)?;
            let disposition = read_bounded_existing(&disposition)?;
            let deferred = deferred.as_ref().map(read_bounded_existing).transpose()?;
            let result = ForemanStore::open(db)?.record_provider_disposition(
                &run_id,
                &work_item,
                &attempt_id,
                ProviderDispositionEvidenceV1 {
                    observation_bytes: &observation,
                    disposition_bytes: &disposition,
                    deferred_bytes: deferred.as_deref(),
                },
                predecessor_disposition_digest.as_deref(),
            )?;
            print_json(&result)?;
        }
        Command::SealAdmission { draft } => {
            let mut admission = ForemanAdmissionV1::from_slice(&read(&draft)?)?;
            admission.seal()?;
            write_raw(&serde_jcs::to_vec(&admission)?)?;
        }
        Command::SealProfile { draft } => {
            let mut profile = ExecutionProfileV2::from_slice(&read(&draft)?)?;
            profile.seal()?;
            write_raw(&serde_jcs::to_vec(&profile)?)?;
        }
        Command::Admit {
            db,
            packet,
            admission,
            profile,
            evaluated_at,
        } => {
            let store = ForemanStore::open(db)?;
            let run_id = store.admit(
                &read(&packet)?,
                &read(&admission)?,
                &read(&profile)?,
                instant(&evaluated_at)?,
            )?;
            print_json(&serde_json::json!({"run_id": run_id}))?;
        }
        Command::BootstrapAdmit {
            db,
            bootstrap,
            packet,
            admission,
            profile,
            capacity_requirement,
            capacity_policy,
            availability_requirement,
            availability_policy,
        } => {
            let bootstrap_bytes = read_bounded_existing(&bootstrap)?;
            let packet_bytes = read_bounded_existing(&packet)?;
            let admission_bytes = read_bounded_existing(&admission)?;
            let profile_bytes = read_bounded_existing(&profile)?;
            let capacity_requirement_bytes = read_bounded_existing(&capacity_requirement)?;
            let capacity_policy_bytes = read_bounded_existing(&capacity_policy)?;
            let availability_requirement_bytes = read_bounded_existing(&availability_requirement)?;
            let availability_policy_bytes = read_bounded_existing(&availability_policy)?;
            let run_id = ForemanStore::admit_self_hosted_at_path(
                db,
                SelfHostedBootstrapInputsV1 {
                    bootstrap_bytes: &bootstrap_bytes,
                    packet_bytes: &packet_bytes,
                    admission_bytes: &admission_bytes,
                    profile_bytes: &profile_bytes,
                    capacity_requirement_bytes: &capacity_requirement_bytes,
                    capacity_policy_bytes: &capacity_policy_bytes,
                    execution_availability_requirement_bytes: &availability_requirement_bytes,
                    execution_availability_policy_bytes: &availability_policy_bytes,
                },
            )?;
            print_json(&serde_json::json!({"run_id": run_id}))?;
        }
        Command::BootstrapStep {
            db,
            run_id,
            bootstrap_digest,
            expected_step_ordinal,
            scheduler_process_occurrence_id,
            recorded_at,
        } => {
            let store = ForemanStore::open(db)?;
            let step = store.advance_self_hosted_driver(
                &run_id,
                &bootstrap_digest,
                expected_step_ordinal,
                &scheduler_process_occurrence_id,
                instant(&recorded_at)?,
            )?;
            print_json(&step)?;
        }
        Command::BootstrapStatus { db, run_id } => {
            print_json(&ForemanStore::open_read_only(db)?.self_hosted_bootstrap(&run_id)?)?;
        }
        Command::Run {
            db,
            run_id,
            work_item,
            recorded_at,
        } => {
            let store = ForemanStore::open(db)?;
            let request = store.prepare_attempt(&run_id, &work_item, instant(&recorded_at)?)?;
            store.record_dispatch_requested(
                &run_id,
                &work_item,
                &request.attempt_id,
                instant(&recorded_at)?,
            )?;
            print_json(&request)?;
        }
        Command::Brief {
            db,
            run_id,
            work_item,
        } => write_raw(&ForemanStore::open_read_only(db)?.worker_brief(&run_id, &work_item)?)?,
        Command::Resume {
            db,
            run_id,
            work_item,
            attempt_id,
            recorded_at,
        } => {
            let store = ForemanStore::open(db)?;
            store.record_resume_requested(
                &run_id,
                &work_item,
                &attempt_id,
                instant(&recorded_at)?,
            )?;
            print_json(&store.projection(&run_id)?)?;
        }
        Command::AcceptEvent { db, event } => {
            ForemanStore::open(db)?.accept_adapter_event(&read(&event)?)?;
        }
        Command::AcceptReceipt { db, receipt } => {
            ForemanStore::open(db)?.accept_terminal_receipt(&read(&receipt)?)?;
        }
        Command::AcceptNotStarted { db, receipt } => {
            ForemanStore::open(db)?.accept_not_started(&read(&receipt)?)?;
        }
        Command::Status { db, run_id }
        | Command::Replay { db, run_id }
        | Command::ExportLive { db, run_id } => {
            print_json(&ForemanStore::open_read_only(db)?.projection(&run_id)?)?;
        }
        Command::Events { db, run_id } => {
            print_json(&ForemanStore::open_read_only(db)?.export_events(&run_id)?)?;
        }
        Command::Close {
            db,
            run_id,
            updated_at,
        } => write_raw(&ForemanStore::open(db)?.close(&run_id, instant(&updated_at)?)?)?,
        Command::ExportFinal { db, run_id } => {
            write_raw(&ForemanStore::open_read_only(db)?.export_final(&run_id)?)?;
        }
    }
    Ok(())
}

fn instant(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid RFC3339 timestamp: {value}"))?
        .with_timezone(&Utc))
}

fn read(path: &PathBuf) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

fn read_bounded_existing(path: &PathBuf) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot open bounded input {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect bounded input {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "bounded input is not a regular file: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() > 0 && metadata.len() <= MAXIMUM_BOOTSTRAP_INPUT_BYTES,
        "bounded input size is outside 1..={MAXIMUM_BOOTSTRAP_INPUT_BYTES}: {}",
        path.display()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAXIMUM_BOOTSTRAP_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read bounded input {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 == metadata.len() && bytes.len() as u64 <= MAXIMUM_BOOTSTRAP_INPUT_BYTES,
        "bounded input changed during acquisition: {}",
        path.display()
    );
    Ok(bytes)
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_raw(&bytes)
}

fn write_raw(bytes: &[u8]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    Ok(())
}
