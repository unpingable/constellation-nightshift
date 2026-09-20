//! Canonical Nightshift runtime CLI. It observes and delegates exact proposals
//! to AG; it has no standing, authorization, Docket, or executor surface.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use chrono::{DateTime, Utc};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use nightshiftd::ag_port::{
    parse_ag_refusal, AgLoopCtlPortV1, AgOccurrencePortV1, AgOpenOccurrenceRequestV1,
};
use nightshiftd::authoring_context::AuthoringContextQueryV1;
use nightshiftd::authoring_custody::{MaudeAuthoringContextHandoffV1, MaudeCustodyVerifierV1};
use nightshiftd::canonical_runtime::{
    prepare_decision_evidence_cycle_request, prepare_external_evidence_cycle_request,
    CanonicalCycleRequestV1, CanonicalRuntime, CycleRunOutcomeV1,
};
use nightshiftd::canonical_store::{
    AgOccurrenceReferenceV1, AgProfileBindingV1, CanonicalStore, ObservationCycleId,
    ObservationCycleV1,
};
use nightshiftd::continuity_authority::ContinuityAuthorityVerifierV1;
use nightshiftd::currentness::{
    CommandPresentEvidencePortV1, PresentEvidencePortV1, PresentEvidenceQueryV1, QualifiedSupportV1,
};
use nightshiftd::external_evidence_composition::ExternalEvidenceProfileV1;
use nightshiftd::external_observation::{
    ExternalObservationHandoffV1, ExternalObservationQueryV1, ExternalObservationVerifierV1,
};
use nightshiftd::nq_admission::{
    CommandNqAdmissionPortV1, NqAdmissionPortV1, NqAdmissionProvenance, NqAdmissionQueryV1,
};
use nightshiftd::packet::NightshiftPacketV1;
use nightshiftd::project_predicate_attention::{
    evaluate, read_json as read_attention_json,
    read_json_from_reader as read_attention_json_stream, replay_attention, verify_pulse_receipt,
    write_json as write_attention_json, AttentionPolicyV1, AttentionReplayBundleV1,
    AttentionStoreV1, PulseReplayInputsV1,
};
use nightshiftd::repository_qualification::{
    NqNgQualificationVerifierV1, QualificationApplicabilityProfileV1, QualificationReceiptStoreV1,
};
use nightshiftd::reservation_qualification::{
    NqNgReservationVerifierV1, ReservationApplicabilityProfileV1, ReservationRealizationStoreV1,
};
use nightshiftd::saved_check_attention::{
    evaluate_saved_check_attention, read_bundle as read_saved_check_attention_bundle,
    replay_saved_check_attention, SavedCheckAttentionPolicyV1, SavedCheckAttentionReplayBundleV1,
    SavedCheckAttentionStoreV1,
};
use nightshiftd::saved_check_recurrence::SavedCheckScheduleV1;
use nightshiftd::saved_check_runtime::{
    read_config as read_saved_check_config, SavedCheckRuntimeV1,
};
use nightshiftd::steady_state_evidence::{
    SteadyStateEvidenceProfileV1, SteadyStateObservationHandoffV1, SteadyStateObservationVerifierV1,
};
use nightshiftd::substrate_origin::{
    SubstrateOriginRequirementV1, SubstrateOriginVerifierV1, REQUIREMENT_SCHEMA_V1,
};

const MAX_EXACT_INPUT_BYTES: u64 = 16 * 1024 * 1024;
// Executable identities are streamed, not parsed as JSON or buffered wholesale.
// This matches the adjacent AG runtime's bounded executable identity envelope.
const MAX_PINNED_PROGRAM_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "nightshift",
    version,
    about = "Canonical temporal observation and attention office"
)]
struct Arguments {
    #[arg(long, global = true, default_value = "nightshift.sqlite")]
    store: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Cycle {
        #[command(subcommand)]
        command: CycleCommand,
    },
    /// Authenticated custody and read-only inspection for external world-
    /// observation candidates. This does not create an observation cycle.
    ExternalObservation {
        #[command(subcommand)]
        command: ExternalObservationCommand,
    },
    /// Operator-owned attention policy over exact verified Pulse
    /// project-predicate support history. CLI invocation is not evidence.
    Attention {
        #[command(subcommand)]
        command: AttentionCommand,
    },
    /// Exact NQ repository-qualification receipt ingress. This command only
    /// replays and retains NQ evidence; it creates no observation or AG act.
    RepositoryQualification {
        #[command(subcommand)]
        command: RepositoryQualificationCommand,
    },
    /// Exact NQ reservation-realization receipt ingress. Replays and retains
    /// evidence only; it creates no observation or continuation act.
    ReservationQualification {
        #[command(subcommand)]
        command: ReservationQualificationCommand,
    },
    /// Seal, validate, or render a non-authorizing orientation packet.
    Packet {
        #[command(subcommand)]
        command: PacketCommand,
    },
    /// Select one deterministic desired saved-check occurrence; performs no execution.
    SavedCheck {
        #[command(subcommand)]
        command: SavedCheckCommand,
    },
}
#[derive(Debug, Subcommand)]
enum SavedCheckCommand {
    /// Select one slot; does not acquire a source or reserve an execution.
    Schedule {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        scheduler_clock_id: String,
        #[arg(long)]
        at: String,
    },
    /// Acquire and evaluate one due slot, or reconcile its retained identity.
    Run {
        #[arg(long)]
        runtime_config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        scheduler_clock_id: String,
        #[arg(long)]
        at: String,
    },
    /// Inspect one retained evaluation without acquiring or reading its source.
    Inspect {
        #[arg(long)]
        evaluation_id: String,
    },
    /// Project and retain attention from one terminal evaluation; sends nothing.
    AttentionEvaluate {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evaluation_id: String,
        #[arg(long)]
        evaluated_at: String,
    },
    /// Recompute an exact saved-check attention bundle supplied on stdin.
    AttentionReplay {
        #[arg(long)]
        bundle_stdin: bool,
    },
    /// Inspect a retained attention receipt without refreshing it.
    AttentionStatus {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evaluation_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum PacketCommand {
    /// Seal a draft by deriving its digest and immutable plan reference.
    Seal {
        #[arg(long)]
        packet: PathBuf,
    },
    /// Validate an already sealed packet at an explicit evaluation time.
    Validate {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        evaluated_at: String,
    },
    /// Render a clearly non-authorizing Markdown projection.
    Render {
        #[arg(long)]
        packet: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AttentionCommand {
    /// Validate and display one exact content-bound operator policy.
    ValidatePolicy {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Verify one exact Pulse receipt by replay, then append its distinct
    /// evidence occurrence idempotently to the governed history.
    Ingest(Box<AttentionIngestArguments>),
    /// Evaluate stored history at one explicit occurrence and emit a replay
    /// bundle containing the deterministic attention receipt.
    Evaluate {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evaluated_at: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Recompute an exact saved evaluation without reading or changing the
    /// store and without refreshing upstream time.
    Replay {
        #[arg(
            long,
            required_unless_present = "bundle_stdin",
            conflicts_with = "bundle_stdin"
        )]
        bundle: Option<PathBuf>,
        /// Read the exact bounded replay bundle from stdin. This is intended
        /// for callers that already retain and bind the input bytes.
        #[arg(long, default_value_t = false, conflicts_with = "bundle")]
        bundle_stdin: bool,
    },
    /// Concise read-only projection of an evaluation at an explicit
    /// occurrence. This does not append evidence.
    Status {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evaluated_at: String,
    },
}

#[derive(Debug, ClapArgs)]
struct AttentionIngestArguments {
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    pulse_receipt: PathBuf,
    #[arg(long)]
    pulse_program: PathBuf,
    #[arg(long)]
    pulse_support_policy: PathBuf,
    #[arg(long)]
    nq_executable: PathBuf,
    #[arg(long)]
    nq_receipt: PathBuf,
    #[arg(long)]
    inventory: PathBuf,
    #[arg(long)]
    catalog: PathBuf,
    #[arg(long)]
    support_evidence: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum RepositoryQualificationCommand {
    /// Replay one exact NQ receipt with the pinned evaluator, then retain it.
    Ingest(Box<RepositoryQualificationIngestArguments>),
}

#[derive(Debug, ClapArgs)]
struct RepositoryQualificationIngestArguments {
    #[arg(long)]
    applicability: PathBuf,
    #[arg(long)]
    nq_profile: PathBuf,
    #[arg(long)]
    nq_evidence: PathBuf,
    #[arg(long)]
    nq_receipt: PathBuf,
    #[arg(long)]
    nq_executable: PathBuf,
}

#[derive(Debug, Subcommand)]
enum ReservationQualificationCommand {
    /// Replay one exact NQ realization receipt, then retain its one-use slot.
    Ingest(Box<ReservationQualificationIngestArguments>),
}

#[derive(Debug, ClapArgs)]
struct ReservationQualificationIngestArguments {
    #[arg(long)]
    applicability: PathBuf,
    #[arg(long)]
    nq_profile: PathBuf,
    #[arg(long)]
    nq_evidence: PathBuf,
    #[arg(long)]
    nq_receipt: PathBuf,
    #[arg(long)]
    nq_executable: PathBuf,
}
#[derive(Debug, Subcommand)]
enum ExternalObservationCommand {
    /// Authenticate and durably retain one exact candidate handoff.
    Import {
        #[arg(long)]
        handoff: PathBuf,
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        producer_principal_id: String,
        #[arg(long)]
        producer_key_id: String,
        #[arg(long)]
        nightshift_runtime_id: String,
        #[arg(long)]
        received_at: String,
    },
    /// Authenticate and retain one passive, non-effectful observation.
    ImportSteadyState {
        #[arg(long)]
        handoff: PathBuf,
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        producer_principal_id: String,
        #[arg(long)]
        producer_key_id: String,
        #[arg(long)]
        nightshift_runtime_id: String,
        #[arg(long)]
        received_at: String,
    },
    /// Read-only lookup. Select exactly one identity form.
    Export {
        #[arg(long)]
        observation_id: Option<String>,
        #[arg(long, requires = "occurrence_id")]
        campaign_id: Option<String>,
        #[arg(long, requires = "campaign_id")]
        occurrence_id: Option<String>,
        #[arg(long)]
        attempt_id: Option<String>,
        #[arg(long)]
        evaluated_at_unix_ms: i64,
        #[arg(long)]
        evidence_ttl_ms: u64,
    },
    /// Deterministically bind one sealed base cycle request to the exact
    /// authenticated source and deployment-owned composition profile. This
    /// writes no runtime state and performs no currentness or AG decision.
    PrepareCycle {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Bind one historical qualification plus one passive observation to an
    /// exact successor request without making a currentness decision.
    PrepareDecisionCycle {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Owner-produced absent/current/stale basis for one passive source.
    SteadyStateBasis {
        #[arg(long)]
        qualification_observation_id: String,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        evaluated_at_unix_ms: u64,
    },
}

#[derive(Debug, Subcommand)]
enum CycleCommand {
    /// Run the sole production observation-cycle path.
    Run(Box<CycleRunArguments>),
    /// Run one sealed AG-bound cycle using only a deployment-owned, content
    /// pinned configuration.  The request supplies no executable or store
    /// pathname selection.
    RunConfig {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Read one exact AG occurrence through AG and record status only.
    SyncAg {
        #[arg(long)]
        cycle_id: String,
        #[arg(long)]
        ag_loopctl: PathBuf,
        #[arg(long)]
        ag_database: PathBuf,
        #[arg(long)]
        ag_observation_resolver: PathBuf,
        #[arg(long)]
        ag_observation_resolver_id: String,
        #[arg(long)]
        ag_runtime_profile: PathBuf,
        #[arg(long)]
        observed_at: String,
    },
    /// Consume an exact durable AG refusal outcome. A refusal closes this
    /// observation cycle and creates no program-counter transition.
    RecordRefusal {
        #[arg(long)]
        cycle_id: String,
        #[arg(long)]
        refusal: PathBuf,
        #[arg(long)]
        observed_at: String,
    },
    /// Apply restart noninheritance, then query AG-bound cycles by status only.
    Recover {
        #[arg(long)]
        ag_loopctl: PathBuf,
        #[arg(long)]
        ag_database: PathBuf,
        #[arg(long)]
        ag_observation_resolver: PathBuf,
        #[arg(long)]
        ag_observation_resolver_id: String,
        #[arg(long)]
        ag_runtime_profile: PathBuf,
        #[arg(long)]
        observed_at: String,
    },
    /// Query AG for the one durable prepared occurrence bound by this exact
    /// sealed request.  This never sweeps unrelated recovery candidates.
    RecoverConfig {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    Show {
        #[arg(long)]
        cycle_id: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    /// Read-only export of every persisted observation with one exact
    /// observation identity, including lineage position. It never mutates
    /// cycle state, acquires leases, or contacts AG.
    ExportObservation {
        #[arg(long)]
        observation_id: String,
    },
    /// Read-only exact authoring-context lookup. Supply exactly one complete
    /// identity form: governed occurrence, proposal, or Maude plan/session.
    ExportAuthoringContext {
        #[arg(long, requires = "occurrence_id")]
        campaign_id: Option<String>,
        #[arg(long, requires = "campaign_id")]
        occurrence_id: Option<String>,
        #[arg(long)]
        proposal_id: Option<String>,
        #[arg(long, requires = "maude_session_id")]
        plan_ref: Option<String>,
        #[arg(long, requires = "plan_ref")]
        maude_session_id: Option<String>,
    },
    /// Read-only authenticated delivery evidence for authoring context.
    ExportAuthoringCustody {
        #[arg(long, requires = "occurrence_id")]
        campaign_id: Option<String>,
        #[arg(long, requires = "campaign_id")]
        occurrence_id: Option<String>,
        #[arg(long)]
        proposal_id: Option<String>,
        #[arg(long, requires = "maude_session_id")]
        plan_ref: Option<String>,
        #[arg(long, requires = "plan_ref")]
        maude_session_id: Option<String>,
    },
    List,
    Replay {
        #[arg(long)]
        cycle_id: String,
    },
}

#[derive(Debug, ClapArgs)]
struct CycleRunArguments {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    present_evidence_resolver: PathBuf,
    /// Exact NQ-NG CLI used only for read-only admission qualification.
    #[arg(long)]
    nq_program: PathBuf,
    /// Configuration locating the owning NQ-NG store. This path is not
    /// authority identity.
    #[arg(long)]
    nq_config: PathBuf,
    /// Stable expected NQ-NG store-genesis identity.
    #[arg(long)]
    nq_source_id: String,
    /// Standing Ed25519 public key used only to verify continuity carriers.
    #[arg(long, requires_all = ["standing_continuity_key_id", "standing_continuity_nq_audience"])]
    standing_continuity_public_key: Option<PathBuf>,
    #[arg(long, requires_all = ["standing_continuity_public_key", "standing_continuity_nq_audience"])]
    standing_continuity_key_id: Option<String>,
    #[arg(long, requires_all = ["standing_continuity_public_key", "standing_continuity_key_id"])]
    standing_continuity_nq_audience: Option<String>,
    /// Independently owned Ed25519 origin-attester public key. Supplying this
    /// activates the relying-side V3 requirement for the exact subject; V1/V2
    /// evidence cannot downgrade it.
    #[arg(long)]
    substrate_origin_public_key: Option<PathBuf>,
    #[arg(long)]
    substrate_origin_profile_id: Option<String>,
    #[arg(long)]
    substrate_origin_subject_ref: Option<String>,
    #[arg(long)]
    substrate_origin_issuer_id: Option<String>,
    #[arg(long)]
    substrate_origin_key_id: Option<String>,
    #[arg(long)]
    substrate_origin_namespace: Option<String>,
    /// SHA-256 digest of the independently pinned decimal Linode instance ID.
    /// Supplying it selects the closed linode_instance_metadata_v1 profile;
    /// metadata observed at runtime is never accepted as its own bootstrap pin.
    #[arg(long, requires = "substrate_origin_public_key")]
    substrate_origin_linode_instance_id_sha256: Option<String>,
    /// Exact first V3 coordinate allowed to establish history. Omit after
    /// cutover; a successor key then requires prior history plus Standing.
    #[arg(long, requires = "substrate_origin_public_key")]
    substrate_origin_bootstrap_coordinate_ref: Option<String>,
    #[arg(long)]
    ag_loopctl: Option<PathBuf>,
    #[arg(long)]
    ag_database: Option<PathBuf>,
    #[arg(long)]
    ag_observation_resolver: Option<PathBuf>,
    /// Resolver identity repeated to AG and checked against its pinned profile.
    #[arg(long)]
    ag_observation_resolver_id: Option<String>,
    /// Deployment-owned AG policy/Docket profile pinned at campaign genesis.
    #[arg(long)]
    ag_runtime_profile: Option<PathBuf>,
    /// Separate exact Maude custody handoff. It is attached in memory to
    /// the sealed base request and never authorizes AG work.
    #[arg(long)]
    maude_authoring_handoff: Option<PathBuf>,
    #[arg(long)]
    maude_custody_credential: Option<PathBuf>,
    #[arg(long)]
    maude_producer_principal_id: Option<String>,
    #[arg(long)]
    maude_producer_key_id: Option<String>,
    #[arg(long)]
    maude_session_custody_credential: Option<PathBuf>,
    #[arg(long)]
    maude_session_issuer_principal_id: Option<String>,
    #[arg(long)]
    maude_session_issuer_key_id: Option<String>,
    #[arg(long)]
    nightshift_runtime_id: Option<String>,
    /// Deployment-owned profile required only when the sealed cycle request
    /// references authenticated external application evidence.
    #[arg(long)]
    external_evidence_profile: Option<PathBuf>,
    /// Deployment-owned decision-relative qualification + passive profile.
    #[arg(long)]
    decision_evidence_profile: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,
}

const AG_CYCLE_CONFIG_SCHEMA_V1: &str = "nightshift.ag_cycle_config.v1";

fn require_digest(name: &str, value: &str) -> anyhow::Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{name} must use sha256:<64 lowercase hex>");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{name} must use sha256:<64 lowercase hex>");
    }
    Ok(())
}

/// Fixed byte pin for an executable or immutable configuration dependency.
/// Mutable SQLite state is deliberately represented only by its fixed path.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PinnedFileV1 {
    path: PathBuf,
    sha256: String,
}

impl PinnedFileV1 {
    fn verify_program(&self, field: &str) -> anyhow::Result<()> {
        if !self.path.is_absolute() {
            bail!("{field}.path must be absolute");
        }
        if self.sha256 != pinned_program_digest(&self.path)? {
            bail!("{field} digest does not match its configured bytes");
        }
        Ok(())
    }

    fn read_program(self, field: &str) -> anyhow::Result<PathBuf> {
        self.verify_program(field)?;
        Ok(self.path)
    }

    fn verify(&self, field: &str) -> anyhow::Result<()> {
        if !self.path.is_absolute() {
            bail!("{field}.path must be absolute");
        }
        let bytes = read_exact_bytes(&self.path)?;
        let actual = format!("sha256:{:x}", Sha256::digest(bytes));
        if self.sha256 != actual {
            bail!("{field} digest does not match its configured bytes");
        }
        Ok(())
    }

    fn read(self, field: &str) -> anyhow::Result<PathBuf> {
        self.verify(field)?;
        Ok(self.path)
    }
}

/// Closed operational coordinates for the AG-bound cycle port.  V1 pins the
/// current production run surface only; it deliberately excludes optional
/// evidence, custody, continuity, and substrate switches.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgCycleConfigV1 {
    schema: String,
    store: PathBuf,
    present_evidence_resolver: PinnedFileV1,
    nq_program: PinnedFileV1,
    nq_config: PinnedFileV1,
    nq_source_id: String,
    ag_loopctl: PinnedFileV1,
    ag_database: PathBuf,
    ag_observation_resolver: PinnedFileV1,
    ag_observation_resolver_id: String,
    /// This profile locates the V2 profile verified by AG's genesis-bound
    /// store law. It is intentionally not byte-pinned here: that profile
    /// pins this config, so a reciprocal byte pin would form an identity
    /// cycle rather than an independently verifiable relation.
    ag_runtime_profile: PathBuf,
    shared_admission_requirement_digest: String,
    /// A configured coordinate for an AG status query.  It is not refreshed
    /// by recovery and therefore cannot establish new currentness.
    recover_observed_at: String,
}

// Retained recovery coordinates locate the existing owners; they do not renew
// the observation timestamp or grant authority for a successor run.
type AgCycleRecoveryCoordinatesV1 = (
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    String,
    PathBuf,
    DateTime<Utc>,
    AgProfileBindingV1,
);

impl AgCycleConfigV1 {
    fn validate_static_pins(&self) -> anyhow::Result<()> {
        self.present_evidence_resolver
            .verify_program("present_evidence_resolver")?;
        self.nq_program.verify_program("nq_program")?;
        self.nq_config.verify("nq_config")?;
        self.ag_loopctl.verify_program("ag_loopctl")?;
        self.ag_observation_resolver
            .verify_program("ag_observation_resolver")?;
        Ok(())
    }

    fn profile_binding(&self) -> anyhow::Result<AgProfileBindingV1> {
        if !self.ag_runtime_profile.is_absolute() {
            bail!("ag_runtime_profile path must be absolute");
        }
        require_digest(
            "shared_admission_requirement_digest",
            &self.shared_admission_requirement_digest,
        )?;
        Ok(AgProfileBindingV1 {
            runtime_profile_digest: None,
            shared_admission_requirement_digest: self.shared_admission_requirement_digest.clone(),
        })
    }

    fn into_run_arguments(
        self,
        request: PathBuf,
    ) -> anyhow::Result<(PathBuf, CycleRunArguments, AgProfileBindingV1)> {
        if self.schema != AG_CYCLE_CONFIG_SCHEMA_V1 {
            bail!("unsupported AG cycle config schema");
        }
        if !self.store.is_absolute() || !self.ag_database.is_absolute() {
            bail!("AG cycle store and AG database paths must be absolute");
        }
        if self.nq_source_id.trim().is_empty() || self.ag_observation_resolver_id.trim().is_empty()
        {
            bail!("AG cycle configuration identities must be non-empty");
        }
        parse_time(&self.recover_observed_at)?;
        self.validate_static_pins()?;
        let profile_binding = self.profile_binding()?;
        Ok((
            self.store,
            CycleRunArguments {
                request,
                present_evidence_resolver: self
                    .present_evidence_resolver
                    .read_program("present_evidence_resolver")?,
                nq_program: self.nq_program.read_program("nq_program")?,
                nq_config: self.nq_config.read("nq_config")?,
                nq_source_id: self.nq_source_id,
                standing_continuity_public_key: None,
                standing_continuity_key_id: None,
                standing_continuity_nq_audience: None,
                substrate_origin_public_key: None,
                substrate_origin_profile_id: None,
                substrate_origin_subject_ref: None,
                substrate_origin_issuer_id: None,
                substrate_origin_key_id: None,
                substrate_origin_namespace: None,
                substrate_origin_linode_instance_id_sha256: None,
                substrate_origin_bootstrap_coordinate_ref: None,
                ag_loopctl: Some(self.ag_loopctl.read_program("ag_loopctl")?),
                ag_database: Some(self.ag_database),
                ag_observation_resolver: Some(
                    self.ag_observation_resolver
                        .read_program("ag_observation_resolver")?,
                ),
                ag_observation_resolver_id: Some(self.ag_observation_resolver_id),
                ag_runtime_profile: Some(self.ag_runtime_profile),
                maude_authoring_handoff: None,
                maude_custody_credential: None,
                maude_producer_principal_id: None,
                maude_producer_key_id: None,
                maude_session_custody_credential: None,
                maude_session_issuer_principal_id: None,
                maude_session_issuer_key_id: None,
                nightshift_runtime_id: None,
                external_evidence_profile: None,
                decision_evidence_profile: None,
                format: OutputFormat::Json,
            },
            profile_binding,
        ))
    }

    fn recovery_coordinates(self) -> anyhow::Result<AgCycleRecoveryCoordinatesV1> {
        if self.schema != AG_CYCLE_CONFIG_SCHEMA_V1 {
            bail!("unsupported AG cycle config schema");
        }
        if !self.store.is_absolute() || !self.ag_database.is_absolute() {
            bail!("AG cycle store and AG database paths must be absolute");
        }
        let observed_at = parse_time(&self.recover_observed_at)?;
        self.validate_static_pins()?;
        let profile_binding = self.profile_binding()?;
        Ok((
            self.store,
            self.ag_loopctl.read_program("ag_loopctl")?,
            self.ag_database,
            self.ag_observation_resolver
                .read_program("ag_observation_resolver")?,
            self.ag_observation_resolver_id,
            self.ag_runtime_profile,
            observed_at,
            profile_binding,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[clap(rename_all = "snake_case")]
enum OutputFormat {
    Json,
    Text,
}

struct NoAgPort;

impl AgOccurrencePortV1 for NoAgPort {
    fn open_occurrence(
        &mut self,
        _request: &AgOpenOccurrenceRequestV1,
    ) -> Result<AgOccurrenceReferenceV1, String> {
        Err("posture-only cycle has no AG adapter".into())
    }

    fn status(&mut self, _: &str, _: &str) -> Result<AgOccurrenceReferenceV1, String> {
        Err("posture-only cycle has no AG adapter".into())
    }
}

struct NoPresentEvidencePort;

impl PresentEvidencePortV1 for NoPresentEvidencePort {
    fn resolve(&mut self, _: &PresentEvidenceQueryV1) -> Result<QualifiedSupportV1, String> {
        Err("recovery never resolves persisted evidence currentness".into())
    }
}

struct NoNqAdmissionPort;

impl NqAdmissionPortV1 for NoNqAdmissionPort {
    fn qualify(&mut self, _: &NqAdmissionQueryV1) -> Result<NqAdmissionProvenance, String> {
        Err("status recovery never qualifies new NQ evidence".into())
    }
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    match arguments.command {
        Command::Cycle { command } => run_cycle_command(&arguments.store, command),
        Command::ExternalObservation { command } => {
            run_external_observation_command(&arguments.store, command)
        }
        Command::Attention { command } => run_attention_command(&arguments.store, command),
        Command::RepositoryQualification { command } => {
            run_repository_qualification_command(&arguments.store, command)
        }
        Command::ReservationQualification { command } => {
            run_reservation_qualification_command(&arguments.store, command)
        }
        Command::Packet { command } => run_packet_command(command),
        Command::SavedCheck { command } => run_saved_check_command(&arguments.store, command),
    }
}

fn run_saved_check_command(store_path: &Path, command: SavedCheckCommand) -> anyhow::Result<()> {
    match command {
        SavedCheckCommand::Schedule {
            policy,
            scheduler_clock_id,
            at,
        } => {
            let policy: SavedCheckScheduleV1 = read_exact_canonical(&policy)?;
            let selection = policy
                .select(&scheduler_clock_id, parse_time(&at)?)
                .map_err(anyhow::Error::msg)?;
            write_exact(&selection)
        }
        SavedCheckCommand::Run {
            runtime_config,
            policy,
            scheduler_clock_id,
            at,
        } => {
            let (config, config_digest) =
                read_saved_check_config(&runtime_config).map_err(anyhow::Error::msg)?;
            let policy: SavedCheckScheduleV1 = read_exact_canonical(&policy)?;
            let mut runtime = SavedCheckRuntimeV1::open(store_path).map_err(anyhow::Error::msg)?;
            let result = runtime
                .run(
                    &config,
                    &config_digest,
                    &policy,
                    &scheduler_clock_id,
                    parse_time(&at)?,
                )
                .map_err(anyhow::Error::msg)?;
            write_exact(&result)
        }
        SavedCheckCommand::Inspect { evaluation_id } => {
            let runtime =
                SavedCheckRuntimeV1::open_read_only(store_path).map_err(anyhow::Error::msg)?;
            let result = runtime
                .inspect(&evaluation_id)
                .map_err(anyhow::Error::msg)?
                .context("saved-check evaluation is not retained")?;
            write_exact(&result)
        }
        SavedCheckCommand::AttentionEvaluate {
            policy,
            evaluation_id,
            evaluated_at,
        } => {
            let policy: SavedCheckAttentionPolicyV1 = read_exact_canonical(&policy)?;
            let runtime =
                SavedCheckRuntimeV1::open_read_only(store_path).map_err(anyhow::Error::msg)?;
            let evaluation = runtime
                .inspect(&evaluation_id)
                .map_err(anyhow::Error::msg)?
                .context("saved-check evaluation is not retained")?;
            let receipt =
                evaluate_saved_check_attention(&policy, &evaluation, parse_time(&evaluated_at)?)
                    .map_err(anyhow::Error::msg)?;
            let mut store =
                SavedCheckAttentionStoreV1::open(store_path).map_err(anyhow::Error::msg)?;
            let receipt = store.retain(&receipt).map_err(anyhow::Error::msg)?;
            write_exact(&SavedCheckAttentionReplayBundleV1 {
                schema: nightshiftd::saved_check_attention::BUNDLE_SCHEMA.into(),
                policy,
                evaluation,
                receipt,
            })
        }
        SavedCheckCommand::AttentionReplay { bundle_stdin } => {
            if !bundle_stdin {
                bail!("saved-check attention replay requires --bundle-stdin");
            }
            let bundle = read_saved_check_attention_bundle(std::io::stdin().lock())
                .map_err(anyhow::Error::msg)?;
            write_exact(&replay_saved_check_attention(&bundle).map_err(anyhow::Error::msg)?)
        }
        SavedCheckCommand::AttentionStatus {
            policy,
            evaluation_id,
        } => {
            let policy: SavedCheckAttentionPolicyV1 = read_exact_canonical(&policy)?;
            policy.validate().map_err(anyhow::Error::msg)?;
            let store = SavedCheckAttentionStoreV1::open_read_only(store_path)
                .map_err(anyhow::Error::msg)?;
            let receipt = store
                .inspect(&policy.policy_digest, &evaluation_id)
                .map_err(anyhow::Error::msg)?
                .context("saved-check attention receipt is not retained")?;
            write_exact(&receipt)
        }
    }
}

fn run_packet_command(command: PacketCommand) -> anyhow::Result<()> {
    match command {
        PacketCommand::Seal { packet } => {
            let mut packet: NightshiftPacketV1 = read_exact(&packet)?;
            packet.seal().map_err(anyhow::Error::msg)?;
            write_exact_without_delimiter(&packet)
        }
        PacketCommand::Validate {
            packet,
            evaluated_at,
        } => {
            let packet: NightshiftPacketV1 = read_exact_canonical(&packet)?;
            write_exact(
                &packet
                    .validate_at(parse_time(&evaluated_at)?)
                    .map_err(anyhow::Error::msg)?,
            )
        }
        PacketCommand::Render { packet } => {
            let packet: NightshiftPacketV1 = read_exact_canonical(&packet)?;
            print!("{}", packet.render_markdown());
            Ok(())
        }
    }
}

fn run_repository_qualification_command(
    store_path: &Path,
    command: RepositoryQualificationCommand,
) -> anyhow::Result<()> {
    match command {
        RepositoryQualificationCommand::Ingest(arguments) => {
            let RepositoryQualificationIngestArguments {
                applicability,
                nq_profile,
                nq_evidence,
                nq_receipt,
                nq_executable,
            } = *arguments;
            let applicability: QualificationApplicabilityProfileV1 = read_exact(&applicability)?;
            let profile: serde_json::Value = read_exact(&nq_profile)?;
            let evidence: serde_json::Value = read_exact(&nq_evidence)?;
            let receipt: serde_json::Value = read_exact(&nq_receipt)?;
            let mut verifier =
                NqNgQualificationVerifierV1::new(nq_executable).map_err(anyhow::Error::msg)?;
            let mut store =
                QualificationReceiptStoreV1::open(store_path).map_err(anyhow::Error::msg)?;
            let retained = store
                .ingest(&applicability, &profile, &evidence, &receipt, &mut verifier)
                .map_err(anyhow::Error::msg)?;
            write_exact(&retained)
        }
    }
}

fn run_reservation_qualification_command(
    store_path: &Path,
    command: ReservationQualificationCommand,
) -> anyhow::Result<()> {
    match command {
        ReservationQualificationCommand::Ingest(arguments) => {
            let ReservationQualificationIngestArguments {
                applicability,
                nq_profile,
                nq_evidence,
                nq_receipt,
                nq_executable,
            } = *arguments;
            let applicability: ReservationApplicabilityProfileV1 = read_exact(&applicability)?;
            let profile: serde_json::Value = read_exact(&nq_profile)?;
            let evidence: serde_json::Value = read_exact(&nq_evidence)?;
            let receipt: serde_json::Value = read_exact(&nq_receipt)?;
            let mut verifier =
                NqNgReservationVerifierV1::new(nq_executable).map_err(anyhow::Error::msg)?;
            let mut store =
                ReservationRealizationStoreV1::open(store_path).map_err(anyhow::Error::msg)?;
            let retained = store
                .ingest(&applicability, &profile, &evidence, &receipt, &mut verifier)
                .map_err(anyhow::Error::msg)?;
            write_exact(&retained)
        }
    }
}

fn run_attention_command(store_path: &Path, command: AttentionCommand) -> anyhow::Result<()> {
    match command {
        AttentionCommand::ValidatePolicy { policy } => {
            let policy: AttentionPolicyV1 =
                read_attention_json(&policy).map_err(anyhow::Error::msg)?;
            policy.validate().map_err(anyhow::Error::msg)?;
            write_exact(&policy)
        }
        AttentionCommand::Ingest(arguments) => {
            let AttentionIngestArguments {
                policy,
                pulse_receipt,
                pulse_program,
                pulse_support_policy,
                nq_executable,
                nq_receipt,
                inventory,
                catalog,
                support_evidence,
            } = *arguments;
            let policy: AttentionPolicyV1 =
                read_attention_json(&policy).map_err(anyhow::Error::msg)?;
            let receipt = verify_pulse_receipt(
                &policy,
                &pulse_receipt,
                &PulseReplayInputsV1 {
                    pulse_executable: pulse_program,
                    pulse_policy: pulse_support_policy,
                    nq_executable,
                    nq_receipt,
                    inventory,
                    catalog,
                    support_evidence,
                },
            )
            .map_err(anyhow::Error::msg)?;
            let mut store = AttentionStoreV1::open(store_path).map_err(anyhow::Error::msg)?;
            write_exact(
                &store
                    .ingest_verified(&policy, receipt)
                    .map_err(anyhow::Error::msg)?,
            )
        }
        AttentionCommand::Evaluate {
            policy,
            evaluated_at,
            output,
        } => {
            let policy: AttentionPolicyV1 =
                read_attention_json(&policy).map_err(anyhow::Error::msg)?;
            let store = AttentionStoreV1::open(store_path).map_err(anyhow::Error::msg)?;
            let history = store.history(&policy).map_err(anyhow::Error::msg)?;
            let bundle = evaluate(&policy, &history, parse_time(&evaluated_at)?)
                .map_err(anyhow::Error::msg)?;
            if let Some(output) = output {
                write_attention_json(&output, &bundle).map_err(anyhow::Error::msg)
            } else {
                write_exact(&bundle)
            }
        }
        AttentionCommand::Replay {
            bundle,
            bundle_stdin,
        } => {
            let bundle: AttentionReplayBundleV1 = match (bundle, bundle_stdin) {
                (Some(path), false) => read_attention_json(&path).map_err(anyhow::Error::msg)?,
                (None, true) => read_attention_json_stream(std::io::stdin().lock())
                    .map_err(anyhow::Error::msg)?,
                _ => bail!("attention replay requires exactly one of --bundle or --bundle-stdin"),
            };
            let replay = replay_attention(&bundle).map_err(anyhow::Error::msg)?;
            write_exact(&replay)?;
            if !replay.matches {
                bail!("Nightshift attention replay did not reproduce the exact receipt");
            }
            Ok(())
        }
        AttentionCommand::Status {
            policy,
            evaluated_at,
        } => {
            let policy: AttentionPolicyV1 =
                read_attention_json(&policy).map_err(anyhow::Error::msg)?;
            let store = AttentionStoreV1::open(store_path).map_err(anyhow::Error::msg)?;
            let history = store.history(&policy).map_err(anyhow::Error::msg)?;
            let bundle = evaluate(&policy, &history, parse_time(&evaluated_at)?)
                .map_err(anyhow::Error::msg)?;
            let receipt = bundle.receipt;
            println!("project: {}", receipt.project);
            println!("concern: {}", receipt.concern);
            println!("subject: {}", receipt.subject_id);
            println!("disposition: {:?}", receipt.disposition);
            println!("reason_class: {:?}", receipt.attention_reason_class);
            println!(
                "recurrence: {}/{} distinct occurrences",
                receipt.qualifying_distinct_occurrences, receipt.required_distinct_occurrences
            );
            println!("evaluated_at: {}", receipt.evaluated_at);
            println!("detail: {}", receipt.detail);
            Ok(())
        }
    }
}

fn run_external_observation_command(
    store_path: &Path,
    command: ExternalObservationCommand,
) -> anyhow::Result<()> {
    match command {
        ExternalObservationCommand::Import {
            handoff,
            credential,
            producer_principal_id,
            producer_key_id,
            nightshift_runtime_id,
            received_at,
        } => {
            let handoff: ExternalObservationHandoffV1 = read_exact_canonical(&handoff)?;
            let verifier = ExternalObservationVerifierV1::from_key_file(
                producer_principal_id,
                producer_key_id,
                nightshift_runtime_id,
                &credential,
            )
            .map_err(anyhow::Error::msg)?;
            let verified = verifier.verify(&handoff).map_err(anyhow::Error::msg)?;
            let received_at = parse_time(&received_at)?;
            let mut store = CanonicalStore::open(store_path)?;
            write_exact(&store.record_external_observation(&verified, received_at)?)
        }
        ExternalObservationCommand::ImportSteadyState {
            handoff,
            credential,
            producer_principal_id,
            producer_key_id,
            nightshift_runtime_id,
            received_at,
        } => {
            let handoff: SteadyStateObservationHandoffV1 = read_exact_canonical(&handoff)?;
            let verifier = SteadyStateObservationVerifierV1::from_key_file(
                producer_principal_id,
                producer_key_id,
                nightshift_runtime_id,
                &credential,
            )
            .map_err(anyhow::Error::msg)?;
            let verified = verifier.verify(&handoff).map_err(anyhow::Error::msg)?;
            let received_at = parse_time(&received_at)?;
            let mut store = CanonicalStore::open(store_path)?;
            write_exact(&store.record_steady_state_observation(&verified, received_at)?)
        }
        ExternalObservationCommand::Export {
            observation_id,
            campaign_id,
            occurrence_id,
            attempt_id,
            evaluated_at_unix_ms,
            evidence_ttl_ms,
        } => {
            let query = match (observation_id, campaign_id, occurrence_id, attempt_id) {
                (Some(observation_id), None, None, None) => {
                    ExternalObservationQueryV1::Observation { observation_id }
                }
                (None, Some(campaign_id), Some(occurrence_id), None) => {
                    ExternalObservationQueryV1::GovernedOccurrence {
                        campaign_id,
                        occurrence_id,
                    }
                }
                (None, None, None, Some(attempt_id)) => {
                    ExternalObservationQueryV1::Attempt { attempt_id }
                }
                _ => bail!(
                    "choose exactly one external-observation query: observation, campaign+occurrence, or attempt"
                ),
            };
            let store = CanonicalStore::open_read_only(store_path)?;
            write_exact(&store.export_external_observation(
                query,
                evaluated_at_unix_ms,
                evidence_ttl_ms,
            )?)
        }
        ExternalObservationCommand::PrepareCycle { request, profile } => {
            let request: CanonicalCycleRequestV1 = read_exact_canonical(&request)?;
            let profile: ExternalEvidenceProfileV1 = read_exact_canonical(&profile)?;
            let store = CanonicalStore::open_read_only(store_path)?;
            write_exact(&prepare_external_evidence_cycle_request(
                &store, request, &profile,
            )?)
        }
        ExternalObservationCommand::PrepareDecisionCycle { request, profile } => {
            let request: CanonicalCycleRequestV1 = read_exact_canonical(&request)?;
            let profile: SteadyStateEvidenceProfileV1 = read_exact_canonical(&profile)?;
            let store = CanonicalStore::open_read_only(store_path)?;
            write_exact(&prepare_decision_evidence_cycle_request(
                &store, request, &profile,
            )?)
        }
        ExternalObservationCommand::SteadyStateBasis {
            qualification_observation_id,
            profile,
            evaluated_at_unix_ms,
        } => {
            let profile: SteadyStateEvidenceProfileV1 = read_exact_canonical(&profile)?;
            let store = CanonicalStore::open_read_only(store_path)?;
            write_exact(&store.steady_state_reobservation_basis(
                &qualification_observation_id,
                &profile,
                evaluated_at_unix_ms,
            )?)
        }
    }
}

fn run_cycle_command(store_path: &Path, command: CycleCommand) -> anyhow::Result<()> {
    run_cycle_command_bound(store_path, command, None)
}

// `PreparedAgRequestV1::exact_request` retains the sealed AG-open envelope.
// The cycle proposal retains that envelope's exact inner proposal_input.  The
// outer cycle-request digest and id are checked separately at recovery.
fn prepared_open_request_matches_proposal_input(
    prepared_open_request: &serde_json::Value,
    proposal_input: &serde_json::Value,
) -> bool {
    prepared_open_request.get("proposal_input") == Some(proposal_input)
}

fn run_cycle_command_bound(
    store_path: &Path,
    command: CycleCommand,
    ag_profile_binding: Option<AgProfileBindingV1>,
) -> anyhow::Result<()> {
    match command {
        CycleCommand::RunConfig { config, request } => {
            let sealed: CanonicalCycleRequestV1 = read_exact_canonical(&request)?;
            sealed.validate().map_err(anyhow::Error::msg)?;
            if sealed.proposal.is_none() {
                bail!("config run requires an AG-bound sealed proposal");
            }
            if sealed.reviewed_plan_binding.is_none() {
                bail!("protected V2 config run requires a sealed reviewed plan binding");
            }
            if sealed.authoring_context.is_some() {
                bail!("config run does not configure Maude custody material");
            }
            let config: AgCycleConfigV1 = read_exact_canonical(&config)?;
            let (configured_store, arguments, binding) = config.into_run_arguments(request)?;
            run_cycle_command_bound(
                &configured_store,
                CycleCommand::Run(Box::new(arguments)),
                Some(binding),
            )
        }
        CycleCommand::Run(arguments) => {
            let CycleRunArguments {
                request,
                present_evidence_resolver,
                nq_program,
                nq_config,
                nq_source_id,
                standing_continuity_public_key,
                standing_continuity_key_id,
                standing_continuity_nq_audience,
                substrate_origin_public_key,
                substrate_origin_profile_id,
                substrate_origin_subject_ref,
                substrate_origin_issuer_id,
                substrate_origin_key_id,
                substrate_origin_namespace,
                substrate_origin_linode_instance_id_sha256,
                substrate_origin_bootstrap_coordinate_ref,
                ag_loopctl,
                ag_database,
                ag_observation_resolver,
                ag_observation_resolver_id,
                ag_runtime_profile,
                maude_authoring_handoff,
                maude_custody_credential,
                maude_producer_principal_id,
                maude_producer_key_id,
                maude_session_custody_credential,
                maude_session_issuer_principal_id,
                maude_session_issuer_key_id,
                nightshift_runtime_id,
                external_evidence_profile,
                decision_evidence_profile,
                format,
            } = *arguments;
            let mut request: CanonicalCycleRequestV1 = read_exact(&request)?;
            if let Some(path) = maude_authoring_handoff {
                if request.authoring_context.is_some() {
                    bail!("base cycle request already contains authoring context");
                }
                let handoff: MaudeAuthoringContextHandoffV1 = read_exact(&path)?;
                if handoff.target_request_id != request.request_id {
                    bail!("Maude handoff does not target the exact sealed base cycle request");
                }
                request.authoring_context = Some(handoff);
                request = request.seal().map_err(anyhow::Error::msg)?;
            }
            let custody_verifier = if request.authoring_context.is_some() {
                let (
                    credential,
                    principal,
                    key_id,
                    session_credential,
                    session_issuer,
                    session_key_id,
                    runtime_id,
                ) = match (
                    maude_custody_credential,
                    maude_producer_principal_id,
                    maude_producer_key_id,
                    maude_session_custody_credential,
                    maude_session_issuer_principal_id,
                    maude_session_issuer_key_id,
                    nightshift_runtime_id,
                ) {
                    (
                        Some(credential),
                        Some(principal),
                        Some(key_id),
                        Some(session_credential),
                        Some(session_issuer),
                        Some(session_key_id),
                        Some(runtime_id),
                    ) => (
                        credential,
                        principal,
                        key_id,
                        session_credential,
                        session_issuer,
                        session_key_id,
                        runtime_id,
                    ),
                    _ => bail!(
                        "Maude authoring context requires --maude-custody-credential, \
                         --maude-producer-principal-id, --maude-producer-key-id, and \
                         --maude-session-custody-credential, \
                         --maude-session-issuer-principal-id, \
                         --maude-session-issuer-key-id, and --nightshift-runtime-id"
                    ),
                };
                Some(
                    MaudeCustodyVerifierV1::from_key_file(
                        principal,
                        key_id,
                        session_issuer,
                        session_key_id,
                        runtime_id,
                        &credential,
                        &session_credential,
                    )
                    .map_err(anyhow::Error::msg)?,
                )
            } else {
                if maude_custody_credential.is_some()
                    || maude_producer_principal_id.is_some()
                    || maude_producer_key_id.is_some()
                    || maude_session_custody_credential.is_some()
                    || maude_session_issuer_principal_id.is_some()
                    || maude_session_issuer_key_id.is_some()
                    || nightshift_runtime_id.is_some()
                {
                    bail!("Maude custody configuration supplied without authoring context");
                }
                None
            };
            let has_proposal = request.proposal.is_some();
            let external_profile = match (
                request.external_evidence.is_some(),
                external_evidence_profile,
            ) {
                (true, Some(path)) => {
                    Some(read_exact_canonical::<ExternalEvidenceProfileV1>(&path)?)
                }
                (true, None) => bail!("external evidence requires --external-evidence-profile"),
                (false, Some(_)) => {
                    bail!("external-evidence profile supplied without an exact evidence reference")
                }
                (false, None) => None,
            };
            let decision_profile = match (
                request.decision_external_evidence.is_some(),
                decision_evidence_profile,
            ) {
                (true, Some(path)) => {
                    Some(read_exact_canonical::<SteadyStateEvidenceProfileV1>(&path)?)
                }
                (true, None) => bail!("decision evidence requires --decision-evidence-profile"),
                (false, Some(_)) => {
                    bail!("decision-evidence profile supplied without an exact evidence reference")
                }
                (false, None) => None,
            };
            let mut store = CanonicalStore::open(store_path)?;
            let mut support = CommandPresentEvidencePortV1::new(present_evidence_resolver)
                .map_err(anyhow::Error::msg)?;
            let nq = CommandNqAdmissionPortV1::new(nq_program, nq_config, nq_source_id)
                .map_err(anyhow::Error::msg)?;
            let nq = match (
                standing_continuity_public_key,
                standing_continuity_key_id,
                standing_continuity_nq_audience,
            ) {
                (Some(key), Some(key_id), Some(audience)) => nq.with_continuity_verifier(
                    ContinuityAuthorityVerifierV1::from_public_key_file(key_id, audience, &key)
                        .map_err(anyhow::Error::msg)?,
                ),
                (None, None, None) => nq,
                _ => bail!(
                    "Standing continuity verification requires public key, key id, and NQ audience"
                ),
            };
            let nq = match (
                substrate_origin_public_key,
                substrate_origin_profile_id,
                substrate_origin_subject_ref,
                substrate_origin_issuer_id,
                substrate_origin_key_id,
                substrate_origin_namespace,
                substrate_origin_linode_instance_id_sha256,
            ) {
                (
                    Some(key),
                    Some(profile_id),
                    Some(subject_ref),
                    Some(issuer_id),
                    Some(key_id),
                    Some(namespace),
                    linode_instance_id_sha256,
                ) => nq.with_substrate_origin_verifier(
                    SubstrateOriginVerifierV1::from_public_key_file(
                        SubstrateOriginRequirementV1 {
                            schema: REQUIREMENT_SCHEMA_V1.into(),
                            profile_id,
                            subject_ref,
                            bootstrap_coordinate_ref:
                                substrate_origin_bootstrap_coordinate_ref,
                            expected_issuer_id: issuer_id,
                            expected_key_id: key_id,
                            expected_namespace: namespace,
                            expected_linode_instance_id_sha256:
                                linode_instance_id_sha256,
                        },
                        &key,
                    )
                    .map_err(anyhow::Error::msg)?,
                ),
                (None, None, None, None, None, None, None) => {
                    if substrate_origin_bootstrap_coordinate_ref.is_some() {
                        bail!("substrate-origin bootstrap coordinate requires the full verifier configuration");
                    }
                    nq
                }
                _ => bail!(
                    "substrate-origin verification requires public key, profile id, subject, issuer id, key id, and namespace"
                ),
            };
            let outcome = if has_proposal {
                let (program, database, resolver, resolver_id, profile) = match (
                    ag_loopctl,
                    ag_database,
                    ag_observation_resolver,
                    ag_observation_resolver_id,
                    ag_runtime_profile,
                ) {
                        (
                            Some(program),
                            Some(database),
                            Some(resolver),
                            Some(resolver_id),
                            Some(profile),
                        ) => {
                            (program, database, resolver, resolver_id, profile)
                        }
                        _ => bail!(
                            "exact work requires --ag-loopctl, --ag-database, --ag-observation-resolver, --ag-observation-resolver-id, and --ag-runtime-profile"
                        ),
                    };
                let mut ag =
                    AgLoopCtlPortV1::new(program, database, resolver, resolver_id, profile)
                        .map_err(anyhow::Error::msg)?;
                let mut runtime = match (external_profile, decision_profile) {
                    (Some(_), Some(_)) => bail!(
                        "cycle cannot configure legacy and decision-relative evidence together"
                    ),
                    (Some(profile), None) => CanonicalRuntime::new_with_external_evidence_profile(
                        &mut store,
                        nq,
                        &mut support,
                        &mut ag,
                        profile,
                    )?,
                    (None, Some(profile)) => CanonicalRuntime::new_with_decision_evidence_profile(
                        &mut store,
                        nq,
                        &mut support,
                        &mut ag,
                        profile,
                    )?,
                    (None, None) => CanonicalRuntime::new(&mut store, nq, &mut support, &mut ag),
                };
                match (custody_verifier.as_ref(), ag_profile_binding) {
                    (Some(_), Some(_)) => bail!("config binding cannot combine with Maude custody"),
                    (Some(verifier), None) => {
                        runtime.run_cycle_with_authoring_custody(request, verifier)?
                    }
                    (None, Some(binding)) => {
                        runtime.run_cycle_with_ag_profile_binding(request, binding)?
                    }
                    (None, None) => runtime.run_cycle(request)?,
                }
            } else {
                if ag_loopctl.is_some()
                    || ag_database.is_some()
                    || ag_observation_resolver.is_some()
                    || ag_observation_resolver_id.is_some()
                    || ag_runtime_profile.is_some()
                {
                    bail!("AG options are forbidden for a posture-only cycle");
                }
                let mut ag = NoAgPort;
                let mut runtime = CanonicalRuntime::new(&mut store, nq, &mut support, &mut ag);
                if ag_profile_binding.is_some() {
                    bail!("AG profile binding requires an AG-bound proposal");
                }
                match custody_verifier.as_ref() {
                    Some(verifier) => {
                        runtime.run_cycle_with_authoring_custody(request, verifier)?
                    }
                    None => runtime.run_cycle(request)?,
                }
            };
            render_outcome(&outcome, format)
        }
        CycleCommand::SyncAg {
            cycle_id,
            ag_loopctl,
            ag_database,
            ag_observation_resolver,
            ag_observation_resolver_id,
            ag_runtime_profile,
            observed_at,
        } => {
            let id = ObservationCycleId::parse(cycle_id)?;
            let now = parse_time(&observed_at)?;
            let mut store = CanonicalStore::open(store_path)?;
            let mut support = NoPresentEvidencePort;
            let nq = NoNqAdmissionPort;
            let mut ag = AgLoopCtlPortV1::new(
                ag_loopctl,
                ag_database,
                ag_observation_resolver,
                ag_observation_resolver_id,
                ag_runtime_profile,
            )
            .map_err(anyhow::Error::msg)?;
            write_exact(
                &CanonicalRuntime::new(&mut store, nq, &mut support, &mut ag).sync_ag(&id, now)?,
            )
        }
        CycleCommand::Recover {
            ag_loopctl,
            ag_database,
            ag_observation_resolver,
            ag_observation_resolver_id,
            ag_runtime_profile,
            observed_at,
        } => {
            let now = parse_time(&observed_at)?;
            let mut store = CanonicalStore::open(store_path)?;
            let candidates = store.recover_after_restart(now)?;
            let mut support = NoPresentEvidencePort;
            let mut ag = AgLoopCtlPortV1::new(
                ag_loopctl,
                ag_database,
                ag_observation_resolver,
                ag_observation_resolver_id,
                ag_runtime_profile,
            )
            .map_err(anyhow::Error::msg)?;
            let mut recovered = Vec::new();
            for cycle in candidates {
                if cycle.prepared_ag_request.is_some() {
                    let nq = NoNqAdmissionPort;
                    recovered.push(
                        CanonicalRuntime::new(&mut store, nq, &mut support, &mut ag)
                            .sync_ag(&cycle.cycle_id, now)
                            .with_context(|| {
                                format!("AG status failed for {}", cycle.cycle_id.as_str())
                            })?,
                    );
                } else {
                    recovered.push(cycle);
                }
            }
            write_exact(&recovered)
        }
        CycleCommand::RecoverConfig { config, request } => {
            let config: AgCycleConfigV1 = read_exact_canonical(&config)?;
            let (
                configured_store,
                ag_loopctl,
                ag_database,
                ag_observation_resolver,
                ag_observation_resolver_id,
                ag_runtime_profile,
                observed_at,
                mut profile_binding,
            ) = config.recovery_coordinates()?;
            let request: CanonicalCycleRequestV1 = read_exact_canonical(&request)?;
            request.validate().map_err(anyhow::Error::msg)?;
            let proposal = request
                .proposal
                .as_ref()
                .context("config recovery requires an AG-bound sealed proposal")?;
            let source_request_digest = format!(
                "sha256:{:x}",
                Sha256::digest(
                    serde_jcs::to_vec(&request)
                        .context("canonicalize sealed request for recovery")?,
                )
            );
            let mut ag = AgLoopCtlPortV1::new(
                ag_loopctl,
                ag_database,
                ag_observation_resolver,
                ag_observation_resolver_id,
                ag_runtime_profile,
            )
            .map_err(anyhow::Error::msg)?;
            // Config-run persists the AG-reopened profile digest, rather than
            // the unverified locator. Reopen the same relation before matching
            // its one retained prepared request; otherwise every valid V2
            // recovery would compare `None` to the persisted digest.
            profile_binding.runtime_profile_digest =
                ag.runtime_profile_digest().map_err(anyhow::Error::msg)?;
            profile_binding
                .validate_prepared()
                .map_err(|error| anyhow::Error::msg(error.to_string()))?;
            let mut store = CanonicalStore::open(&configured_store)?;
            let cycle = store
                .list_cycles()?
                .into_iter()
                .filter(|cycle| {
                    cycle.prepared_ag_request.as_ref().is_some_and(|prepared| {
                        prepared.campaign_id == proposal.campaign_id
                            && prepared.occurrence_id == proposal.occurrence_id
                            && prepared.source_cycle_request_id.as_deref()
                                == Some(request.request_id.as_str())
                            && prepared.source_cycle_request_digest.as_deref()
                                == Some(source_request_digest.as_str())
                            && prepared.ag_profile_binding.as_ref() == Some(&profile_binding)
                            && prepared_open_request_matches_proposal_input(
                                &prepared.exact_request,
                                &proposal.proposal_input,
                            )
                    })
                })
                .collect::<Vec<_>>();
            let [cycle] = cycle.as_slice() else {
                bail!("exact sealed request must match exactly one durable prepared AG request");
            };
            let mut support = NoPresentEvidencePort;
            let nq = NoNqAdmissionPort;
            write_exact(
                &CanonicalRuntime::new(&mut store, nq, &mut support, &mut ag)
                    .sync_ag(&cycle.cycle_id, observed_at)?,
            )
        }
        CycleCommand::RecordRefusal {
            cycle_id,
            refusal,
            observed_at,
        } => {
            let id = ObservationCycleId::parse(cycle_id)?;
            let now = parse_time(&observed_at)?;
            let exact_outcome: serde_json::Value = read_exact(&refusal)?;
            let mut store = CanonicalStore::open(store_path)?;
            let cycle = store.get_cycle(&id)?;
            let request = cycle
                .prepared_ag_request
                .as_ref()
                .context("cycle has no exact prepared AG request")?;
            let refusal =
                parse_ag_refusal(exact_outcome, &request.campaign_id, &request.occurrence_id)
                    .map_err(anyhow::Error::msg)?;
            write_exact(&store.record_ag_refusal(&id, &cycle.state_digest, refusal, now)?)
        }
        CycleCommand::Show { cycle_id, format } => {
            let store = CanonicalStore::open(store_path)?;
            let cycle = store.get_cycle(&ObservationCycleId::parse(cycle_id)?)?;
            match format {
                OutputFormat::Json => write_exact(&cycle),
                OutputFormat::Text => render_cycle_text(&cycle),
            }
        }
        CycleCommand::List => write_exact(&CanonicalStore::open(store_path)?.list_cycles()?),
        CycleCommand::ExportObservation { observation_id } => {
            let store = CanonicalStore::open(store_path)?;
            write_exact(
                &store
                    .export_observation(&observation_id)
                    .map_err(anyhow::Error::msg)?,
            )
        }
        CycleCommand::ExportAuthoringContext {
            campaign_id,
            occurrence_id,
            proposal_id,
            plan_ref,
            maude_session_id,
        } => {
            let query = authoring_query(
                campaign_id,
                occurrence_id,
                proposal_id,
                plan_ref,
                maude_session_id,
            )?;
            let store = CanonicalStore::open_read_only(store_path)?;
            write_exact(&store.export_authoring_context(query)?)
        }
        CycleCommand::ExportAuthoringCustody {
            campaign_id,
            occurrence_id,
            proposal_id,
            plan_ref,
            maude_session_id,
        } => {
            let query = authoring_query(
                campaign_id,
                occurrence_id,
                proposal_id,
                plan_ref,
                maude_session_id,
            )?;
            let store = CanonicalStore::open_read_only(store_path)?;
            write_exact(&store.export_authoring_custody(query)?)
        }
        CycleCommand::Replay { cycle_id } => {
            let store = CanonicalStore::open(store_path)?;
            write_exact(&store.replay(&ObservationCycleId::parse(cycle_id)?)?)
        }
    }
}

fn authoring_query(
    campaign_id: Option<String>,
    occurrence_id: Option<String>,
    proposal_id: Option<String>,
    plan_ref: Option<String>,
    maude_session_id: Option<String>,
) -> anyhow::Result<AuthoringContextQueryV1> {
    match (
        campaign_id,
        occurrence_id,
        proposal_id,
        plan_ref,
        maude_session_id,
    ) {
        (Some(campaign_id), Some(occurrence_id), None, None, None) => {
            Ok(AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            })
        }
        (None, None, Some(proposal_id), None, None) => {
            Ok(AuthoringContextQueryV1::Proposal { proposal_id })
        }
        (None, None, None, Some(plan_ref), Some(session_id)) => {
            Ok(AuthoringContextQueryV1::MaudeContext {
                plan_ref,
                session_id,
            })
        }
        _ => bail!(
            "choose exactly one complete authoring-context query: campaign+occurrence, proposal, or plan-ref+maude-session-id"
        ),
    }
}

fn render_outcome(outcome: &CycleRunOutcomeV1, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => write_exact(outcome),
        OutputFormat::Text => {
            let cycle = match outcome {
                CycleRunOutcomeV1::Missed { cycle }
                | CycleRunOutcomeV1::PostureOnly { cycle }
                | CycleRunOutcomeV1::AgOccurrenceOpened { cycle } => cycle,
            };
            render_cycle_text(cycle)
        }
    }
}

fn render_cycle_text(cycle: &ObservationCycleV1) -> anyhow::Result<()> {
    println!("cycle: {}", cycle.cycle_id.as_str());
    println!("slot: {}", cycle.slot.slot_id.as_str());
    println!("status: {:?}", cycle.status);
    println!("state_digest: {}", cycle.state_digest);
    println!("headline_display_only: {:?}", cycle.headline());
    Ok(())
}

fn read_exact<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let bytes = read_exact_bytes(path)?;
    decode_exact(&bytes, path)
}

fn pinned_program_digest(path: &Path) -> anyhow::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open pinned program {}", path.display()))?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_PINNED_PROGRAM_BYTES {
        bail!(
            "pinned program must be a nonempty regular file within 256 MiB: {}",
            path.display()
        );
    }
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed += count as u64;
        if observed > MAX_PINNED_PROGRAM_BYTES {
            bail!("pinned program exceeds 256 MiB: {}", path.display());
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if observed != before.len() || !same_pinned_program_metadata(&before, &after) {
        bail!("pinned program changed during hashing: {}", path.display());
    }
    let located = std::fs::symlink_metadata(path)?;
    if !located.is_file() || !same_pinned_program_metadata(&after, &located) {
        bail!(
            "pinned program pathname changed during hashing: {}",
            path.display()
        );
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn same_pinned_program_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

fn read_exact_bytes(path: &Path) -> anyhow::Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    let file = if let Some(raw) = exact_input_inherited_fd(path)? {
        let duplicated = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("duplicate exact input {}", path.display()));
        }
        // SAFETY: F_DUPFD_CLOEXEC returned a fresh owned descriptor.
        unsafe { std::fs::File::from_raw_fd(duplicated) }
    } else {
        let mut options = OpenOptions::new();
        options.read(true);
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options
            .open(path)
            .with_context(|| format!("open exact input {}", path.display()))?
    };
    #[cfg(not(target_os = "linux"))]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        options
            .open(path)
            .with_context(|| format!("open exact input {}", path.display()))?
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect exact input {}", path.display()))?;
    if !metadata.is_file() {
        bail!("exact input is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_EXACT_INPUT_BYTES {
        bail!("exact input exceeds 16 MiB: {}", path.display());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_EXACT_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read exact input {}", path.display()))?;
    if bytes.len() as u64 > MAX_EXACT_INPUT_BYTES {
        bail!("exact input exceeds 16 MiB: {}", path.display());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn exact_input_inherited_fd(path: &Path) -> anyhow::Result<Option<i32>> {
    let Some(text) = path.to_str() else {
        return Ok(None);
    };
    let Some(digits) = text.strip_prefix("/proc/self/fd/") else {
        return Ok(None);
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("inherited exact-input descriptor is malformed");
    }
    let descriptor: i32 = digits
        .parse()
        .context("inherited exact-input descriptor is out of range")?;
    if descriptor < 3 {
        bail!("standard descriptors cannot carry exact input");
    }
    Ok(Some(descriptor))
}

fn decode_exact<T: DeserializeOwned>(bytes: &[u8], path: &Path) -> anyhow::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)
        .with_context(|| format!("decode exact JSON {}", path.display()))?;
    deserializer
        .end()
        .with_context(|| format!("reject trailing JSON in {}", path.display()))?;
    Ok(value)
}

fn read_exact_canonical<T: DeserializeOwned + Serialize>(path: &Path) -> anyhow::Result<T> {
    let actual = read_exact_bytes(path)?;
    let value = decode_exact(&actual, path)?;
    let expected = serde_jcs::to_vec(&value).context("canonicalize exact input")?;
    if actual != expected {
        bail!("input must be exact canonical JSON: {}", path.display());
    }
    Ok(value)
}

fn write_exact<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let bytes = serde_jcs::to_vec(value).context("canonicalize output")?;
    println!(
        "{}",
        String::from_utf8(bytes).context("canonical JSON is UTF-8")?
    );
    Ok(())
}

fn write_exact_without_delimiter<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let bytes = serde_jcs::to_vec(value).context("canonicalize output")?;
    std::io::stdout()
        .lock()
        .write_all(&bytes)
        .context("write exact canonical output")
}

fn parse_time(value: &str) -> anyhow::Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .context("observed_at must be RFC3339")?
        .with_timezone(&Utc))
}

#[cfg(test)]
mod exact_input_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_input_reads_inherited_descriptor_without_reopening_pathname() {
        use std::os::fd::AsRawFd as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.json");
        std::fs::write(&path, br#"{"value":"original"}"#).unwrap();
        let retained = std::fs::File::open(&path).unwrap();
        let inherited = PathBuf::from(format!("/proc/self/fd/{}", retained.as_raw_fd()));
        std::fs::rename(&path, directory.path().join("validated.json")).unwrap();
        std::fs::write(&path, br#"{"value":"replacement"}"#).unwrap();
        let value: serde_json::Value = read_exact(&inherited).unwrap();
        assert_eq!(value["value"], "original");
        assert!(exact_input_inherited_fd(Path::new("/proc/self/fd/2")).is_err());
    }

    #[test]
    fn exact_input_preserves_crlf_and_rejects_trailing_json() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.json");
        std::fs::write(&path, br#"{"value":"line\r\n"}"#).unwrap();
        let value: serde_json::Value = read_exact(&path).unwrap();
        assert_eq!(value["value"], "line\r\n");
        std::fs::write(&path, b"{}\n{}\n").unwrap();
        assert!(read_exact::<serde_json::Value>(&path).is_err());
    }

    #[test]
    fn exact_input_rejects_oversize_and_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.json");
        std::fs::write(&path, vec![b' '; MAX_EXACT_INPUT_BYTES as usize + 1]).unwrap();
        assert!(read_exact::<serde_json::Value>(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            std::fs::write(&path, b"{}").unwrap();
            let linked = directory.path().join("linked.json");
            symlink(&path, &linked).unwrap();
            assert!(read_exact::<serde_json::Value>(&linked).is_err());
        }
    }

    #[test]
    fn external_observation_input_requires_exact_canonical_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("handoff.json");
        std::fs::write(&path, br#"{ "b": 2, "a": 1 }"#).unwrap();
        assert!(read_exact_canonical::<serde_json::Value>(&path).is_err());

        std::fs::write(&path, br#"{"a":1,"b":2}"#).unwrap();
        let value: serde_json::Value = read_exact_canonical(&path).unwrap();
        assert_eq!(value, serde_json::json!({"a": 1, "b": 2}));
    }

    #[test]
    fn pinned_cycle_dependency_rejects_content_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixed-dependency");
        std::fs::write(&path, b"qualified bytes").unwrap();
        let pin = PinnedFileV1 {
            path,
            sha256: format!("sha256:{:x}", Sha256::digest(b"qualified bytes")),
        };
        pin.verify("dependency").unwrap();
        std::fs::write(&pin.path, b"different bytes").unwrap();
        assert!(pin.verify("dependency").is_err());
    }

    #[test]
    fn pinned_program_above_json_bound_is_streamed_but_config_is_still_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large-program");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_EXACT_INPUT_BYTES + 1).unwrap();
        let mut expected = Sha256::new();
        for _ in 0..MAX_EXACT_INPUT_BYTES / 1024 {
            expected.update([0_u8; 1024]);
        }
        expected.update([0_u8]);
        let pin = PinnedFileV1 {
            path,
            sha256: format!("sha256:{:x}", expected.finalize()),
        };
        pin.verify_program("nq_program").unwrap();
        assert!(pin.verify("nq_config").is_err());
        assert!(read_exact_bytes(&pin.path).is_err());
        pin.read_program("nq_program").unwrap();
    }

    #[test]
    fn pinned_program_rejects_oversize_empty_nonregular_and_content_mutation() {
        let directory = tempfile::tempdir().unwrap();
        assert!(pinned_program_digest(directory.path()).is_err());
        let path = directory.path().join("program");
        let file = std::fs::File::create(&path).unwrap();
        assert!(pinned_program_digest(&path).is_err());
        file.set_len(MAX_PINNED_PROGRAM_BYTES + 1).unwrap();
        assert!(pinned_program_digest(&path).is_err());
        std::fs::write(&path, b"qualified program bytes").unwrap();
        let pin = PinnedFileV1 {
            path,
            sha256: format!("sha256:{:x}", Sha256::digest(b"qualified program bytes")),
        };
        pin.verify_program("program").unwrap();
        std::fs::write(&pin.path, b"substituted program bytes").unwrap();
        assert!(pin.verify_program("program").is_err());
        #[cfg(unix)]
        {
            let linked = directory.path().join("linked-program");
            std::os::unix::fs::symlink(&pin.path, &linked).unwrap();
            assert!(pinned_program_digest(&linked).is_err());
        }
    }

    #[test]
    fn qualified_real_cycle_config_program_loading_when_supplied() {
        let Some(path) = std::env::var_os("NIGHTSHIFT_QUALIFY_CYCLE_CONFIG") else {
            return;
        };
        let config: AgCycleConfigV1 = read_exact(Path::new(&path)).unwrap();
        let expected_program = config.nq_program.path.clone();
        assert!(std::fs::metadata(&expected_program).unwrap().len() > MAX_EXACT_INPUT_BYTES);
        let (_, arguments, _) = config
            .into_run_arguments(PathBuf::from("/not-executed-qualification-request.json"))
            .unwrap();
        assert_eq!(arguments.nq_program, expected_program);
        let recovery: AgCycleConfigV1 = read_exact(Path::new(&path)).unwrap();
        recovery.recovery_coordinates().unwrap();
        // Loading validates every real configured byte pin; it does not invoke
        // the program, open a runtime store, or acquire an observation.
    }

    #[test]
    fn cycle_config_requires_absolute_mutable_store_coordinates() {
        let directory = tempfile::tempdir().unwrap();
        let dependency = directory.path().join("dependency");
        std::fs::write(&dependency, b"qualified bytes").unwrap();
        let pin = || PinnedFileV1 {
            path: dependency.clone(),
            sha256: format!("sha256:{:x}", Sha256::digest(b"qualified bytes")),
        };
        let config = AgCycleConfigV1 {
            schema: AG_CYCLE_CONFIG_SCHEMA_V1.into(),
            store: PathBuf::from("relative.sqlite"),
            present_evidence_resolver: pin(),
            nq_program: pin(),
            nq_config: pin(),
            nq_source_id: "source".into(),
            ag_loopctl: pin(),
            ag_database: directory.path().join("ag.sqlite"),
            ag_observation_resolver: pin(),
            ag_observation_resolver_id: "resolver".into(),
            ag_runtime_profile: directory.path().join("runtime-profile.json"),
            shared_admission_requirement_digest: format!("sha256:{}", "b".repeat(64)),
            recover_observed_at: "2026-09-12T00:00:00Z".into(),
        };
        assert!(config
            .into_run_arguments(directory.path().join("request.json"))
            .is_err());
    }

    #[test]
    fn attention_replay_selects_exactly_one_input_contract() {
        assert!(Arguments::try_parse_from([
            "nightshift",
            "attention",
            "replay",
            "--bundle",
            "/tmp/bundle.json"
        ])
        .is_ok());
        assert!(
            Arguments::try_parse_from(["nightshift", "attention", "replay", "--bundle-stdin"])
                .is_ok()
        );
        assert!(Arguments::try_parse_from(["nightshift", "attention", "replay"]).is_err());
        assert!(Arguments::try_parse_from([
            "nightshift",
            "attention",
            "replay",
            "--bundle",
            "/tmp/bundle.json",
            "--bundle-stdin"
        ])
        .is_err());
    }

    #[test]
    fn recovery_matches_the_retained_open_envelope_inner_proposal_only() {
        let proposal_input = serde_json::json!({
            "class": "initial",
            "observation": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "proposal": {"schema": "ag.governed-loop.exact-work-proposal/v1"}
        });
        let retained_open_envelope = serde_json::json!({
            "schema": "nightshift.ag_open_occurrence_request.v1",
            "request_id": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "campaign_id": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "occurrence_id": "8f67f8d1-a0e8-4a89-a664-2273304285b2",
            "mode": {"genesis": {}},
            "proposal_input": proposal_input.clone()
        });
        let altered_inner = serde_json::json!({"class": "successor"});
        assert_ne!(retained_open_envelope, proposal_input);
        assert!(prepared_open_request_matches_proposal_input(
            &retained_open_envelope,
            &proposal_input,
        ));
        assert!(!prepared_open_request_matches_proposal_input(
            &retained_open_envelope,
            &altered_inner,
        ));
        assert!(!prepared_open_request_matches_proposal_input(
            &serde_json::json!({"proposal_input": null}),
            &proposal_input,
        ));
    }

    #[test]
    fn shared_config_and_saved_check_command_surfaces_coexist() {
        for verb in ["run-config", "recover-config"] {
            assert!(Arguments::try_parse_from([
                "nightshift",
                "cycle",
                verb,
                "--config",
                "/not-opened/config.json",
                "--request",
                "/not-opened/request.json",
            ])
            .is_ok());
            assert!(Arguments::try_parse_from([
                "nightshift",
                "cycle",
                verb,
                "--config",
                "/not-opened/config.json",
            ])
            .is_err());
        }
        assert!(Arguments::try_parse_from([
            "nightshift",
            "saved-check",
            "schedule",
            "--policy",
            "/not-opened/policy.json",
            "--scheduler-clock-id",
            "qualified-owner-clock",
            "--at",
            "2026-09-14T00:00:00Z",
        ])
        .is_ok());
        assert!(Arguments::try_parse_from([
            "nightshift",
            "saved-check",
            "attention-replay",
            "--bundle-stdin",
        ])
        .is_ok());
    }
}
