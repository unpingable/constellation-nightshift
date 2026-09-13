//! Nightshift-owned temporal lineage for qualified operational observations.
//!
//! This module consumes exact FIELD-CLOCK Monitor testimony and NQ
//! qualification artifacts through fixture-compatible closed types. It does
//! not qualify claims, contact another office, grant authority, or actuate a
//! target. Immutable lineage and changing re-observation evaluation remain
//! separate contracts.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const OPERATIONAL_LINEAGE_SCHEMA_V1: &str = "nightshift.operational-observation-lineage/v1";
pub const REOBSERVATION_EVALUATION_SCHEMA_V1: &str =
    "nightshift.operational-reobservation-evaluation/v1";
pub const MONITOR_OPERATIONAL_SCHEMA_V1: &str = "monitor.operational-acquisition/v1";
pub const NQ_OPERATIONAL_QUALIFICATION_SCHEMA_V1: &str =
    "nq.operational-observation-qualification/v1";
pub const FIELD_CLOCK_MONITOR_RESULT_HEAD: &str = "b2d52fe34f146774cbf5601819982c267c7fb082";
pub const FIELD_CLOCK_NQ_RESULT_HEAD: &str = "39b9f84f2f70955dd12e5cbfe798c740f9e52854";

const MONITOR_SIGNATURE_DOMAIN_V1: &str = "monitor.operational-observation.v1";
const MONITOR_CONTENT_DIGEST_DOMAIN_V1: &str = "operational.content.v1";
const MAX_COLLECTION: usize = 64;
const MONITOR_MAX_COLLECTION: usize = 32;
const MONITOR_MAX_TEXT_BYTES: usize = 512;
const MAX_RAW_BYTES: usize = 1024 * 1024;
const MAX_AGE_SECONDS: u64 = 31 * 24 * 60 * 60;
const NONCLAIMS: [&str; 4] = [
    "lineage is temporal custody, not claim qualification",
    "currentness is not standing, authorization, or permission to act",
    "producer class does not establish evidentiary precedence",
    "re-observation may acquire testimony but cannot remediate a target",
];
const NQ_NONCLAIMS: [&str; 3] = [
    "NQ qualification grants no authorization or remediation",
    "NQ qualification does not establish Nightshift temporal currentness",
    "producer class alone grants no evidentiary precedence",
];
const NQ_REOPENED_REFUSAL_CODES: [&str; 5] = [
    "receiver_custody_inversion",
    "evaluation_time_inversion",
    "subject_identity_mismatch",
    "producer_identity_mismatch",
    "payload_custody_missing",
];
const NQ_UNOPENED_REFUSAL_CODES: [&str; 41] = [
    "record_oversized",
    "record_malformed",
    "field_malformed",
    "closed_schema_violation",
    "field_missing",
    "field_type",
    "object_expected",
    "body_malformed",
    "schema_unknown",
    "authority_present",
    "invalid_token",
    "invalid_text",
    "subject_kind_unknown",
    "unsupported_subject_basis_contract",
    "subject_basis_kind_mismatch",
    "invalid_collection",
    "noncanonical_collection",
    "locator_kind_unknown",
    "timestamp_invalid",
    "timestamp_noncanonical",
    "digest_invalid",
    "timestamp_inversion",
    "acquisition_outcome_unknown",
    "lineage_invalid",
    "coverage_invalid",
    "coverage_incomplete",
    "content_length_invalid",
    "observation_time_missing",
    "observation_time_inversion",
    "failure_as_world_claim",
    "key_algorithm_unknown",
    "public_key_malformed",
    "producer_key_mismatch",
    "signer_identity_mismatch",
    "signature_domain_mismatch",
    "signature_malformed",
    "signature_invalid",
    "payload_digest_law_unknown",
    "payload_missing",
    "payload_malformed",
    "payload_substitution",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKindV1 {
    Host,
    ServiceInstance,
    DeploymentRelease,
    RepositoryRevision,
    SchedulerJob,
    EcadDesignRevision,
    Toolchain,
    Pdk,
    LicenseEntitlement,
    Worker,
    ArtifactSet,
    StageOccurrence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "basis_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubjectBasisV1 {
    Host {
        machine_identity: String,
    },
    ServiceInstance {
        service_identity: String,
        instance_identity: String,
    },
    DeploymentRelease {
        deployment_identity: String,
        release_identity: String,
    },
    RepositoryRevision {
        repository_identity: String,
        revision_identity: String,
    },
    SchedulerJob {
        scheduler_identity: String,
        job_identity: String,
    },
    EcadDesignRevision {
        design_identity: String,
        revision_identity: String,
    },
    Toolchain {
        toolchain_identity: String,
    },
    Pdk {
        pdk_identity: String,
    },
    LicenseEntitlement {
        entitlement_identity: String,
    },
    Worker {
        worker_identity: String,
    },
    ArtifactSet {
        artifact_set_identity: String,
    },
    StageOccurrence {
        run_identity: String,
        stage_occurrence_identity: String,
    },
}

impl SubjectBasisV1 {
    fn validate(&self, kind: SubjectKindV1) -> Result<(), String> {
        let values = match (kind, self) {
            (SubjectKindV1::Host, Self::Host { machine_identity }) => vec![machine_identity],
            (
                SubjectKindV1::ServiceInstance,
                Self::ServiceInstance {
                    service_identity,
                    instance_identity,
                },
            ) => vec![service_identity, instance_identity],
            (
                SubjectKindV1::DeploymentRelease,
                Self::DeploymentRelease {
                    deployment_identity,
                    release_identity,
                },
            ) => vec![deployment_identity, release_identity],
            (
                SubjectKindV1::RepositoryRevision,
                Self::RepositoryRevision {
                    repository_identity,
                    revision_identity,
                },
            ) => vec![repository_identity, revision_identity],
            (
                SubjectKindV1::SchedulerJob,
                Self::SchedulerJob {
                    scheduler_identity,
                    job_identity,
                },
            ) => vec![scheduler_identity, job_identity],
            (
                SubjectKindV1::EcadDesignRevision,
                Self::EcadDesignRevision {
                    design_identity,
                    revision_identity,
                },
            ) => vec![design_identity, revision_identity],
            (SubjectKindV1::Toolchain, Self::Toolchain { toolchain_identity }) => {
                vec![toolchain_identity]
            }
            (SubjectKindV1::Pdk, Self::Pdk { pdk_identity }) => vec![pdk_identity],
            (
                SubjectKindV1::LicenseEntitlement,
                Self::LicenseEntitlement {
                    entitlement_identity,
                },
            ) => vec![entitlement_identity],
            (SubjectKindV1::Worker, Self::Worker { worker_identity }) => vec![worker_identity],
            (
                SubjectKindV1::ArtifactSet,
                Self::ArtifactSet {
                    artifact_set_identity,
                },
            ) => vec![artifact_set_identity],
            (
                SubjectKindV1::StageOccurrence,
                Self::StageOccurrence {
                    run_identity,
                    stage_occurrence_identity,
                },
            ) => vec![run_identity, stage_occurrence_identity],
            _ => return Err("subject kind and stable-basis family differ".into()),
        };
        values
            .into_iter()
            .try_for_each(|value| digest("stable_basis", value))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalSubjectV1 {
    pub kind: SubjectKindV1,
    pub namespace: String,
    pub basis_contract: String,
    pub stable_basis: SubjectBasisV1,
}

impl OperationalSubjectV1 {
    fn validate(&self) -> Result<(), String> {
        monitor_token("subject.namespace", &self.namespace)?;
        let expected = match self.kind {
            SubjectKindV1::Host => "monitor.subject-basis.host-machine/v1",
            SubjectKindV1::ServiceInstance => "monitor.subject-basis.service-instance-registry/v1",
            SubjectKindV1::DeploymentRelease => {
                "monitor.subject-basis.deployment-release-content/v1"
            }
            SubjectKindV1::RepositoryRevision => {
                "monitor.subject-basis.repository-revision-content/v1"
            }
            SubjectKindV1::SchedulerJob => "monitor.subject-basis.scheduler-job-occurrence/v1",
            SubjectKindV1::EcadDesignRevision => {
                "monitor.subject-basis.ecad-design-revision-content/v1"
            }
            SubjectKindV1::Toolchain => "monitor.subject-basis.toolchain-content/v1",
            SubjectKindV1::Pdk => "monitor.subject-basis.pdk-content/v1",
            SubjectKindV1::LicenseEntitlement => {
                "monitor.subject-basis.license-entitlement-registry/v1"
            }
            SubjectKindV1::Worker => "monitor.subject-basis.worker-registry/v1",
            SubjectKindV1::ArtifactSet => "monitor.subject-basis.artifact-set-content/v1",
            SubjectKindV1::StageOccurrence => "monitor.subject-basis.stage-occurrence/v1",
        };
        if self.basis_contract != expected {
            return Err("unsupported subject basis contract".into());
        }
        self.stable_basis.validate(self.kind)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerPrincipalV1 {
    pub principal_id: String,
    pub collector_id: String,
    pub key_algorithm: String,
    pub public_key_hex: String,
    pub public_key_digest: String,
    pub producer_class: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionOutcomeV1 {
    ObservationProduced,
    NoResponse,
    CommandFailed,
    ProducerUnavailable,
    ReceiverUnavailable,
    MalformedInput,
    Refused,
}

impl AcquisitionOutcomeV1 {
    fn text(self) -> &'static str {
        match self {
            Self::ObservationProduced => "observation_produced",
            Self::NoResponse => "no_response",
            Self::CommandFailed => "command_failed",
            Self::ProducerUnavailable => "producer_unavailable",
            Self::ReceiverUnavailable => "receiver_unavailable",
            Self::MalformedInput => "malformed_input",
            Self::Refused => "refused",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionV1 {
    attempt_id: String,
    started_at: String,
    ended_at: String,
    outcome: AcquisitionOutcomeV1,
    diagnostic_code: String,
    raw_basis_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MonitorLineageV1 {
    epoch: String,
    sequence: u64,
    predecessor_observation_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LocatorKindV1 {
    LocalPath,
    HostLabel,
    DnsName,
    IpAddress,
    Url,
    Socket,
    SchedulerDisplayName,
    RepositoryCheckout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LocatorV1 {
    kind: LocatorKindV1,
    value: String,
    observed_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentV1 {
    media_type: String,
    digest_domain: String,
    digest: String,
    byte_length: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CoverageV1 {
    expected_dimensions: Vec<String>,
    observed_dimensions: Vec<String>,
    omitted_dimensions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MonitorBodyV1 {
    schema: String,
    producer: ProducerPrincipalV1,
    subject: OperationalSubjectV1,
    locators: Vec<LocatorV1>,
    acquisition: AcquisitionV1,
    lineage: MonitorLineageV1,
    producer_observed_at: Option<String>,
    payload_schema: Option<String>,
    payload: Option<ContentV1>,
    attachments: Vec<ContentV1>,
    coverage: CoverageV1,
    grants_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedMonitorV1 {
    body: MonitorBodyV1,
    signature_domain: String,
    signer_key_identity_digest: String,
    signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSupportV1 {
    pub claim_id: String,
    pub proposition: String,
    pub value_digest: String,
    pub monitor_record_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CannotTestifyV1 {
    pub claim_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalV1 {
    pub code: String,
    pub exact_basis_digest: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NqInputV1 {
    input_id: String,
    raw_record_digest: String,
    monitor_record_digest: Option<String>,
    subject_identity_digest: Option<String>,
    producer_identity_digest: Option<String>,
    producer_principal_id: Option<String>,
    producer_class: Option<String>,
    acquisition_outcome: Option<String>,
    producer_observed_at: Option<DateTime<Utc>>,
    receiver_custody_at: DateTime<Utc>,
    payload_schema: Option<String>,
    claim_support: Vec<ClaimSupportV1>,
    cannot_testify: Vec<CannotTestifyV1>,
    refusals: Vec<RefusalV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContradictionV1 {
    pub subject_identity_digest: String,
    pub claim_id: String,
    pub first_input_id: String,
    pub first_value_digest: String,
    pub second_input_id: String,
    pub second_value_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NqArtifactV1 {
    schema: String,
    profile_id: String,
    monitor_contract_head: String,
    evaluated_at: DateTime<Utc>,
    inputs: Vec<NqInputV1>,
    contradictions: Vec<ContradictionV1>,
    nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactCustodyV1 {
    pub raw_bytes_sha256: String,
    pub raw_bytes_length: u64,
    pub semantic_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalObservationLineageV1 {
    pub schema: String,
    pub lineage_id: String,
    pub monitor_result_head: String,
    pub nq_result_head: String,
    pub monitor_custody: ExactArtifactCustodyV1,
    pub nq_custody: ExactArtifactCustodyV1,
    pub nq_profile_id: String,
    pub nq_input_id: String,
    pub subject: OperationalSubjectV1,
    pub subject_identity_digest: String,
    pub producer: ProducerPrincipalV1,
    pub producer_identity_digest: String,
    pub acquisition_outcome: AcquisitionOutcomeV1,
    pub acquisition_started_at: String,
    pub acquisition_ended_at: String,
    pub producer_observed_at: Option<String>,
    pub receiver_custody_at: String,
    pub nq_qualified_at: String,
    pub nightshift_admitted_at: String,
    pub epoch: String,
    pub sequence: u64,
    pub predecessor_observation_digest: Option<String>,
    pub payload_schema: Option<String>,
    pub claim_support: Vec<ClaimSupportV1>,
    pub cannot_testify: Vec<CannotTestifyV1>,
    pub refusals: Vec<RefusalV1>,
    pub contradictions: Vec<ContradictionV1>,
    pub nonclaims: Vec<String>,
}

impl OperationalObservationLineageV1 {
    pub fn computed_lineage_id(&self) -> Result<String, String> {
        object_id(self, "lineage_id")
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != OPERATIONAL_LINEAGE_SCHEMA_V1
            || self.monitor_result_head != FIELD_CLOCK_MONITOR_RESULT_HEAD
            || self.nq_result_head != FIELD_CLOCK_NQ_RESULT_HEAD
        {
            return Err("lineage schema or FIELD result-head pin mismatch".into());
        }
        digest("lineage_id", &self.lineage_id)?;
        custody(&self.monitor_custody)?;
        custody(&self.nq_custody)?;
        self.subject.validate()?;
        producer(&self.producer)?;
        digest("subject_identity_digest", &self.subject_identity_digest)?;
        digest("producer_identity_digest", &self.producer_identity_digest)?;
        if self.subject_identity_digest != monitor_subject_digest(&self.subject)?
            || self.producer_identity_digest != monitor_producer_digest(&self.producer)?
        {
            return Err("embedded operational subject or producer identity mismatch".into());
        }
        token("nq_profile_id", &self.nq_profile_id)?;
        token("nq_input_id", &self.nq_input_id)?;
        token("epoch", &self.epoch)?;
        match (self.sequence, &self.predecessor_observation_digest) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => {
                return Err("sequence and predecessor are inconsistent".into())
            }
            (_, Some(value)) => digest("predecessor_observation_digest", value)?,
        }
        let start = time("acquisition_started_at", &self.acquisition_started_at)?;
        let end = time("acquisition_ended_at", &self.acquisition_ended_at)?;
        let receiver = time("receiver_custody_at", &self.receiver_custody_at)?;
        let nq = time("nq_qualified_at", &self.nq_qualified_at)?;
        let admitted = time("nightshift_admitted_at", &self.nightshift_admitted_at)?;
        if start > end || receiver < end || nq < receiver || admitted < nq {
            return Err("operational lineage time ordering is invalid".into());
        }
        match self.acquisition_outcome {
            AcquisitionOutcomeV1::ObservationProduced => {
                let observed = time(
                    "producer_observed_at",
                    self.producer_observed_at
                        .as_deref()
                        .ok_or_else(|| "produced observation lacks producer time".to_owned())?,
                )?;
                if observed < start || observed > end || self.payload_schema.is_none() {
                    return Err("produced observation time or payload schema is invalid".into());
                }
            }
            _ if self.producer_observed_at.is_some()
                || self.payload_schema.is_some()
                || !self.claim_support.is_empty() =>
            {
                return Err("failed acquisition was promoted into world testimony".into());
            }
            _ => {}
        }
        findings(self)?;
        if self.nonclaims != NONCLAIMS.into_iter().map(str::to_owned).collect::<Vec<_>>() {
            return Err("lineage nonclaims changed".into());
        }
        if self.lineage_id != self.computed_lineage_id()? {
            return Err("lineage identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDispositionV1 {
    Admitted,
    ExactReplay,
}

pub fn admit_operational_lineage(
    monitor_bytes: &[u8],
    nq_bytes: &[u8],
    nq_input_id: &str,
    admitted_at: DateTime<Utc>,
    history: &[OperationalObservationLineageV1],
) -> Result<(OperationalObservationLineageV1, AdmissionDispositionV1), String> {
    if monitor_bytes.is_empty()
        || nq_bytes.is_empty()
        || monitor_bytes.len() > MAX_RAW_BYTES
        || nq_bytes.len() > MAX_RAW_BYTES
    {
        return Err("source bytes are empty or exceed one MiB".into());
    }
    if history.len() > MAX_COLLECTION {
        return Err("lineage history exceeds its bound".into());
    }
    let monitor: SignedMonitorV1 =
        serde_json::from_slice(monitor_bytes).map_err(|error| format!("Monitor bytes: {error}"))?;
    let body_bytes = extract_object_field(monitor_bytes, "body")?;
    validate_monitor(&monitor, body_bytes)?;
    let nq: NqArtifactV1 =
        serde_json::from_slice(nq_bytes).map_err(|error| format!("NQ bytes: {error}"))?;
    validate_nq(&nq)?;
    let input = nq
        .inputs
        .iter()
        .find(|value| value.input_id == nq_input_id)
        .ok_or_else(|| "selected NQ input is absent".to_owned())?;
    bind_input(input, monitor_bytes, body_bytes, &monitor)?;
    let observation_digest = monitor_observation_digest(body_bytes);
    let subject_digest = monitor_subject_digest(&monitor.body.subject)?;
    let producer_digest = monitor_producer_digest(&monitor.body.producer)?;
    let contradictions = nq
        .contradictions
        .iter()
        .filter(|value| value.subject_identity_digest == subject_digest)
        .cloned()
        .collect();
    let mut record = OperationalObservationLineageV1 {
        schema: OPERATIONAL_LINEAGE_SCHEMA_V1.into(),
        lineage_id: String::new(),
        monitor_result_head: FIELD_CLOCK_MONITOR_RESULT_HEAD.into(),
        nq_result_head: FIELD_CLOCK_NQ_RESULT_HEAD.into(),
        monitor_custody: ExactArtifactCustodyV1 {
            raw_bytes_sha256: sha256(monitor_bytes),
            raw_bytes_length: monitor_bytes.len() as u64,
            semantic_digest: observation_digest,
        },
        nq_custody: ExactArtifactCustodyV1 {
            raw_bytes_sha256: sha256(nq_bytes),
            raw_bytes_length: nq_bytes.len() as u64,
            semantic_digest: jcs_digest(&nq)?,
        },
        nq_profile_id: nq.profile_id,
        nq_input_id: input.input_id.clone(),
        subject: monitor.body.subject.clone(),
        subject_identity_digest: subject_digest,
        producer: monitor.body.producer.clone(),
        producer_identity_digest: producer_digest,
        acquisition_outcome: monitor.body.acquisition.outcome,
        acquisition_started_at: monitor.body.acquisition.started_at,
        acquisition_ended_at: monitor.body.acquisition.ended_at,
        producer_observed_at: monitor.body.producer_observed_at,
        receiver_custody_at: canonical_time(input.receiver_custody_at),
        nq_qualified_at: canonical_time(nq.evaluated_at),
        nightshift_admitted_at: canonical_time(admitted_at),
        epoch: monitor.body.lineage.epoch,
        sequence: monitor.body.lineage.sequence,
        predecessor_observation_digest: monitor.body.lineage.predecessor_observation_digest,
        payload_schema: monitor.body.payload_schema,
        claim_support: input.claim_support.clone(),
        cannot_testify: input.cannot_testify.clone(),
        refusals: input.refusals.clone(),
        contradictions,
        nonclaims: NONCLAIMS.into_iter().map(str::to_owned).collect(),
    };
    record.lineage_id = record.computed_lineage_id()?;
    record.validate()?;
    admit_history(history, record)
}

fn admit_history(
    history: &[OperationalObservationLineageV1],
    candidate: OperationalObservationLineageV1,
) -> Result<(OperationalObservationLineageV1, AdmissionDispositionV1), String> {
    for value in history {
        value.validate()?;
        if value.monitor_custody == candidate.monitor_custody
            && value.nq_custody == candidate.nq_custody
            && value.nq_input_id == candidate.nq_input_id
        {
            return Ok((value.clone(), AdmissionDispositionV1::ExactReplay));
        }
        if value.subject_identity_digest == candidate.subject_identity_digest
            && value.producer_identity_digest == candidate.producer_identity_digest
            && value.epoch == candidate.epoch
            && value.sequence == candidate.sequence
        {
            return Err("operational lineage fork refused".into());
        }
    }
    if candidate.sequence > 0 {
        let predecessor = history
            .iter()
            .find(|value| {
                value.subject_identity_digest == candidate.subject_identity_digest
                    && value.producer_identity_digest == candidate.producer_identity_digest
                    && value.epoch == candidate.epoch
                    && value.sequence.checked_add(1) == Some(candidate.sequence)
            })
            .ok_or_else(|| "operational lineage predecessor is absent".to_owned())?;
        if candidate.predecessor_observation_digest.as_ref()
            != Some(&predecessor.monitor_custody.semantic_digest)
        {
            return Err("operational lineage predecessor binding mismatch".into());
        }
    }
    Ok((candidate, AdmissionDispositionV1::Admitted))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReobservationProfileV1 {
    pub profile_id: String,
    pub max_age_seconds: u64,
}

impl ReobservationProfileV1 {
    pub fn semantic_digest(&self) -> Result<String, String> {
        token("profile_id", &self.profile_id)?;
        if self.max_age_seconds == 0 || self.max_age_seconds > MAX_AGE_SECONDS {
            return Err("max age is zero or exceeds 31 days".into());
        }
        jcs_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReobservationDispositionV1 {
    Current,
    Stale,
    AcquisitionFailure,
    CannotTestify,
    Refused,
    Contradictory,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReobservationTriggerV1 {
    None,
    MaxAgeElapsed,
    AcquisitionFailure,
    NoSupportedClaims,
    QualificationRefusal,
    ClaimContradiction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NextLawfulActionV1 {
    AwaitCurrentnessChange,
    RequestReobservation,
    RequestQualificationReview,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalReobservationEvaluationV1 {
    pub schema: String,
    pub evaluation_id: String,
    pub lineage_id: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub max_age_seconds: u64,
    pub evaluated_at: String,
    pub current_until: Option<String>,
    pub exact_supported_claim_ids: Vec<String>,
    pub disposition: ReobservationDispositionV1,
    pub reobservation_trigger: ReobservationTriggerV1,
    pub next_lawful_action: NextLawfulActionV1,
    pub grants_authority: bool,
}

impl OperationalReobservationEvaluationV1 {
    pub fn computed_evaluation_id(&self) -> Result<String, String> {
        object_id(self, "evaluation_id")
    }

    pub fn validate_against(
        &self,
        lineage: &OperationalObservationLineageV1,
        profile: &ReobservationProfileV1,
    ) -> Result<(), String> {
        lineage.validate()?;
        if self.schema != REOBSERVATION_EVALUATION_SCHEMA_V1
            || self.lineage_id != lineage.lineage_id
            || self.profile_id != profile.profile_id
            || self.profile_digest != profile.semantic_digest()?
            || self.max_age_seconds != profile.max_age_seconds
            || self.grants_authority
        {
            return Err("evaluation binding is invalid".into());
        }
        digest("evaluation_id", &self.evaluation_id)?;
        ordered(
            "exact_supported_claim_ids",
            &self.exact_supported_claim_ids,
            true,
        )?;
        let supported = lineage
            .claim_support
            .iter()
            .map(|value| value.claim_id.as_str())
            .collect::<BTreeSet<_>>();
        if self
            .exact_supported_claim_ids
            .iter()
            .any(|value| !supported.contains(value.as_str()))
        {
            return Err("evaluation widened NQ claim support".into());
        }
        let evaluated = time("evaluated_at", &self.evaluated_at)?;
        let expected = evaluation_state(lineage, profile, evaluated)?;
        if self.current_until != expected.0
            || self.disposition != expected.1
            || self.reobservation_trigger != expected.2
            || self.next_lawful_action != expected.3
        {
            return Err("re-observation disposition does not match exact lineage and time".into());
        }
        if self.evaluation_id != self.computed_evaluation_id()? {
            return Err("evaluation identity mismatch".into());
        }
        Ok(())
    }
}

pub fn evaluate_reobservation(
    lineage: &OperationalObservationLineageV1,
    profile: &ReobservationProfileV1,
    evaluated_at: DateTime<Utc>,
) -> Result<OperationalReobservationEvaluationV1, String> {
    lineage.validate()?;
    let profile_digest = profile.semantic_digest()?;
    let claim_ids = lineage
        .claim_support
        .iter()
        .map(|value| value.claim_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let state = evaluation_state(lineage, profile, evaluated_at)?;
    let mut result = OperationalReobservationEvaluationV1 {
        schema: REOBSERVATION_EVALUATION_SCHEMA_V1.into(),
        evaluation_id: String::new(),
        lineage_id: lineage.lineage_id.clone(),
        profile_id: profile.profile_id.clone(),
        profile_digest,
        max_age_seconds: profile.max_age_seconds,
        evaluated_at: canonical_time(evaluated_at),
        current_until: state.0,
        exact_supported_claim_ids: claim_ids,
        disposition: state.1,
        reobservation_trigger: state.2,
        next_lawful_action: state.3,
        grants_authority: false,
    };
    result.evaluation_id = result.computed_evaluation_id()?;
    result.validate_against(lineage, profile)?;
    Ok(result)
}

fn evaluation_state(
    lineage: &OperationalObservationLineageV1,
    profile: &ReobservationProfileV1,
    evaluated_at: DateTime<Utc>,
) -> Result<
    (
        Option<String>,
        ReobservationDispositionV1,
        ReobservationTriggerV1,
        NextLawfulActionV1,
    ),
    String,
> {
    let admitted = time("nightshift_admitted_at", &lineage.nightshift_admitted_at)?;
    if evaluated_at < admitted {
        return Err("re-observation evaluation precedes Nightshift admission".into());
    }
    if lineage.acquisition_outcome != AcquisitionOutcomeV1::ObservationProduced {
        return Ok((
            None,
            ReobservationDispositionV1::AcquisitionFailure,
            ReobservationTriggerV1::AcquisitionFailure,
            NextLawfulActionV1::RequestReobservation,
        ));
    }
    if !lineage.refusals.is_empty() {
        return Ok((
            None,
            ReobservationDispositionV1::Refused,
            ReobservationTriggerV1::QualificationRefusal,
            NextLawfulActionV1::RequestQualificationReview,
        ));
    }
    if !lineage.contradictions.is_empty() {
        return Ok((
            None,
            ReobservationDispositionV1::Contradictory,
            ReobservationTriggerV1::ClaimContradiction,
            NextLawfulActionV1::RequestQualificationReview,
        ));
    }
    if lineage.claim_support.is_empty() {
        return Ok((
            None,
            ReobservationDispositionV1::CannotTestify,
            ReobservationTriggerV1::NoSupportedClaims,
            NextLawfulActionV1::RequestReobservation,
        ));
    }
    let observed = time(
        "producer_observed_at",
        lineage
            .producer_observed_at
            .as_deref()
            .ok_or_else(|| "produced lineage lacks producer time".to_owned())?,
    )?;
    let seconds = i64::try_from(profile.max_age_seconds)
        .map_err(|_| "max age exceeds duration".to_owned())?;
    let until = observed
        .checked_add_signed(Duration::seconds(seconds))
        .ok_or_else(|| "currentness horizon overflow".to_owned())?;
    if evaluated_at < until {
        Ok((
            Some(canonical_time(until)),
            ReobservationDispositionV1::Current,
            ReobservationTriggerV1::None,
            NextLawfulActionV1::AwaitCurrentnessChange,
        ))
    } else {
        Ok((
            Some(canonical_time(until)),
            ReobservationDispositionV1::Stale,
            ReobservationTriggerV1::MaxAgeElapsed,
            NextLawfulActionV1::RequestReobservation,
        ))
    }
}

fn validate_monitor(value: &SignedMonitorV1, body_bytes: &[u8]) -> Result<(), String> {
    let body = &value.body;
    if body.schema != MONITOR_OPERATIONAL_SCHEMA_V1
        || value.signature_domain != MONITOR_SIGNATURE_DOMAIN_V1
        || body.grants_authority
    {
        return Err("Monitor schema, signature domain, or authority boundary is invalid".into());
    }
    body.subject.validate()?;
    producer(&body.producer)?;
    if value.signer_key_identity_digest != monitor_producer_digest(&body.producer)? {
        return Err("Monitor signer identity mismatch".into());
    }
    monitor_token("attempt_id", &body.acquisition.attempt_id)?;
    monitor_token("diagnostic_code", &body.acquisition.diagnostic_code)?;
    if let Some(value) = &body.acquisition.raw_basis_digest {
        digest("raw_basis_digest", value)?;
    }
    let start = time("started_at", &body.acquisition.started_at)?;
    let end = time("ended_at", &body.acquisition.ended_at)?;
    if start > end {
        return Err("Monitor acquisition time inversion".into());
    }
    monitor_token("epoch", &body.lineage.epoch)?;
    match (
        body.lineage.sequence,
        &body.lineage.predecessor_observation_digest,
    ) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => return Err("Monitor lineage shape is invalid".into()),
        (_, Some(value)) => digest("predecessor", value)?,
    }
    coverage(&body.coverage)?;
    match body.acquisition.outcome {
        AcquisitionOutcomeV1::ObservationProduced => {
            let observed = time(
                "producer_observed_at",
                body.producer_observed_at
                    .as_deref()
                    .ok_or_else(|| "produced record lacks observation time".to_owned())?,
            )?;
            if observed < start || observed > end {
                return Err("producer time outside acquisition".into());
            }
            monitor_token(
                "payload_schema",
                body.payload_schema
                    .as_deref()
                    .ok_or_else(|| "produced record lacks payload schema".to_owned())?,
            )?;
            content(
                body.payload
                    .as_ref()
                    .ok_or_else(|| "produced record lacks payload custody".to_owned())?,
            )?;
        }
        _ if body.producer_observed_at.is_some()
            || body.payload_schema.is_some()
            || body.payload.is_some()
            || !body.coverage.observed_dimensions.is_empty() =>
        {
            return Err("failed acquisition carries world testimony".into());
        }
        _ => {}
    }
    if body.attachments.len() > MONITOR_MAX_COLLECTION
        || body.locators.len() > MONITOR_MAX_COLLECTION
    {
        return Err("Monitor locators or attachments exceed 32".into());
    }
    for item in &body.attachments {
        content(item)?;
    }
    for item in &body.locators {
        monitor_text("locator.value", &item.value)?;
        time("locator.observed_at", &item.observed_at)?;
    }
    let key: [u8; 32] = lower_hex(&body.producer.public_key_hex, 32, "public key")?
        .try_into()
        .map_err(|_| "public key length".to_owned())?;
    let signature: [u8; 64] = lower_hex(&value.signature_hex, 64, "signature")?
        .try_into()
        .map_err(|_| "signature length".to_owned())?;
    let verifying = VerifyingKey::from_bytes(&key).map_err(|_| "public key encoding".to_owned())?;
    verifying
        .verify_strict(
            &signature_transcript(body_bytes),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| "strict Monitor Ed25519 verification failed".to_owned())
}

fn validate_nq(value: &NqArtifactV1) -> Result<(), String> {
    if value.schema != NQ_OPERATIONAL_QUALIFICATION_SCHEMA_V1
        || value.monitor_contract_head != FIELD_CLOCK_MONITOR_RESULT_HEAD
    {
        return Err("NQ schema or Monitor result pin mismatch".into());
    }
    token("profile_id", &value.profile_id)?;
    if value.inputs.is_empty() || value.inputs.len() > MAX_COLLECTION {
        return Err("NQ input count invalid".into());
    }
    let mut ids = BTreeSet::new();
    for input in &value.inputs {
        token("input_id", &input.input_id)?;
        digest("raw_record_digest", &input.raw_record_digest)?;
        if !ids.insert(input.input_id.as_str()) {
            return Err("duplicate NQ input".into());
        }
        validate_nq_findings(input, value.evaluated_at)?;
    }
    let mut complete_claim_domain: Option<Vec<&str>> = None;
    for input in &value.inputs {
        if nq_input_is_reopened(input) && input.refusals.is_empty() {
            let domain = input
                .claim_support
                .iter()
                .map(|claim| claim.claim_id.as_str())
                .chain(
                    input
                        .cannot_testify
                        .iter()
                        .map(|finding| finding.claim_id.as_str()),
                )
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            match &complete_claim_domain {
                Some(expected) if *expected != domain => {
                    return Err(
                        "NQ non-refused inputs differ from the complete ordered claim domain"
                            .into(),
                    )
                }
                None => complete_claim_domain = Some(domain),
                _ => {}
            }
        }
    }
    let mut contradiction_ids = BTreeSet::new();
    for item in &value.contradictions {
        token("contradiction.claim_id", &item.claim_id)?;
        digest("contradiction.subject", &item.subject_identity_digest)?;
        digest("contradiction.first_value", &item.first_value_digest)?;
        digest("contradiction.second_value", &item.second_value_digest)?;
        if item.first_input_id == item.second_input_id
            || item.first_value_digest == item.second_value_digest
            || !contradiction_ids.insert((
                item.subject_identity_digest.as_str(),
                item.claim_id.as_str(),
                item.first_input_id.as_str(),
                item.second_input_id.as_str(),
            ))
        {
            return Err("NQ contradiction identity or values are invalid".into());
        }
        let first = value
            .inputs
            .iter()
            .find(|input| input.input_id == item.first_input_id)
            .ok_or_else(|| "contradiction first input is unknown".to_owned())?;
        let second = value
            .inputs
            .iter()
            .find(|input| input.input_id == item.second_input_id)
            .ok_or_else(|| "contradiction second input is unknown".to_owned())?;
        if first.subject_identity_digest.as_deref() != Some(item.subject_identity_digest.as_str())
            || second.subject_identity_digest.as_deref()
                != Some(item.subject_identity_digest.as_str())
            || !claim_value_is(first, &item.claim_id, &item.first_value_digest)
            || !claim_value_is(second, &item.claim_id, &item.second_value_digest)
        {
            return Err("NQ contradiction does not bind exact input claim values".into());
        }
    }
    if value.contradictions != expected_nq_contradictions(&value.inputs) {
        return Err("NQ contradiction graph differs from qualify_one closure".into());
    }
    if value.nonclaims
        != NQ_NONCLAIMS
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    {
        return Err("NQ operational nonclaims changed".into());
    }
    Ok(())
}

fn validate_nq_findings(input: &NqInputV1, evaluated_at: DateTime<Utc>) -> Result<(), String> {
    if input.claim_support.len() > MAX_COLLECTION
        || input.cannot_testify.len() > MAX_COLLECTION
        || input.refusals.len() > 1
    {
        return Err("NQ input finding collection or refusal count is invalid".into());
    }
    if let Some(value) = &input.monitor_record_digest {
        digest("monitor_record_digest", value)?;
    }
    if let Some(value) = &input.subject_identity_digest {
        digest("subject_identity_digest", value)?;
    }
    if let Some(value) = &input.producer_identity_digest {
        digest("producer_identity_digest", value)?;
    }
    if let Some(value) = &input.producer_principal_id {
        token("producer_principal_id", value)?;
    }
    if let Some(value) = &input.producer_class {
        token("producer_class", value)?;
    }
    if let Some(value) = &input.payload_schema {
        token("payload_schema", value)?;
    }
    let reopened = [
        input.monitor_record_digest.is_some(),
        input.subject_identity_digest.is_some(),
        input.producer_identity_digest.is_some(),
        input.producer_principal_id.is_some(),
        input.producer_class.is_some(),
        input.acquisition_outcome.is_some(),
    ];
    if reopened.iter().any(|present| *present) && !reopened.iter().all(|present| *present) {
        return Err("NQ reopened Monitor identity tuple is partial".into());
    }
    let outcome = input.acquisition_outcome.as_deref();
    if let Some(value) = outcome {
        if ![
            "observation_produced",
            "no_response",
            "command_failed",
            "producer_unavailable",
            "receiver_unavailable",
            "malformed_input",
            "refused",
        ]
        .contains(&value)
        {
            return Err("NQ acquisition outcome is outside FIELD".into());
        }
        if value == "observation_produced" {
            if input.producer_observed_at.is_none() || input.payload_schema.is_none() {
                return Err("NQ produced input lacks producer time or payload schema".into());
            }
        } else if input.producer_observed_at.is_some() || input.payload_schema.is_some() {
            return Err("NQ failed input carries produced testimony metadata".into());
        }
    } else if input.producer_observed_at.is_some() || input.payload_schema.is_some() {
        return Err("NQ unopened input carries Monitor testimony metadata".into());
    }
    let mut support_ids = BTreeSet::new();
    for claim in &input.claim_support {
        token("claim_id", &claim.claim_id)?;
        text("proposition", &claim.proposition)?;
        digest("value_digest", &claim.value_digest)?;
        let expected_monitor = input
            .monitor_record_digest
            .as_deref()
            .ok_or_else(|| "claim support lacks a Monitor record identity".to_owned())?;
        if claim.monitor_record_digest != expected_monitor
            || !support_ids.insert(claim.claim_id.as_str())
        {
            return Err("NQ claim support binding or identity is invalid".into());
        }
    }
    let mut cannot_ids = BTreeSet::new();
    for finding in &input.cannot_testify {
        token("cannot_testify.claim_id", &finding.claim_id)?;
        text("cannot_testify.reason", &finding.reason)?;
        if support_ids.contains(finding.claim_id.as_str())
            || !cannot_ids.insert(finding.claim_id.as_str())
        {
            return Err("NQ cannot-testify overlaps or duplicates claim support".into());
        }
    }
    for refusal in &input.refusals {
        token("refusal.code", &refusal.code)?;
        text("refusal.detail", &refusal.detail)?;
        digest("refusal.exact_basis_digest", &refusal.exact_basis_digest)?;
        if refusal.exact_basis_digest != input.raw_record_digest {
            return Err("NQ refusal does not bind exact input bytes".into());
        }
    }
    let is_reopened = reopened.iter().all(|present| *present);
    if let Some(refusal) = input.refusals.first() {
        let admitted_codes = if is_reopened {
            NQ_REOPENED_REFUSAL_CODES.as_slice()
        } else {
            NQ_UNOPENED_REFUSAL_CODES.as_slice()
        };
        if !admitted_codes.contains(&refusal.code.as_str()) {
            return Err("NQ refusal code does not match its reopened/unopened branch".into());
        }
        let expected_detail = match refusal.code.as_str() {
            "receiver_custody_inversion" => {
                Some("receiver custody precedes completion of the signed acquisition")
            }
            "evaluation_time_inversion" => Some("NQ evaluation precedes receiver custody"),
            "subject_identity_mismatch" => {
                Some("subject is outside the exact qualification profile")
            }
            "producer_identity_mismatch" => {
                Some("producer is outside the exact qualification profile")
            }
            "payload_custody_missing" => Some("produced observation lacks reopened payload bytes"),
            _ => None,
        };
        if expected_detail.is_some_and(|detail| refusal.detail != detail) {
            return Err("NQ reopened refusal detail differs from qualify_one".into());
        }
        if !is_reopened {
            validate_nq_unopened_refusal_detail(&refusal.code, &refusal.detail)?;
        }
    }
    let evaluation_inverted = evaluated_at < input.receiver_custody_at;
    let evaluation_refusal = input
        .refusals
        .first()
        .is_some_and(|refusal| refusal.code == "evaluation_time_inversion");
    if is_reopened && evaluation_inverted != evaluation_refusal {
        return Err(
            "NQ evaluation/receiver time ordering does not match qualify_one refusal".into(),
        );
    }
    match (is_reopened, input.refusals.is_empty()) {
        (false, false) => {
            if !input.claim_support.is_empty() || !input.cannot_testify.is_empty() {
                return Err("NQ unopened refusal carries qualification findings".into());
            }
        }
        (false, true) => return Err("NQ unopened input lacks its exact refusal".into()),
        (true, false) => {
            if !input.claim_support.is_empty() || !input.cannot_testify.is_empty() {
                return Err("NQ refusal is mixed with support or cannot-testify".into());
            }
        }
        (true, true) => {
            if input.claim_support.is_empty() && input.cannot_testify.is_empty() {
                return Err("NQ non-refused input has no qualification finding".into());
            }
            if outcome != Some("observation_produced")
                && (!input.claim_support.is_empty() || input.cannot_testify.is_empty())
            {
                return Err("NQ failed acquisition has an impossible finding shape".into());
            }
            if let Some(outcome) = outcome.filter(|value| *value != "observation_produced") {
                let expected =
                    format!("Monitor acquisition outcome {outcome} produced no world testimony");
                if input
                    .cannot_testify
                    .iter()
                    .any(|finding| finding.reason != expected)
                {
                    return Err(
                        "NQ failed-acquisition cannot-testify reason differs from qualify_one"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn nq_input_is_reopened(input: &NqInputV1) -> bool {
    input.monitor_record_digest.is_some()
        && input.subject_identity_digest.is_some()
        && input.producer_identity_digest.is_some()
        && input.producer_principal_id.is_some()
        && input.producer_class.is_some()
        && input.acquisition_outcome.is_some()
}

fn validate_nq_unopened_refusal_detail(code: &str, detail: &str) -> Result<(), String> {
    let exact = |values: &[&str]| values.contains(&detail);
    let field_form = |fields: &[&str], suffixes: &[&str]| {
        fields.iter().any(|field| {
            suffixes
                .iter()
                .any(|suffix| detail == format!("{field}{suffix}"))
        })
    };
    let valid = match code {
        "record_oversized" => exact(&["signed Monitor record exceeds one MiB"]),
        "record_malformed" | "body_malformed" => {
            nq_serde_json_error_detail(detail, Some(MAX_RAW_BYTES + 1), Some(MAX_RAW_BYTES))
        }
        "payload_malformed" => nq_serde_json_error_detail(detail, None, None),
        "field_missing" => ["body", "producer", "subject"]
            .iter()
            .any(|field| detail == format!("missing exact field {field}")),
        "field_malformed" => ["body", "producer", "subject"]
            .iter()
            .any(|field| detail == format!("field {field} object is unterminated")),
        "closed_schema_violation" => exact(&["JSON object keys differ from closed contract"]),
        "field_type" => {
            field_form(
                &[
                    "producer",
                    "subject",
                    "acquisition",
                    "lineage",
                    "coverage",
                    "stable_basis",
                    "payload",
                ],
                &[" is not an object"],
            ) || field_form(
                &[
                    "schema",
                    "kind",
                    "value",
                    "observed_at",
                    "namespace",
                    "basis_contract",
                    "basis_type",
                    "machine_identity",
                    "service_identity",
                    "instance_identity",
                    "deployment_identity",
                    "release_identity",
                    "repository_identity",
                    "revision_identity",
                    "scheduler_identity",
                    "job_identity",
                    "design_identity",
                    "toolchain_identity",
                    "pdk_identity",
                    "entitlement_identity",
                    "worker_identity",
                    "artifact_set_identity",
                    "run_identity",
                    "stage_occurrence_identity",
                    "attempt_id",
                    "started_at",
                    "ended_at",
                    "outcome",
                    "diagnostic_code",
                    "epoch",
                    "payload_schema",
                    "media_type",
                    "digest_domain",
                    "digest",
                    "principal_id",
                    "collector_id",
                    "key_algorithm",
                    "public_key_hex",
                    "public_key_digest",
                    "producer_class",
                    "signer_key_identity_digest",
                    "signature_domain",
                    "signature_hex",
                ],
                &[" is not a string"],
            ) || field_form(
                &[
                    "locators",
                    "attachments",
                    "expected_dimensions",
                    "observed_dimensions",
                    "omitted_dimensions",
                ],
                &[" is not an array"],
            ) || field_form(
                &[
                    "expected_dimensions",
                    "observed_dimensions",
                    "omitted_dimensions",
                ],
                &[" contains a non-string"],
            ) || exact(&["raw basis digest is not a string"])
                || ["body", "producer", "subject"]
                    .iter()
                    .any(|field| detail == format!("field {field} is not an object"))
        }
        "object_expected" => exact(&["JSON value is not an object"]),
        "schema_unknown" => exact(&["Monitor operational schema is unsupported"]),
        "authority_present" => exact(&["Monitor testimony cannot grant authority"]),
        "invalid_text" => field_form(
            &[
                "subject namespace",
                "locator value",
                "acquisition attempt",
                "acquisition diagnostic",
                "observation epoch",
                "payload schema",
                "content media type",
                "producer principal",
                "collector identity",
                "producer class",
                "expected coverage",
                "observed coverage",
                "omitted coverage",
                "locator observation time",
                "acquisition start",
                "acquisition end",
                "producer observation time",
            ],
            &[" is invalid"],
        ),
        "invalid_token" => field_form(
            &[
                "subject namespace",
                "acquisition attempt",
                "acquisition diagnostic",
                "observation epoch",
                "payload schema",
                "content media type",
                "producer principal",
                "collector identity",
                "producer class",
                "expected coverage",
                "observed coverage",
                "omitted coverage",
            ],
            &[" contains whitespace"],
        ),
        "subject_kind_unknown" => exact(&["Monitor subject kind is outside the closed contract"]),
        "unsupported_subject_basis_contract" => {
            exact(&["subject stable-basis contract is not the family-owned v1 contract"])
        }
        "subject_basis_kind_mismatch" => exact(&["subject kind and stable-basis contract differ"]),
        "invalid_collection" => exact(&[
            "locators is oversized",
            "attachments is oversized",
            "expected coverage is empty or oversized",
            "observed coverage is empty or oversized",
            "omitted coverage is empty or oversized",
        ]),
        "noncanonical_collection" => exact(&[
            "expected coverage must be sorted and unique",
            "observed coverage must be sorted and unique",
            "omitted coverage must be sorted and unique",
        ]),
        "locator_kind_unknown" => exact(&["locator kind is unsupported"]),
        "timestamp_noncanonical" => field_form(
            &[
                "locator observation time",
                "acquisition start",
                "acquisition end",
                "producer observation time",
            ],
            &[" is not canonical UTC RFC3339"],
        ),
        "timestamp_invalid" => nq_timestamp_error_detail(detail),
        "digest_invalid" => field_form(
            &[
                "raw acquisition basis",
                "predecessor observation",
                "stable subject basis",
                "content digest",
            ],
            &[
                " lacks sha256 prefix",
                " is not a canonical nonzero sha256 digest",
            ],
        ),
        "timestamp_inversion" => exact(&["acquisition end precedes start"]),
        "acquisition_outcome_unknown" => {
            exact(&["Monitor acquisition outcome is outside the closed contract"])
        }
        "lineage_invalid" => exact(&[
            "observation sequence is not unsigned",
            "sequence and predecessor observation are inconsistent",
        ]),
        "coverage_invalid" => exact(&["coverage is inconsistent with its exact denominator"]),
        "coverage_incomplete" => {
            exact(&["every expected dimension must be observed or explicitly omitted"])
        }
        "content_length_invalid" => exact(&["content byte length is absent or zero"]),
        "observation_time_missing" => exact(&["produced observation lacks producer time"]),
        "observation_time_inversion" => {
            exact(&["producer observation time falls outside acquisition"])
        }
        "failure_as_world_claim" => exact(&[
            "failed acquisition carries world testimony or observed coverage",
            "failed acquisition carries payload testimony",
        ]),
        "key_algorithm_unknown" => exact(&["producer key algorithm is unsupported"]),
        "public_key_malformed" => exact(&[
            "producer public key is not exact lowercase hex",
            "public key length is invalid",
            "Cannot decompress Edwards point",
        ]),
        "producer_key_mismatch" => exact(&["producer public key identity is invalid"]),
        "signer_identity_mismatch" => exact(&["signature does not bind exact producer principal"]),
        "signature_domain_mismatch" => exact(&["signature domain is unsupported"]),
        "signature_malformed" => exact(&[
            "signature is not exact lowercase hex",
            "signature length is invalid",
        ]),
        "signature_invalid" => exact(&["strict Ed25519 verification failed"]),
        "payload_digest_law_unknown" => exact(&[
            "content digest domain is unsupported",
            "payload digest domain is unsupported",
        ]),
        "payload_missing" => exact(&[
            "produced observation lacks payload custody",
            "exact payload bytes were not supplied",
        ]),
        "payload_substitution" => exact(&["payload bytes do not match exact Monitor custody"]),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("NQ unopened refusal detail differs from pinned reopen law".into())
    }
}

fn nq_serde_json_error_detail(
    detail: &str,
    maximum_line: Option<usize>,
    maximum_column: Option<usize>,
) -> bool {
    let Some((message, position)) = detail.rsplit_once(" at line ") else {
        return false;
    };
    let Some((line, column)) = position.split_once(" column ") else {
        return false;
    };
    let coordinate = |value: &str, allow_zero: bool, maximum: Option<usize>| {
        let Ok(number) = value.parse::<usize>() else {
            return false;
        };
        (allow_zero || number > 0)
            && maximum.is_none_or(|maximum| number <= maximum)
            && value == number.to_string()
    };
    if !coordinate(line, false, maximum_line) || !coordinate(column, true, maximum_column) {
        return false;
    }
    [
        "EOF while parsing a list",
        "EOF while parsing an object",
        "EOF while parsing a string",
        "EOF while parsing a value",
        "control character (\\u0000-\\u001F) found while parsing a string",
        "expected `,` or `]`",
        "expected `,` or `}`",
        "expected `:`",
        "expected `\"`",
        "expected ident",
        "expected value",
        "invalid escape",
        "invalid number",
        "number out of range",
        "invalid unicode code point",
        "key must be a string",
        "lone leading surrogate in hex escape",
        "recursion limit exceeded",
        "trailing comma",
        "trailing characters",
        "unexpected end of hex escape",
    ]
    .contains(&message)
}

fn nq_timestamp_error_detail(detail: &str) -> bool {
    const FIELDS: [&str; 4] = [
        "locator observation time",
        "acquisition start",
        "acquisition end",
        "producer observation time",
    ];
    const ERRORS: [&str; 4] = [
        "input contains invalid characters",
        "input is out of range",
        "premature end of input",
        "trailing input",
    ];
    FIELDS.iter().any(|field| {
        ERRORS
            .iter()
            .any(|error| detail == format!("{field}: {error}"))
    })
}

fn claim_value_is(input: &NqInputV1, claim_id: &str, value_digest: &str) -> bool {
    input
        .claim_support
        .iter()
        .any(|claim| claim.claim_id == claim_id && claim.value_digest == value_digest)
}

fn expected_nq_contradictions(inputs: &[NqInputV1]) -> Vec<ContradictionV1> {
    let mut seen: BTreeMap<(&str, &str), (&str, &str)> = BTreeMap::new();
    let mut output = Vec::new();
    for input in inputs {
        let Some(subject) = input.subject_identity_digest.as_deref() else {
            continue;
        };
        for claim in &input.claim_support {
            let key = (subject, claim.claim_id.as_str());
            if let Some((prior_input, prior_value)) = seen.get(&key) {
                if *prior_value != claim.value_digest {
                    output.push(ContradictionV1 {
                        subject_identity_digest: subject.to_owned(),
                        claim_id: claim.claim_id.clone(),
                        first_input_id: (*prior_input).to_owned(),
                        first_value_digest: (*prior_value).to_owned(),
                        second_input_id: input.input_id.clone(),
                        second_value_digest: claim.value_digest.clone(),
                    });
                }
            } else {
                seen.insert(key, (&input.input_id, &claim.value_digest));
            }
        }
    }
    output
}

fn bind_input(
    input: &NqInputV1,
    raw: &[u8],
    body_bytes: &[u8],
    monitor: &SignedMonitorV1,
) -> Result<(), String> {
    let body = &monitor.body;
    let observation = monitor_observation_digest(body_bytes);
    let subject = monitor_subject_digest(&body.subject)?;
    let producer_id = monitor_producer_digest(&body.producer)?;
    if input.raw_record_digest != sha256(raw)
        || input.monitor_record_digest.as_deref() != Some(observation.as_str())
        || input.subject_identity_digest.as_deref() != Some(subject.as_str())
        || input.producer_identity_digest.as_deref() != Some(producer_id.as_str())
        || input.producer_principal_id.as_deref() != Some(body.producer.principal_id.as_str())
        || input.producer_class.as_deref() != Some(body.producer.producer_class.as_str())
        || input.acquisition_outcome.as_deref() != Some(body.acquisition.outcome.text())
        || input.payload_schema != body.payload_schema
    {
        return Err("NQ input does not bind exact Monitor semantics".into());
    }
    let observed = body
        .producer_observed_at
        .as_deref()
        .map(|value| time("producer_observed_at", value))
        .transpose()?;
    if input.producer_observed_at != observed {
        return Err("NQ producer time differs from Monitor".into());
    }
    let acquisition_ended = time("acquisition_ended_at", &body.acquisition.ended_at)?;
    let receiver_inverted = input.receiver_custody_at < acquisition_ended;
    let receiver_refusal = input
        .refusals
        .first()
        .is_some_and(|refusal| refusal.code == "receiver_custody_inversion");
    if receiver_inverted != receiver_refusal {
        return Err(
            "NQ receiver/acquisition time ordering does not match qualify_one refusal".into(),
        );
    }
    for claim in &input.claim_support {
        token("claim_id", &claim.claim_id)?;
        text("proposition", &claim.proposition)?;
        digest("value_digest", &claim.value_digest)?;
        if claim.monitor_record_digest != observation {
            return Err("claim support names another Monitor record".into());
        }
    }
    for refusal in &input.refusals {
        token("refusal.code", &refusal.code)?;
        digest("refusal.basis", &refusal.exact_basis_digest)?;
        if refusal.exact_basis_digest != input.raw_record_digest {
            return Err("refusal basis differs from Monitor bytes".into());
        }
    }
    Ok(())
}

fn producer(value: &ProducerPrincipalV1) -> Result<(), String> {
    monitor_token("principal_id", &value.principal_id)?;
    monitor_token("collector_id", &value.collector_id)?;
    monitor_token("producer_class", &value.producer_class)?;
    if value.key_algorithm != "ed25519" {
        return Err("unsupported producer key algorithm".into());
    }
    let key = lower_hex(&value.public_key_hex, 32, "public key")?;
    if value.public_key_digest != monitor_digest("operational.ed25519.public-key.v1", &[&key]) {
        return Err("producer key digest mismatch".into());
    }
    Ok(())
}

fn coverage(value: &CoverageV1) -> Result<(), String> {
    monitor_ordered("expected", &value.expected_dimensions, false)?;
    monitor_ordered("observed", &value.observed_dimensions, true)?;
    monitor_ordered("omitted", &value.omitted_dimensions, true)?;
    let observed = value.observed_dimensions.iter().collect::<BTreeSet<_>>();
    let omitted = value.omitted_dimensions.iter().collect::<BTreeSet<_>>();
    let expected = value.expected_dimensions.iter().collect::<BTreeSet<_>>();
    if !observed.is_disjoint(&omitted) || expected != observed.union(&omitted).copied().collect() {
        return Err("coverage is not an exact disjoint partition".into());
    }
    Ok(())
}

fn content(value: &ContentV1) -> Result<(), String> {
    monitor_token("media_type", &value.media_type)?;
    if value.digest_domain != MONITOR_CONTENT_DIGEST_DOMAIN_V1 || value.byte_length == 0 {
        return Err("content domain or length invalid".into());
    }
    digest("content.digest", &value.digest)
}

fn findings(value: &OperationalObservationLineageV1) -> Result<(), String> {
    if value.claim_support.len() > MAX_COLLECTION
        || value.cannot_testify.len() > MAX_COLLECTION
        || value.refusals.len() > MAX_COLLECTION
        || value.contradictions.len() > MAX_COLLECTION
    {
        return Err("finding collection exceeds bound".into());
    }
    let mut claims = BTreeSet::new();
    for item in &value.claim_support {
        token("claim_id", &item.claim_id)?;
        digest("value_digest", &item.value_digest)?;
        if item.monitor_record_digest != value.monitor_custody.semantic_digest
            || !claims.insert(item.claim_id.as_str())
        {
            return Err("claim binding or uniqueness invalid".into());
        }
    }
    for item in &value.cannot_testify {
        token("cannot_testify.claim_id", &item.claim_id)?;
        text("cannot_testify.reason", &item.reason)?;
    }
    for item in &value.refusals {
        token("refusal.code", &item.code)?;
        digest("refusal.basis", &item.exact_basis_digest)?;
        text("refusal.detail", &item.detail)?;
    }
    if value
        .contradictions
        .iter()
        .any(|item| item.subject_identity_digest != value.subject_identity_digest)
    {
        return Err("contradiction names another subject".into());
    }
    Ok(())
}

fn custody(value: &ExactArtifactCustodyV1) -> Result<(), String> {
    digest("raw_bytes_sha256", &value.raw_bytes_sha256)?;
    digest("semantic_digest", &value.semantic_digest)?;
    if value.raw_bytes_length == 0 || value.raw_bytes_length > MAX_RAW_BYTES as u64 {
        return Err("custody length invalid".into());
    }
    Ok(())
}

fn monitor_subject_digest(value: &OperationalSubjectV1) -> Result<String, String> {
    Ok(monitor_digest(
        "operational.subject.v1",
        &[&serde_json::to_vec(value).map_err(|error| error.to_string())?],
    ))
}

fn monitor_producer_digest(value: &ProducerPrincipalV1) -> Result<String, String> {
    Ok(monitor_digest(
        "operational.producer-principal.v1",
        &[&serde_json::to_vec(value).map_err(|error| error.to_string())?],
    ))
}

fn monitor_observation_digest(body_bytes: &[u8]) -> String {
    monitor_digest("operational.acquisition-record.v1", &[body_bytes])
}

fn monitor_digest(domain: &str, parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"monitor-skunkworks.digest.v1\0");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn signature_transcript(body: &[u8]) -> Vec<u8> {
    let domain = MONITOR_SIGNATURE_DOMAIN_V1.as_bytes();
    let mut result = Vec::with_capacity(2 + domain.len() + 8 + body.len());
    result.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    result.extend_from_slice(domain);
    result.extend_from_slice(&(body.len() as u64).to_be_bytes());
    result.extend_from_slice(body);
    result
}

fn object_id<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity preimage is not an object".to_owned())?
        .remove(field);
    jcs_digest(&value)
}

fn jcs_digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(sha256(
        &serde_jcs::to_vec(value).map_err(|error| error.to_string())?,
    ))
}

fn sha256(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}
fn canonical_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn time(name: &str, value: &str) -> Result<DateTime<Utc>, String> {
    if !value.ends_with('Z') {
        return Err(format!("{name} is not canonical UTC RFC3339"));
    }
    value.parse().map_err(|_| format!("{name} is not RFC3339"))
}

fn text(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 1024
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        Err(format!(
            "{name} is empty, oversized, non-ASCII, or contains controls"
        ))
    } else {
        Ok(())
    }
}

fn token(name: &str, value: &str) -> Result<(), String> {
    text(name, value)?;
    if value.chars().any(char::is_whitespace) {
        Err(format!("{name} contains whitespace"))
    } else {
        Ok(())
    }
}

fn digest(name: &str, value: &str) -> Result<(), String> {
    let Some(value) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} is not SHA-256"));
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(format!("{name} is not exact lowercase SHA-256"))
    } else {
        Ok(())
    }
}

fn ordered(name: &str, values: &[String], allow_empty: bool) -> Result<(), String> {
    if (!allow_empty && values.is_empty())
        || values.len() > MAX_COLLECTION
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(format!(
            "{name} is empty, oversized, unsorted, or duplicated"
        ));
    }
    values.iter().try_for_each(|value| token(name, value))
}

fn monitor_text(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MONITOR_MAX_TEXT_BYTES
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        Err(format!(
            "{name} is empty, exceeds 512 bytes, is non-ASCII, or contains controls"
        ))
    } else {
        Ok(())
    }
}

fn monitor_token(name: &str, value: &str) -> Result<(), String> {
    monitor_text(name, value)?;
    if value.chars().any(char::is_whitespace) {
        Err(format!("{name} contains whitespace"))
    } else {
        Ok(())
    }
}

fn monitor_ordered(name: &str, values: &[String], allow_empty: bool) -> Result<(), String> {
    if (!allow_empty && values.is_empty())
        || values.len() > MONITOR_MAX_COLLECTION
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(format!(
            "{name} is empty, exceeds 32 items, unsorted, or duplicated"
        ));
    }
    values
        .iter()
        .try_for_each(|value| monitor_token(name, value))
}

fn extract_object_field<'a>(bytes: &'a [u8], key: &str) -> Result<&'a [u8], String> {
    fn skip_ws(bytes: &[u8], mut cursor: usize) -> usize {
        while bytes
            .get(cursor)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            cursor += 1;
        }
        cursor
    }
    fn string_end(bytes: &[u8], start: usize) -> Result<usize, String> {
        if bytes.get(start) != Some(&b'"') {
            return Err("JSON object member name is not a string".into());
        }
        let mut cursor = start + 1;
        let mut escaped = false;
        while let Some(byte) = bytes.get(cursor).copied() {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return Ok(cursor + 1);
            }
            cursor += 1;
        }
        Err("unterminated JSON object member name".into())
    }

    let mut cursor = skip_ws(bytes, 0);
    if bytes.get(cursor) != Some(&b'{') {
        return Err("exact artifact root is not an object".into());
    }
    cursor += 1;
    let mut found = None;
    loop {
        cursor = skip_ws(bytes, cursor);
        if bytes.get(cursor) == Some(&b'}') {
            cursor += 1;
            break;
        }
        let name_start = cursor;
        let name_end = string_end(bytes, name_start)?;
        let name: String = serde_json::from_slice(&bytes[name_start..name_end])
            .map_err(|error| format!("JSON object member name: {error}"))?;
        cursor = skip_ws(bytes, name_end);
        if bytes.get(cursor) != Some(&b':') {
            return Err("JSON object member lacks colon".into());
        }
        let value_start = skip_ws(bytes, cursor + 1);
        let mut values =
            serde_json::Deserializer::from_slice(&bytes[value_start..]).into_iter::<IgnoredAny>();
        values
            .next()
            .ok_or_else(|| "JSON object member lacks value".to_owned())?
            .map_err(|error| format!("JSON object member value: {error}"))?;
        let value_end = value_start + values.byte_offset();
        if name == key {
            if found.is_some() {
                return Err(format!("duplicate exact object field {key}"));
            }
            if bytes.get(value_start) != Some(&b'{') {
                return Err(format!("exact field {key} is not an object"));
            }
            found = Some(&bytes[value_start..value_end]);
        }
        cursor = skip_ws(bytes, value_end);
        match bytes.get(cursor) {
            Some(b',') => cursor += 1,
            Some(b'}') => {
                cursor += 1;
                break;
            }
            _ => return Err("JSON object member lacks comma or closing brace".into()),
        }
    }
    if skip_ws(bytes, cursor) != bytes.len() {
        return Err("trailing bytes after exact artifact object".into());
    }
    found.ok_or_else(|| format!("missing exact object field {key}"))
}

fn lower_hex(value: &str, bytes: usize, name: &str) -> Result<Vec<u8>, String> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} is not exact lowercase hex"));
    }
    hex::decode(value).map_err(|_| format!("{name} cannot be decoded"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn d(value: &str) -> String {
        sha256(value.as_bytes())
    }

    fn monitor(
        outcome: AcquisitionOutcomeV1,
        sequence: u64,
        predecessor: Option<String>,
    ) -> Vec<u8> {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let public = signing.verifying_key().to_bytes();
        let produced = outcome == AcquisitionOutcomeV1::ObservationProduced;
        let producer_value = ProducerPrincipalV1 {
            principal_id: "producer:fixture".into(),
            collector_id: "collector:fixture".into(),
            key_algorithm: "ed25519".into(),
            public_key_hex: hex::encode(public),
            public_key_digest: monitor_digest("operational.ed25519.public-key.v1", &[&public]),
            producer_class: "instrumented_monitor".into(),
        };
        let body = MonitorBodyV1 {
            schema: MONITOR_OPERATIONAL_SCHEMA_V1.into(),
            producer: producer_value.clone(),
            subject: OperationalSubjectV1 {
                kind: SubjectKindV1::EcadDesignRevision,
                namespace: "fixture:ecad".into(),
                basis_contract: "monitor.subject-basis.ecad-design-revision-content/v1".into(),
                stable_basis: SubjectBasisV1::EcadDesignRevision {
                    design_identity: d("design"),
                    revision_identity: d("revision"),
                },
            },
            locators: vec![],
            acquisition: AcquisitionV1 {
                attempt_id: format!("attempt:{sequence}"),
                started_at: format!("2026-08-30T01:00:{sequence:02}Z"),
                ended_at: format!("2026-08-30T01:00:{:02}Z", sequence + 1),
                outcome,
                diagnostic_code: outcome.text().into(),
                raw_basis_digest: Some(d("raw")),
            },
            lineage: MonitorLineageV1 {
                epoch: "epoch:fixture".into(),
                sequence,
                predecessor_observation_digest: predecessor,
            },
            producer_observed_at: produced.then(|| format!("2026-08-30T01:00:{sequence:02}Z")),
            payload_schema: produced.then(|| "fixture.ecad-stage/v1".into()),
            payload: produced.then(|| ContentV1 {
                media_type: "application/json".into(),
                digest_domain: MONITOR_CONTENT_DIGEST_DOMAIN_V1.into(),
                digest: d("payload"),
                byte_length: 7,
            }),
            attachments: vec![],
            coverage: CoverageV1 {
                expected_dimensions: vec!["stage_result".into()],
                observed_dimensions: if produced {
                    vec!["stage_result".into()]
                } else {
                    vec![]
                },
                omitted_dimensions: if produced {
                    vec![]
                } else {
                    vec!["stage_result".into()]
                },
            },
            grants_authority: false,
        };
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let signature = signing.sign(&signature_transcript(&body_bytes));
        serde_json::to_vec(&SignedMonitorV1 {
            signer_key_identity_digest: monitor_producer_digest(&producer_value).unwrap(),
            signature_domain: MONITOR_SIGNATURE_DOMAIN_V1.into(),
            signature_hex: hex::encode(signature.to_bytes()),
            body,
        })
        .unwrap()
    }

    fn sign_exact_body(body_bytes: &[u8], producer: &ProducerPrincipalV1) -> Vec<u8> {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let signature = signing.sign(&signature_transcript(body_bytes));
        format!(
            "{{ \"body\" : {}, \"signature_domain\":{},\"signer_key_identity_digest\":{},\"signature_hex\":{} }}",
            std::str::from_utf8(body_bytes).unwrap(),
            serde_json::to_string(MONITOR_SIGNATURE_DOMAIN_V1).unwrap(),
            serde_json::to_string(&monitor_producer_digest(producer).unwrap()).unwrap(),
            serde_json::to_string(&hex::encode(signature.to_bytes())).unwrap(),
        )
        .into_bytes()
    }

    fn reordered_whitespace_monitor() -> Vec<u8> {
        let canonical = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let signed: SignedMonitorV1 = serde_json::from_slice(&canonical).unwrap();
        let body = &signed.body;
        let fields = [
            (
                "subject",
                serde_json::to_string_pretty(&body.subject).unwrap(),
            ),
            ("schema", serde_json::to_string(&body.schema).unwrap()),
            (
                "producer",
                serde_json::to_string_pretty(&body.producer).unwrap(),
            ),
            ("lineage", serde_json::to_string(&body.lineage).unwrap()),
            ("locators", serde_json::to_string(&body.locators).unwrap()),
            (
                "producer_observed_at",
                serde_json::to_string(&body.producer_observed_at).unwrap(),
            ),
            (
                "acquisition",
                serde_json::to_string(&body.acquisition).unwrap(),
            ),
            (
                "payload_schema",
                serde_json::to_string(&body.payload_schema).unwrap(),
            ),
            ("payload", serde_json::to_string(&body.payload).unwrap()),
            (
                "attachments",
                serde_json::to_string(&body.attachments).unwrap(),
            ),
            ("coverage", serde_json::to_string(&body.coverage).unwrap()),
            (
                "grants_authority",
                serde_json::to_string(&body.grants_authority).unwrap(),
            ),
        ];
        let body_text = format!(
            "{{\n  {}\n}}",
            fields
                .into_iter()
                .map(|(name, value)| format!("\"{name}\":{value}"))
                .collect::<Vec<_>>()
                .join(",\n  ")
        );
        sign_exact_body(body_text.as_bytes(), &body.producer)
    }

    fn subsecond_monitor() -> Vec<u8> {
        let canonical = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let mut signed: SignedMonitorV1 = serde_json::from_slice(&canonical).unwrap();
        signed.body.acquisition.started_at = "2026-08-30T01:00:00.123456789Z".into();
        signed.body.acquisition.ended_at = "2026-08-30T01:00:00.223456789Z".into();
        signed.body.producer_observed_at = Some("2026-08-30T01:00:00.123456789Z".into());
        let body_bytes = serde_json::to_vec(&signed.body).unwrap();
        sign_exact_body(&body_bytes, &signed.body.producer)
    }

    fn monitor_with_payload(payload: &[u8]) -> Vec<u8> {
        let canonical = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let mut signed: SignedMonitorV1 = serde_json::from_slice(&canonical).unwrap();
        let reference = signed.body.payload.as_mut().unwrap();
        reference.digest = monitor_digest(MONITOR_CONTENT_DIGEST_DOMAIN_V1, &[payload]);
        reference.byte_length = payload.len() as u64;
        let body_bytes = serde_json::to_vec(&signed.body).unwrap();
        sign_exact_body(&body_bytes, &signed.body.producer)
    }

    fn validate_monitor_fixture(signed: &SignedMonitorV1) -> Result<(), String> {
        let bytes = serde_json::to_vec(signed).unwrap();
        let body = extract_object_field(&bytes, "body").unwrap();
        validate_monitor(signed, body)
    }

    fn nq(raw: &[u8], refused: bool) -> Vec<u8> {
        let signed: SignedMonitorV1 = serde_json::from_slice(raw).unwrap();
        let observation = monitor_observation_digest(extract_object_field(raw, "body").unwrap());
        let produced = signed.body.acquisition.outcome == AcquisitionOutcomeV1::ObservationProduced;
        let input = NqInputV1 {
            input_id: "input:fixture".into(),
            raw_record_digest: sha256(raw),
            monitor_record_digest: Some(observation.clone()),
            subject_identity_digest: Some(monitor_subject_digest(&signed.body.subject).unwrap()),
            producer_identity_digest: Some(monitor_producer_digest(&signed.body.producer).unwrap()),
            producer_principal_id: Some(signed.body.producer.principal_id.clone()),
            producer_class: Some(signed.body.producer.producer_class.clone()),
            acquisition_outcome: Some(signed.body.acquisition.outcome.text().into()),
            producer_observed_at: signed
                .body
                .producer_observed_at
                .as_deref()
                .map(|value| value.parse().unwrap()),
            receiver_custody_at: "2026-08-30T01:00:10Z".parse().unwrap(),
            payload_schema: signed.body.payload_schema.clone(),
            claim_support: if produced && !refused {
                vec![ClaimSupportV1 {
                    claim_id: "claim:stage".into(),
                    proposition: "stage testimony".into(),
                    value_digest: d("value"),
                    monitor_record_digest: observation,
                }]
            } else {
                vec![]
            },
            cannot_testify: if produced {
                vec![]
            } else {
                vec![CannotTestifyV1 {
                    claim_id: "claim:stage".into(),
                    reason: format!(
                        "Monitor acquisition outcome {} produced no world testimony",
                        signed.body.acquisition.outcome.text()
                    ),
                }]
            },
            refusals: if refused {
                vec![RefusalV1 {
                    code: "subject_identity_mismatch".into(),
                    exact_basis_digest: sha256(raw),
                    detail: "subject is outside the exact qualification profile".into(),
                }]
            } else {
                vec![]
            },
        };
        serde_json::to_vec(&NqArtifactV1 {
            schema: NQ_OPERATIONAL_QUALIFICATION_SCHEMA_V1.into(),
            profile_id: "profile:fixture".into(),
            monitor_contract_head: FIELD_CLOCK_MONITOR_RESULT_HEAD.into(),
            evaluated_at: "2026-08-30T01:00:11Z".parse().unwrap(),
            inputs: vec![input],
            contradictions: vec![],
            nonclaims: vec![
                "NQ qualification grants no authorization or remediation".into(),
                "NQ qualification does not establish Nightshift temporal currentness".into(),
                "producer class alone grants no evidentiary precedence".into(),
            ],
        })
        .unwrap()
    }

    fn admit(
        raw: &[u8],
        qualified: &[u8],
        history: &[OperationalObservationLineageV1],
    ) -> Result<OperationalObservationLineageV1, String> {
        admit_operational_lineage(
            raw,
            qualified,
            "input:fixture",
            "2026-08-30T01:00:12Z".parse().unwrap(),
            history,
        )
        .map(|value| value.0)
    }

    #[test]
    fn produced_lineage_and_evaluation_are_deterministic() {
        let raw = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let lineage = admit(&raw, &nq(&raw, false), &[]).unwrap();
        assert_ne!(
            lineage.monitor_custody.raw_bytes_sha256,
            lineage.monitor_custody.semantic_digest
        );
        let profile = ReobservationProfileV1 {
            profile_id: "profile:hour".into(),
            max_age_seconds: 3600,
        };
        let current =
            evaluate_reobservation(&lineage, &profile, "2026-08-30T01:30:00Z".parse().unwrap())
                .unwrap();
        let stale =
            evaluate_reobservation(&lineage, &profile, "2026-08-30T02:00:00Z".parse().unwrap())
                .unwrap();
        assert_eq!(
            lineage.lineage_id,
            "sha256:3e224bb1c7e40149111053702a65a673f04d97c9778997e5473641484637d62d"
        );
        assert_eq!(
            current.evaluation_id,
            "sha256:fdf61370ed39aa86b707d50edcee3a8b56027c07fa8151aaab716fb79148631f"
        );
        assert_eq!(
            stale.evaluation_id,
            "sha256:baa4900eb7230bfa63d50922a2b53a2d6b7609f358bee5e7ae727e12f0e64845"
        );
        assert_eq!(current.disposition, ReobservationDispositionV1::Current);
        assert_eq!(stale.disposition, ReobservationDispositionV1::Stale);
        assert_ne!(current.evaluation_id, stale.evaluation_id);
    }

    #[test]
    fn replay_converges_and_fork_or_missing_predecessor_refuses() {
        let raw = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let first = admit(&raw, &nq(&raw, false), &[]).unwrap();
        let replay = admit_operational_lineage(
            &raw,
            &nq(&raw, false),
            "input:fixture",
            "2026-08-30T01:00:13Z".parse().unwrap(),
            std::slice::from_ref(&first),
        )
        .unwrap();
        assert_eq!(replay.1, AdmissionDispositionV1::ExactReplay);
        let fork = monitor(AcquisitionOutcomeV1::NoResponse, 0, None);
        assert!(
            admit(&fork, &nq(&fork, false), std::slice::from_ref(&first))
                .unwrap_err()
                .contains("fork")
        );
        let next = monitor(
            AcquisitionOutcomeV1::ObservationProduced,
            1,
            Some(first.monitor_custody.semantic_digest.clone()),
        );
        assert!(admit(&next, &nq(&next, false), &[])
            .unwrap_err()
            .contains("predecessor"));
        admit(&next, &nq(&next, false), &[first]).unwrap();
    }

    #[test]
    fn substitutions_and_claim_widening_refuse() {
        let raw = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let mut qualified: NqArtifactV1 = serde_json::from_slice(&nq(&raw, false)).unwrap();
        qualified.inputs[0].raw_record_digest = d("substitution");
        assert!(admit(&raw, &serde_json::to_vec(&qualified).unwrap(), &[])
            .unwrap_err()
            .contains("does not bind"));
        let lineage = admit(&raw, &nq(&raw, false), &[]).unwrap();
        let profile = ReobservationProfileV1 {
            profile_id: "profile:hour".into(),
            max_age_seconds: 3600,
        };
        let mut evaluation =
            evaluate_reobservation(&lineage, &profile, "2026-08-30T01:30:00Z".parse().unwrap())
                .unwrap();
        evaluation
            .exact_supported_claim_ids
            .push("claim:widened".into());
        evaluation.evaluation_id = evaluation.computed_evaluation_id().unwrap();
        assert!(evaluation
            .validate_against(&lineage, &profile)
            .unwrap_err()
            .contains("widened"));
    }

    #[test]
    fn failures_and_refusals_never_become_current() {
        let failure_raw = monitor(AcquisitionOutcomeV1::NoResponse, 0, None);
        let failure = admit(&failure_raw, &nq(&failure_raw, false), &[]).unwrap();
        let profile = ReobservationProfileV1 {
            profile_id: "profile:hour".into(),
            max_age_seconds: 3600,
        };
        assert_eq!(
            evaluate_reobservation(&failure, &profile, "2026-08-30T01:30:00Z".parse().unwrap())
                .unwrap()
                .disposition,
            ReobservationDispositionV1::AcquisitionFailure
        );
        let raw = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let refused = admit(&raw, &nq(&raw, true), &[]).unwrap();
        let result =
            evaluate_reobservation(&refused, &profile, "2026-08-30T01:30:00Z".parse().unwrap())
                .unwrap();
        assert_eq!(result.disposition, ReobservationDispositionV1::Refused);
        assert!(!result.grants_authority);
    }

    #[test]
    fn typed_identity_signature_time_and_unknown_fields_are_closed() {
        let raw = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let mut signed: SignedMonitorV1 = serde_json::from_slice(&raw).unwrap();
        signed.body.subject.basis_contract = "monitor.subject-basis.hostname-hash/v1".into();
        assert!(validate_monitor_fixture(&signed)
            .unwrap_err()
            .contains("basis contract"));
        let mut wrong_family: SignedMonitorV1 = serde_json::from_slice(&raw).unwrap();
        wrong_family.body.subject.kind = SubjectKindV1::Host;
        wrong_family.body.subject.basis_contract = "monitor.subject-basis.host-machine/v1".into();
        assert!(validate_monitor_fixture(&wrong_family)
            .unwrap_err()
            .contains("stable-basis family"));
        let mut unicode: SignedMonitorV1 = serde_json::from_slice(&raw).unwrap();
        unicode.body.subject.namespace = "é".repeat(512);
        assert!(validate_monitor_fixture(&unicode)
            .unwrap_err()
            .contains("non-ASCII"));
        let mut signed: SignedMonitorV1 = serde_json::from_slice(&raw).unwrap();
        signed.body.acquisition.started_at = "2026-08-30T02:00:00Z".into();
        assert!(validate_monitor_fixture(&signed)
            .unwrap_err()
            .contains("time inversion"));
        let mut bytes = raw;
        let pos = bytes.iter().rposition(|byte| *byte == b'}').unwrap();
        bytes.splice(pos..pos, b",\"command\":\"retry\"".iter().copied());
        assert!(serde_json::from_slice::<SignedMonitorV1>(&bytes).is_err());
    }

    #[test]
    fn contradiction_is_preserved_without_precedence_or_authority() {
        let raw = monitor_with_payload(br#"{"stage":"ready"}"#);
        let mut qualified: NqArtifactV1 = serde_json::from_slice(&nq(&raw, false)).unwrap();
        qualified.inputs[0].claim_support[0].value_digest =
            jcs_digest(&serde_json::json!("ready")).unwrap();
        let other_raw = monitor_with_payload(br#"{"stage":"blocked"}"#);
        let other_artifact: NqArtifactV1 = serde_json::from_slice(&nq(&other_raw, false)).unwrap();
        let mut other = other_artifact.inputs[0].clone();
        other.input_id = "input:other".into();
        other.claim_support[0].value_digest = jcs_digest(&serde_json::json!("blocked")).unwrap();
        qualified.inputs.push(other);
        qualified.contradictions = expected_nq_contradictions(&qualified.inputs);
        let lineage = admit(&raw, &serde_json::to_vec(&qualified).unwrap(), &[]).unwrap();
        let profile = ReobservationProfileV1 {
            profile_id: "profile:hour".into(),
            max_age_seconds: 3600,
        };
        let result =
            evaluate_reobservation(&lineage, &profile, "2026-08-30T01:30:00Z".parse().unwrap())
                .unwrap();
        assert_eq!(
            result.disposition,
            ReobservationDispositionV1::Contradictory
        );
        assert!(!result.grants_authority);
    }
    #[test]
    fn independent_time_axes_refuse_inversion() {
        let raw = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let qualified = nq(&raw, false);
        assert!(admit_operational_lineage(
            &raw,
            &qualified,
            "input:fixture",
            "2026-08-30T01:00:10Z".parse().unwrap(),
            &[],
        )
        .unwrap_err()
        .contains("time ordering"));
        let lineage = admit(&raw, &qualified, &[]).unwrap();
        let profile = ReobservationProfileV1 {
            profile_id: "profile:hour".into(),
            max_age_seconds: 3600,
        };
        assert!(evaluate_reobservation(
            &lineage,
            &profile,
            "2026-08-30T01:00:11Z".parse().unwrap(),
        )
        .unwrap_err()
        .contains("precedes Nightshift admission"));

        let mut early_receiver: NqArtifactV1 = serde_json::from_slice(&qualified).unwrap();
        early_receiver.inputs[0].receiver_custody_at = "2026-08-30T01:00:00Z".parse().unwrap();
        assert!(
            admit(&raw, &serde_json::to_vec(&early_receiver).unwrap(), &[])
                .unwrap_err()
                .contains("time ordering")
        );
        let mut early_nq: NqArtifactV1 = serde_json::from_slice(&qualified).unwrap();
        early_nq.evaluated_at = "2026-08-30T01:00:09Z".parse().unwrap();
        assert!(admit(&raw, &serde_json::to_vec(&early_nq).unwrap(), &[])
            .unwrap_err()
            .contains("time ordering"));
    }

    #[test]
    fn schemas_and_exact_vectors_are_closed() {
        let lineage: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/nightshift.operational-observation-lineage.v1.schema.json"
        ))
        .unwrap();
        let evaluation: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/nightshift.operational-reobservation-evaluation.v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            lineage["$id"],
            serde_json::json!("urn:nightshift:operational-observation-lineage:v1")
        );
        assert_eq!(
            evaluation["$id"],
            serde_json::json!("urn:nightshift:operational-reobservation-evaluation:v1")
        );
        assert_eq!(lineage["additionalProperties"], serde_json::json!(false));
        assert_eq!(evaluation["additionalProperties"], serde_json::json!(false));
        assert_eq!(
            lineage["properties"]["subject"]["oneOf"]
                .as_array()
                .unwrap()
                .len(),
            12
        );
        assert_eq!(
            lineage["properties"]["subject"]["oneOf"][0]["properties"]["stable_basis"]
                ["additionalProperties"],
            serde_json::json!(false)
        );
        assert_eq!(
            evaluation["properties"]["grants_authority"]["const"],
            serde_json::json!(false)
        );
    }
    #[test]
    fn exact_reordered_whitespace_body_is_verified_without_reserialization() {
        let raw = reordered_whitespace_monitor();
        let body_bytes = extract_object_field(&raw, "body").unwrap();
        let signed: SignedMonitorV1 = serde_json::from_slice(&raw).unwrap();
        assert_ne!(
            body_bytes,
            serde_json::to_vec(&signed.body).unwrap().as_slice(),
            "fixture must differ from typed reserialization"
        );
        let qualified = nq(&raw, false);
        let lineage = admit(&raw, &qualified, &[]).unwrap();
        assert_eq!(
            lineage.monitor_custody.semantic_digest,
            monitor_observation_digest(body_bytes)
        );

        let mut substituted = raw.clone();
        let offset = substituted
            .windows(b"\"schema\":".len())
            .position(|window| window == b"\"schema\":")
            .unwrap()
            + b"\"schema\":".len();
        substituted.insert(offset, b' ');
        let substituted_nq = nq(&substituted, false);
        assert!(admit(&substituted, &substituted_nq, &[])
            .unwrap_err()
            .contains("Ed25519"));
    }

    #[test]
    fn subsecond_axes_and_currentness_horizon_are_preserved() {
        let raw = subsecond_monitor();
        let mut qualified: NqArtifactV1 = serde_json::from_slice(&nq(&raw, false)).unwrap();
        qualified.inputs[0].receiver_custody_at = "2026-08-30T01:00:00.323456789Z".parse().unwrap();
        qualified.evaluated_at = "2026-08-30T01:00:00.423456789Z".parse().unwrap();
        let qualified = serde_json::to_vec(&qualified).unwrap();
        let lineage = admit_operational_lineage(
            &raw,
            &qualified,
            "input:fixture",
            "2026-08-30T01:00:00.523456789Z".parse().unwrap(),
            &[],
        )
        .unwrap()
        .0;
        assert_eq!(
            lineage.receiver_custody_at,
            "2026-08-30T01:00:00.323456789Z"
        );
        assert_eq!(lineage.nq_qualified_at, "2026-08-30T01:00:00.423456789Z");
        assert_eq!(
            lineage.nightshift_admitted_at,
            "2026-08-30T01:00:00.523456789Z"
        );
        let profile = ReobservationProfileV1 {
            profile_id: "profile:subsecond".into(),
            max_age_seconds: 1,
        };
        let current = evaluate_reobservation(
            &lineage,
            &profile,
            "2026-08-30T01:00:00.923456789Z".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            current.current_until.as_deref(),
            Some("2026-08-30T01:00:01.123456789Z")
        );
        let stale = evaluate_reobservation(
            &lineage,
            &profile,
            "2026-08-30T01:00:01.123456789Z".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(stale.disposition, ReobservationDispositionV1::Stale);
    }
    #[test]
    fn runtime_profile_bounds_embedded_identities_and_nq_findings_are_cross_bound() {
        for profile_id in [
            "p".repeat(1025),
            "profile:\u{1}fixture".into(),
            "é".repeat(512),
        ] {
            assert!(ReobservationProfileV1 {
                profile_id,
                max_age_seconds: 60,
            }
            .semantic_digest()
            .is_err());
        }

        let raw = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let qualified = nq(&raw, false);
        let lineage = admit(&raw, &qualified, &[]).unwrap();
        let mut subject_substitution = lineage.clone();
        subject_substitution.subject_identity_digest = d("other-subject");
        subject_substitution.lineage_id = subject_substitution.computed_lineage_id().unwrap();
        assert!(subject_substitution
            .validate()
            .unwrap_err()
            .contains("embedded operational subject"));
        let mut producer_substitution = lineage;
        producer_substitution.producer_identity_digest = d("other-producer");
        producer_substitution.lineage_id = producer_substitution.computed_lineage_id().unwrap();
        assert!(producer_substitution
            .validate()
            .unwrap_err()
            .contains("embedded operational subject"));

        let mut bad_refusal: NqArtifactV1 = serde_json::from_slice(&qualified).unwrap();
        bad_refusal.inputs[0].refusals.push(RefusalV1 {
            code: "fixture_refusal".into(),
            exact_basis_digest: d("other-raw"),
            detail: "wrong exact basis".into(),
        });
        assert!(admit(&raw, &serde_json::to_vec(&bad_refusal).unwrap(), &[])
            .unwrap_err()
            .contains("refusal"));

        let mut overlap: NqArtifactV1 = serde_json::from_slice(&qualified).unwrap();
        overlap.inputs[0].cannot_testify.push(CannotTestifyV1 {
            claim_id: "claim:stage".into(),
            reason: "overlap fixture".into(),
        });
        assert!(admit(&raw, &serde_json::to_vec(&overlap).unwrap(), &[])
            .unwrap_err()
            .contains("cannot-testify"));

        let mut contradiction: NqArtifactV1 = serde_json::from_slice(&qualified).unwrap();
        let mut other = contradiction.inputs[0].clone();
        other.input_id = "input:other".into();
        other.claim_support[0].value_digest = d("other");
        contradiction.inputs.push(other);
        contradiction.contradictions.push(ContradictionV1 {
            subject_identity_digest: contradiction.inputs[0]
                .subject_identity_digest
                .clone()
                .unwrap(),
            claim_id: "claim:stage".into(),
            first_input_id: "input:fixture".into(),
            first_value_digest: d("wrong-first"),
            second_input_id: "input:other".into(),
            second_value_digest: d("other"),
        });
        assert!(
            admit(&raw, &serde_json::to_vec(&contradiction).unwrap(), &[])
                .unwrap_err()
                .contains("exact input claim values")
        );
    }

    #[test]
    fn nq_qualify_one_closure_and_all_inputs_are_validated() {
        let raw = monitor(AcquisitionOutcomeV1::ObservationProduced, 0, None);
        let qualified_bytes = nq(&raw, false);
        let qualified: NqArtifactV1 = serde_json::from_slice(&qualified_bytes).unwrap();

        let mut mixed = qualified.clone();
        mixed.inputs[0].claim_support.clear();
        mixed.inputs[0].cannot_testify.push(CannotTestifyV1 {
            claim_id: "claim:stage".into(),
            reason: "cannot testify".into(),
        });
        let mixed_raw_digest = mixed.inputs[0].raw_record_digest.clone();
        mixed.inputs[0].refusals.push(RefusalV1 {
            code: "subject_identity_mismatch".into(),
            exact_basis_digest: mixed_raw_digest,
            detail: "subject is outside the exact qualification profile".into(),
        });
        assert!(validate_nq(&mixed)
            .unwrap_err()
            .contains("mixed with support or cannot-testify"));

        let mut empty = qualified.clone();
        empty.inputs[0].claim_support.clear();
        assert!(validate_nq(&empty)
            .unwrap_err()
            .contains("no qualification finding"));

        let mut unopened = qualified.clone();
        {
            let input = &mut unopened.inputs[0];
            input.monitor_record_digest = None;
            input.subject_identity_digest = None;
            input.producer_identity_digest = None;
            input.producer_principal_id = None;
            input.producer_class = None;
            input.acquisition_outcome = None;
            input.producer_observed_at = None;
            input.payload_schema = None;
            input.claim_support.clear();
            input.cannot_testify.clear();
            input.refusals = vec![RefusalV1 {
                code: "record_malformed".into(),
                exact_basis_digest: input.raw_record_digest.clone(),
                detail: "expected value at line 1 column 1".into(),
            }];
        }
        validate_nq(&unopened).unwrap();

        for detail in ["value is not a string", "observed_at is not a string"] {
            validate_nq_unopened_refusal_detail("field_type", detail).unwrap();
        }
        for (value, expected) in [
            ("2026-aa-30T01:00:00Z", "input contains invalid characters"),
            ("2026-99-30T01:00:00Z", "input is out of range"),
            ("2026-08-30T01:00:00+Z", "premature end of input"),
            ("2026-08-30T01:00:00ZZ", "trailing input"),
        ] {
            assert_eq!(
                value.parse::<DateTime<Utc>>().unwrap_err().to_string(),
                expected
            );
            validate_nq_unopened_refusal_detail(
                "timestamp_invalid",
                &format!("acquisition start: {expected}"),
            )
            .unwrap();
        }
        for invented in [
            "acquisition start: bad or unsupported format",
            "acquisition start: bad or unsupported format string",
            "acquisition start: input is not enough for unique date and time",
            "acquisition start: no possible date and time matching input",
            "acquisition start: invented parser result",
        ] {
            assert!(validate_nq_unopened_refusal_detail("timestamp_invalid", invented).is_err());
        }
        let record_last_line = format!("expected value at line {} column 0", MAX_RAW_BYTES + 1);
        validate_nq_unopened_refusal_detail("record_malformed", &record_last_line).unwrap();
        let record_past_last_line =
            format!("expected value at line {} column 0", MAX_RAW_BYTES + 2);
        assert!(
            validate_nq_unopened_refusal_detail("record_malformed", &record_past_last_line,)
                .is_err()
        );
        let record_last_column = format!("expected value at line 1 column {}", MAX_RAW_BYTES);
        validate_nq_unopened_refusal_detail("record_malformed", &record_last_column).unwrap();
        let record_past_last_column =
            format!("expected value at line 1 column {}", MAX_RAW_BYTES + 1);
        assert!(
            validate_nq_unopened_refusal_detail("record_malformed", &record_past_last_column,)
                .is_err()
        );
        let unbounded_payload_coordinate =
            format!("expected value at line {} column 0", MAX_RAW_BYTES + 2);
        validate_nq_unopened_refusal_detail("payload_malformed", &unbounded_payload_coordinate)
            .unwrap();
        assert!(validate_nq_unopened_refusal_detail(
            "record_malformed",
            &unbounded_payload_coordinate,
        )
        .is_err());
        assert!(validate_nq_unopened_refusal_detail(
            "payload_malformed",
            "expected value at line 01 column 0",
        )
        .is_err());

        let mut fixed_detail = unopened.clone();
        fixed_detail.inputs[0].refusals[0].code = "record_oversized".into();
        fixed_detail.inputs[0].refusals[0].detail = "signed Monitor record exceeds one MiB".into();
        validate_nq(&fixed_detail).unwrap();

        let mut wrong_fixed_detail = fixed_detail.clone();
        wrong_fixed_detail.inputs[0].refusals[0].detail =
            "expected value at line 1 column 1".into();
        assert!(validate_nq(&wrong_fixed_detail)
            .unwrap_err()
            .contains("detail differs"));

        let mut invented_dynamic_detail = unopened.clone();
        invented_dynamic_detail.inputs[0].refusals[0].detail =
            "invented parser result at line 1 column 1".into();
        assert!(validate_nq(&invented_dynamic_detail)
            .unwrap_err()
            .contains("detail differs"));

        let mut noncanonical_dynamic_detail = unopened.clone();
        noncanonical_dynamic_detail.inputs[0].refusals[0].detail =
            "expected value at line 01 column 1".into();
        assert!(validate_nq(&noncanonical_dynamic_detail)
            .unwrap_err()
            .contains("detail differs"));

        let mut wrong_unopened_branch = unopened.clone();
        wrong_unopened_branch.inputs[0].refusals[0].code = "subject_identity_mismatch".into();
        wrong_unopened_branch.inputs[0].refusals[0].detail =
            "subject is outside the exact qualification profile".into();
        assert!(validate_nq(&wrong_unopened_branch)
            .unwrap_err()
            .contains("reopened/unopened branch"));

        let mut wrong_reopened_branch = qualified.clone();
        wrong_reopened_branch.inputs[0].claim_support.clear();
        let exact_basis = wrong_reopened_branch.inputs[0].raw_record_digest.clone();
        wrong_reopened_branch.inputs[0].refusals = vec![RefusalV1 {
            code: "record_malformed".into(),
            exact_basis_digest: exact_basis,
            detail: "expected value at line 1 column 1".into(),
        }];
        assert!(validate_nq(&wrong_reopened_branch)
            .unwrap_err()
            .contains("reopened/unopened branch"));

        let mut partial = unopened.clone();
        partial.inputs[0].producer_class = Some("instrumented_monitor".into());
        assert!(validate_nq(&partial)
            .unwrap_err()
            .contains("identity tuple is partial"));

        let mut unselected_bad_identity = qualified.clone();
        let mut other = unselected_bad_identity.inputs[0].clone();
        other.input_id = "input:unselected".into();
        other.producer_identity_digest = Some("not-a-digest".into());
        unselected_bad_identity.inputs.push(other);
        assert!(validate_nq(&unselected_bad_identity)
            .unwrap_err()
            .contains("SHA-256"));

        let mut unselected_bad_outcome = qualified.clone();
        let mut other = unselected_bad_outcome.inputs[0].clone();
        other.input_id = "input:unselected".into();
        other.acquisition_outcome = Some("response".into());
        unselected_bad_outcome.inputs.push(other);
        assert!(validate_nq(&unselected_bad_outcome)
            .unwrap_err()
            .contains("outside FIELD"));

        let mut unselected_bad_time = qualified.clone();
        let mut other = unselected_bad_time.inputs[0].clone();
        other.input_id = "input:unselected".into();
        other.receiver_custody_at = "2026-08-30T01:00:12Z".parse().unwrap();
        unselected_bad_time.inputs.push(other);
        assert!(validate_nq(&unselected_bad_time)
            .unwrap_err()
            .contains("time ordering"));

        let failure_raw = monitor(AcquisitionOutcomeV1::NoResponse, 0, None);
        let mut failure: NqArtifactV1 = serde_json::from_slice(&nq(&failure_raw, false)).unwrap();
        validate_nq(&failure).unwrap();
        failure.inputs[0].cannot_testify[0].reason = "generic failure".into();
        assert!(validate_nq(&failure)
            .unwrap_err()
            .contains("reason differs"));
        failure = serde_json::from_slice(&nq(&failure_raw, false)).unwrap();
        failure.inputs[0].cannot_testify.clear();
        assert!(validate_nq(&failure)
            .unwrap_err()
            .contains("no qualification finding"));

        let mut multiple_refusals = unopened;
        let second_raw_digest = multiple_refusals.inputs[0].raw_record_digest.clone();
        multiple_refusals.inputs[0].refusals.push(RefusalV1 {
            code: "second_refusal".into(),
            exact_basis_digest: second_raw_digest,
            detail: "owner-impossible second refusal".into(),
        });
        assert!(validate_nq(&multiple_refusals)
            .unwrap_err()
            .contains("refusal count"));

        let mut wrong_claim_domain = qualified.clone();
        let mut other = wrong_claim_domain.inputs[0].clone();
        other.input_id = "input:other-domain".into();
        other.claim_support[0].claim_id = "claim:other".into();
        wrong_claim_domain.inputs.push(other);
        assert!(validate_nq(&wrong_claim_domain)
            .unwrap_err()
            .contains("complete ordered claim domain"));

        let mut missing_contradiction = qualified;
        let mut other = missing_contradiction.inputs[0].clone();
        other.input_id = "input:other".into();
        other.claim_support[0].value_digest = d("other");
        missing_contradiction.inputs.push(other);
        assert!(validate_nq(&missing_contradiction)
            .unwrap_err()
            .contains("contradiction graph"));
    }

    #[test]
    fn independently_fixed_field_owner_vectors_reopen_and_negatives_refuse() {
        const MONITOR: &[u8] =
            include_bytes!("../tests/fixtures/operational_lineage/field-monitor.accepted.json");
        const NQ: &[u8] =
            include_bytes!("../tests/fixtures/operational_lineage/field-nq.accepted.json");
        assert_eq!(
            sha256(MONITOR),
            "sha256:9908a346475a228c75c48a30d947e3a15ad86f7c11079295e4e03e4e6df70345"
        );
        assert_eq!(
            sha256(NQ),
            "sha256:4e5958ccce4013e3d28531b32940630f7c7962c2690bd7a7493ca7f1981dc378"
        );
        let lineage = admit_operational_lineage(
            MONITOR,
            NQ,
            "input:field-vector",
            "2026-08-30T03:00:00.523456789Z".parse().unwrap(),
            &[],
        )
        .unwrap()
        .0;
        assert_eq!(lineage.claim_support[0].claim_id, "claim:availability");
        assert_eq!(
            lineage.producer_observed_at.as_deref(),
            Some("2026-08-30T03:00:00.123456789Z")
        );
        assert_eq!(
            lineage.receiver_custody_at,
            "2026-08-30T03:00:00.323456789Z"
        );

        let unknown_locator = include_bytes!(
            "../tests/fixtures/operational_lineage/field-monitor.unknown-locator.refused.json"
        );
        assert!(admit_operational_lineage(
            unknown_locator,
            NQ,
            "input:field-vector",
            "2026-08-30T03:00:00.523456789Z".parse().unwrap(),
            &[],
        )
        .unwrap_err()
        .contains("unknown variant"));

        let oversized_locators = include_bytes!(
            "../tests/fixtures/operational_lineage/field-monitor.oversized-locators.refused.json"
        );
        assert!(admit_operational_lineage(
            oversized_locators,
            NQ,
            "input:field-vector",
            "2026-08-30T03:00:00.523456789Z".parse().unwrap(),
            &[],
        )
        .unwrap_err()
        .contains("exceed 32"));
        let oversized_attachments = include_bytes!(
            "../tests/fixtures/operational_lineage/field-monitor.oversized-attachments.refused.json"
        );
        assert!(admit_operational_lineage(
            oversized_attachments,
            NQ,
            "input:field-vector",
            "2026-08-30T03:00:00.523456789Z".parse().unwrap(),
            &[],
        )
        .unwrap_err()
        .contains("exceed 32"));

        let oversized_text = include_bytes!(
            "../tests/fixtures/operational_lineage/field-monitor.oversized-subject-text.refused.json"
        );
        assert!(admit_operational_lineage(
            oversized_text,
            NQ,
            "input:field-vector",
            "2026-08-30T03:00:00.523456789Z".parse().unwrap(),
            &[],
        )
        .unwrap_err()
        .contains("exceeds 512 bytes"));
    }
}
