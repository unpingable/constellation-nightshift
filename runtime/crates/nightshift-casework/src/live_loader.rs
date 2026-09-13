use std::{collections::BTreeMap, path::Path};

use chrono::{DateTime, Utc};
use nightshift_foreman::{
    read_only_run_snapshot, ExecutionProfileV2, ForemanAdmissionV1, HumanQuestionV1,
    NotStartedReceiptV1, ReadOnlyRunSnapshotV1, TerminalReceiptV1,
};
use nightshiftd::packet::NightshiftPacketV1;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    live_capacity::project_provider_capacity, live_execution::project_provider_execution,
    live_model::*,
};

#[derive(Debug, Error)]
pub enum LiveCaseworkError {
    #[error("foreman read snapshot failed: {0}")]
    Foreman(String),
    #[error("live packet is invalid: {0}")]
    Packet(String),
    #[error("live foreman contract is invalid: {0}")]
    Contract(String),
    #[error("live source identities do not agree: {0}")]
    Identity(&'static str),
    #[error("live projection serialization failed: {0}")]
    Projection(String),
}

#[derive(Clone, Debug)]
pub struct LoadedLiveRun {
    pub projection: CaseworkLiveRunV1,
    pub provider_execution: CaseworkLiveProviderExecutionV1,
    pub packet_bytes: Vec<u8>,
    pub admission_bytes: Vec<u8>,
    pub profile_bytes: Vec<u8>,
    pub journal_framing_bytes: Vec<u8>,
    pub accepted_receipts_framing_bytes: Vec<u8>,
    pub event_bytes: BTreeMap<u64, Vec<u8>>,
    pub accepted_receipt_bytes: BTreeMap<String, Vec<u8>>,
    pub final_snapshot_bytes: Option<Vec<u8>>,
}

pub fn load_live_run_at(
    store_path: &Path,
    run_id: &str,
    evaluated_at: DateTime<Utc>,
) -> Result<LoadedLiveRun, LiveCaseworkError> {
    let snapshot = read_only_run_snapshot(store_path, run_id)
        .map_err(|error| LiveCaseworkError::Foreman(error.to_string()))?;
    project(snapshot, evaluated_at)
}

fn project(
    snapshot: ReadOnlyRunSnapshotV1,
    evaluated_at: DateTime<Utc>,
) -> Result<LoadedLiveRun, LiveCaseworkError> {
    if snapshot.projection.work_items.len() > 4096
        || snapshot.projection.resource_claims.len() > 4096
        || snapshot.events.len() > 1_048_576
        || snapshot.terminal_receipts.len() > 4096
        || snapshot
            .events
            .iter()
            .any(|event| event.raw_bytes.is_empty() || event.raw_bytes.len() > 16 * 1024 * 1024)
    {
        return Err(LiveCaseworkError::Contract(
            "live snapshot exceeds projection collection or byte bounds".to_owned(),
        ));
    }
    let packet = NightshiftPacketV1::from_slice(&snapshot.packet_bytes)
        .map_err(|error| LiveCaseworkError::Packet(error.to_string()))?;
    packet
        .validate_integrity()
        .map_err(|error| LiveCaseworkError::Packet(error.to_string()))?;
    let admission = ForemanAdmissionV1::from_slice(&snapshot.admission_bytes)
        .map_err(|error| LiveCaseworkError::Contract(error.to_string()))?;
    admission
        .validate()
        .map_err(|error| LiveCaseworkError::Contract(error.to_string()))?;
    let profile = ExecutionProfileV2::from_slice(&snapshot.profile_bytes)
        .map_err(|error| LiveCaseworkError::Contract(error.to_string()))?;
    profile
        .validate()
        .map_err(|error| LiveCaseworkError::Contract(error.to_string()))?;
    if snapshot.run_id != admission.run_id
        || snapshot.projection.run_id != admission.run_id
        || snapshot.projection.packet_id != packet.packet_id
    {
        return Err(LiveCaseworkError::Identity("run_id or packet_id"));
    }
    if admission.packet_digest != packet.packet_digest
        || profile.packet_digest != packet.packet_digest
        || snapshot.projection.packet_digest != packet.packet_digest
    {
        return Err(LiveCaseworkError::Identity("packet_digest"));
    }
    if profile.admission_digest != admission.admission_digest
        || snapshot.projection.admission_digest != admission.admission_digest
        || snapshot.projection.profile_digest != profile.profile_digest
    {
        return Err(LiveCaseworkError::Identity(
            "admission_digest or profile_digest",
        ));
    }

    let packet_sha = plain_sha256(&snapshot.packet_bytes);
    let admission_sha = plain_sha256(&snapshot.admission_bytes);
    let profile_sha = plain_sha256(&snapshot.profile_bytes);
    let journal_framing_bytes = journal_framing(&snapshot);
    let journal_sha = plain_sha256(&journal_framing_bytes);
    let final_snapshot_sha = snapshot.final_snapshot_bytes.as_deref().map(plain_sha256);
    let receipts_by_item: BTreeMap<_, _> = snapshot
        .terminal_receipts
        .iter()
        .map(|receipt| (receipt.work_item_id.as_str(), receipt))
        .collect();
    let event_bytes = snapshot
        .events
        .iter()
        .map(|event| (event.sequence, event.raw_bytes.clone()))
        .collect();
    let accepted_receipt_bytes = snapshot
        .terminal_receipts
        .iter()
        .map(|receipt| (receipt.work_item_id.clone(), receipt.raw_bytes.clone()))
        .collect();
    let accepted_receipts_framing_bytes = accepted_receipts_framing(&accepted_receipt_bytes);
    let accepted_receipts_framing_sha = plain_sha256(&accepted_receipts_framing_bytes);
    let packet_items: BTreeMap<_, _> = packet
        .work_items
        .iter()
        .map(|item| (&item.id, item))
        .collect();

    let mut state_counts = BTreeMap::new();
    let mut work_items = Vec::with_capacity(snapshot.projection.work_items.len());
    for mechanism in &snapshot.projection.work_items {
        let intent = packet_items
            .get(&mechanism.work_item_id)
            .ok_or(LiveCaseworkError::Identity("projection work_item_id"))?;
        let scheduler_state = serde_json::to_value(&mechanism.scheduler_state)
            .map_err(|error| LiveCaseworkError::Projection(error.to_string()))?
            .as_str()
            .ok_or_else(|| {
                LiveCaseworkError::Projection("scheduler state is not a string".to_owned())
            })?
            .to_owned();
        *state_counts.entry(scheduler_state.clone()).or_insert(0) += 1;
        let accepted_receipt = receipts_by_item
            .get(mechanism.work_item_id.as_str())
            .copied();
        let accepted_outcome = accepted_receipt.map(|receipt| LiveAcceptedOutcomeV1 {
            state: receipt.state.clone(),
            result_classification: receipt.result_classification.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
        });
        let accepted_receipt_kind = accepted_receipt.map(|receipt| receipt.receipt_kind.clone());
        let accepted_outcome_absent_reason = if accepted_outcome.is_none() {
            Some("NO_ACCEPTED_TERMINAL_OR_NOT_STARTED_RECEIPT".to_owned())
        } else {
            None
        };
        let mut human_questions = mechanism.human_questions.clone();
        if let Some(receipt) = accepted_receipt {
            for question in accepted_receipt_questions(receipt)? {
                if let Some(existing) = human_questions
                    .iter()
                    .find(|existing| existing.question_id == question.question_id)
                {
                    if existing != &question {
                        return Err(LiveCaseworkError::Identity(
                            "live question identity disagreement",
                        ));
                    }
                } else {
                    human_questions.push(question);
                }
            }
        }
        if human_questions.len() > 1024 {
            return Err(LiveCaseworkError::Contract(
                "live question collection exceeds bound".to_owned(),
            ));
        }
        work_items.push(LiveWorkItemV1 {
            work_item_id: intent.id.clone(),
            track: intent.track.clone(),
            campaign_codename: intent.campaign.codename.clone(),
            campaign_slug: intent.campaign.canonical_slug.clone(),
            dependencies: intent.dependencies.clone(),
            entry_predicates: intent.entry_predicates.clone(),
            stop_conditions: intent.stop_conditions.clone(),
            scheduler_state,
            scheduler_state_recognized: true,
            dependency_terminality: mechanism.dependency_terminality.clone(),
            resource_lock_keys: mechanism.resource_lock_keys.clone(),
            active_attempt_id: mechanism.active_attempt_id.clone(),
            adapter_id: mechanism.adapter_id.clone(),
            adapter_version: mechanism.adapter_version.clone(),
            provider_model_class: mechanism.provider_model_class.clone(),
            provider_identity: mechanism.provider_identity.clone(),
            model_identity: mechanism.model_identity.clone(),
            session_identity: mechanism.session_identity.clone(),
            thread_identity: mechanism.thread_identity.clone(),
            turn_identity: mechanism.turn_identity.clone(),
            queue_identity: mechanism.queue_identity.clone(),
            last_event_sequence: mechanism.last_event_sequence,
            last_event_digest: mechanism.last_event_digest.clone(),
            human_questions: human_questions
                .iter()
                .map(|question| LiveQuestionV1 {
                    navigation_id: question_navigation_id(
                        &mechanism.work_item_id,
                        &question.question_id,
                    ),
                    question_id: question.question_id.clone(),
                    question: question.question.clone(),
                    exhausted_evidence: question.exhausted_evidence.clone(),
                    safe_default: question.safe_default.clone(),
                    consequences: question.consequences.clone(),
                    resume_point: question.resume_point.clone(),
                })
                .collect(),
            accepted_receipt_kind,
            accepted_outcome,
            accepted_outcome_absent_reason,
        });
    }
    if work_items.len() != packet.work_items.len() {
        return Err(LiveCaseworkError::Identity("work item count"));
    }

    let events = snapshot
        .events
        .iter()
        .map(|event| LiveEventV1 {
            sequence: event.sequence,
            event_id: event.event_id.clone(),
            work_item_id: event.work_item_id.clone(),
            attempt_id: event.attempt_id.clone(),
            kind: event.kind.clone(),
            recorded_at: event.recorded_at.clone(),
            retained_raw_digest: event.raw_digest.clone(),
            exact_bytes_sha256: plain_sha256(&event.raw_bytes),
            raw_length: event.raw_bytes.len(),
        })
        .collect();
    let lifecycle = if snapshot.final_snapshot_bytes.is_some() {
        "CLOSED_EXACT_FINAL_SNAPSHOT_RETAINED"
    } else {
        "OPEN"
    }
    .to_owned();
    let terminal_receipt_count = snapshot
        .terminal_receipts
        .iter()
        .filter(|receipt| receipt.receipt_kind == "terminal")
        .count();
    let not_started_receipt_count = snapshot
        .terminal_receipts
        .iter()
        .filter(|receipt| receipt.receipt_kind == "not_started")
        .count();

    let provider_capacity =
        project_provider_capacity(&snapshot, &packet, &admission, &profile, evaluated_at)?;
    let provider_execution = project_provider_execution(
        &snapshot,
        &packet,
        &admission,
        &profile,
        evaluated_at,
        &provider_capacity.status,
    )?;
    let capacity_binding_status = if provider_capacity.requirement.is_some() {
        "EXACT_RECORDED_CAPACITY_REQUIREMENT"
    } else {
        "POLICY_REFERENCE_ONLY_NO_RECORDED_DECISION"
    };

    let mut projection = CaseworkLiveRunV1 {
        schema: CASEWORK_LIVE_RUN_SCHEMA_V1.to_owned(),
        projection_digest: String::new(),
        navigation_id: navigation_id(&snapshot.run_id),
        run_id: snapshot.run_id.clone(),
        evaluated_at: evaluated_at.to_rfc3339(),
        packet: LivePacketV1 {
            packet_id: packet.packet_id.clone(),
            packet_digest: packet.packet_digest.clone(),
            exact_bytes_sha256: packet_sha.clone(),
            integrity: "VALID".to_owned(),
            created_at: packet.created_at.to_rfc3339(),
            current_until: packet.current_until.to_rfc3339(),
            currentness: currentness(evaluated_at, packet.created_at, packet.current_until),
        },
        admission: LiveAdmissionV1 {
            admission_digest: admission.admission_digest.clone(),
            exact_bytes_sha256: admission_sha.clone(),
            admitted_at: admission.admitted_at.to_rfc3339(),
            expires_at: admission.expires_at.to_rfc3339(),
            currentness: currentness(evaluated_at, admission.admitted_at, admission.expires_at),
            maximum_concurrent_workers: admission.maximum_concurrent_workers,
        },
        execution_profile: LiveExecutionProfileV1 {
            profile_digest: profile.profile_digest.clone(),
            exact_bytes_sha256: profile_sha.clone(),
            budget_policy_ref: profile.budget_policy_ref,
            capacity_binding_status: capacity_binding_status.to_owned(),
        },
        foreman: LiveForemanV1 {
            source_schema: snapshot.projection.schema.clone(),
            lifecycle,
            scheduler_state_counts: state_counts,
            terminal_receipt_count,
            not_started_receipt_count,
            closed_final_receipts_digest: snapshot.projection.closed_final_receipts_digest.clone(),
        },
        work_items,
        resource_claims: snapshot
            .projection
            .resource_claims
            .iter()
            .map(|claim| LiveResourceClaimV1 {
                resource_lock_key: claim.resource_lock_key.clone(),
                work_item_id: claim.work_item_id.clone(),
                attempt_id: claim.attempt_id.clone(),
            })
            .collect(),
        events,
        raw_sources: LiveRawSourcesV1 {
            packet_sha256: packet_sha,
            admission_sha256: admission_sha,
            profile_sha256: profile_sha,
            journal_framing_sha256: journal_sha,
            accepted_receipts_framing_sha256: accepted_receipts_framing_sha,
            final_snapshot_sha256: final_snapshot_sha,
        },
        sealed_case_run_id: None,
        provider_capacity,
        authority_effect: "READ_ONLY_OPERATOR_PROJECTION".to_owned(),
    };
    projection.projection_digest = projection_digest(&projection)?;
    Ok(LoadedLiveRun {
        projection,
        provider_execution,
        packet_bytes: snapshot.packet_bytes,
        admission_bytes: snapshot.admission_bytes,
        profile_bytes: snapshot.profile_bytes,
        journal_framing_bytes,
        accepted_receipts_framing_bytes,
        event_bytes,
        accepted_receipt_bytes,
        final_snapshot_bytes: snapshot.final_snapshot_bytes,
    })
}

pub(crate) fn reseal_live_projection(
    projection: &mut CaseworkLiveRunV1,
) -> Result<(), LiveCaseworkError> {
    projection.projection_digest = projection_digest(projection)?;
    Ok(())
}

fn currentness(now: DateTime<Utc>, begins: DateTime<Utc>, ends: DateTime<Utc>) -> String {
    if now < begins {
        "NOT_YET_CURRENT"
    } else if now > ends {
        "EXPIRED"
    } else {
        "CURRENT"
    }
    .to_owned()
}

fn plain_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn navigation_id(run_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CASEWORK_LIVE_NAVIGATION_DOMAIN_V1);
    hasher.update(run_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn question_navigation_id(work_item_id: &str, question_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CASEWORK_LIVE_QUESTION_NAVIGATION_DOMAIN_V1);
    hasher.update((work_item_id.len() as u64).to_be_bytes());
    hasher.update(work_item_id.as_bytes());
    hasher.update((question_id.len() as u64).to_be_bytes());
    hasher.update(question_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn journal_framing(snapshot: &ReadOnlyRunSnapshotV1) -> Vec<u8> {
    let capacity = snapshot
        .events
        .iter()
        .fold(FOREMAN_JOURNAL_FRAMING_V1.len(), |total, event| {
            total
                .saturating_add(16)
                .saturating_add(event.raw_bytes.len())
        });
    let mut framed = Vec::with_capacity(capacity);
    framed.extend_from_slice(FOREMAN_JOURNAL_FRAMING_V1);
    for event in &snapshot.events {
        framed.extend_from_slice(&event.sequence.to_be_bytes());
        framed.extend_from_slice(&(event.raw_bytes.len() as u64).to_be_bytes());
        framed.extend_from_slice(&event.raw_bytes);
    }
    framed
}

fn accepted_receipts_framing(receipts: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let capacity = receipts.iter().fold(
        FOREMAN_ACCEPTED_RECEIPTS_FRAMING_V1.len(),
        |total, (work_item_id, bytes)| {
            total
                .saturating_add(16)
                .saturating_add(work_item_id.len())
                .saturating_add(bytes.len())
        },
    );
    let mut framed = Vec::with_capacity(capacity);
    framed.extend_from_slice(FOREMAN_ACCEPTED_RECEIPTS_FRAMING_V1);
    for (work_item_id, bytes) in receipts {
        framed.extend_from_slice(&(work_item_id.len() as u64).to_be_bytes());
        framed.extend_from_slice(work_item_id.as_bytes());
        framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        framed.extend_from_slice(bytes);
    }
    framed
}

fn projection_digest<T: Serialize>(projection: &T) -> Result<String, LiveCaseworkError> {
    let mut value = serde_json::to_value(projection)
        .map_err(|error| LiveCaseworkError::Projection(error.to_string()))?;
    let Value::Object(object) = &mut value else {
        return Err(LiveCaseworkError::Projection(
            "live projection must serialize as an object".to_owned(),
        ));
    };
    object.remove("projection_digest");
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| LiveCaseworkError::Projection(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(CASEWORK_LIVE_RUN_DIGEST_DOMAIN_V1);
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn accepted_receipt_questions(
    receipt: &nightshift_foreman::ReadOnlyTerminalReceiptRowV1,
) -> Result<Vec<HumanQuestionV1>, LiveCaseworkError> {
    let questions = match receipt.receipt_kind.as_str() {
        "terminal" => {
            let parsed = TerminalReceiptV1::from_slice(&receipt.raw_bytes)
                .map_err(|error| LiveCaseworkError::Contract(error.to_string()))?;
            parsed
                .validate()
                .map_err(|error| LiveCaseworkError::Contract(error.to_string()))?;
            if serde_jcs::to_vec(&parsed)
                .map_err(|error| LiveCaseworkError::Projection(error.to_string()))?
                != receipt.raw_bytes
                || parsed.receipt_digest != receipt.receipt_digest
                || parsed.work_item_id != receipt.work_item_id
                || Some(parsed.attempt_id.as_str()) != receipt.attempt_id.as_deref()
            {
                return Err(LiveCaseworkError::Identity(
                    "accepted terminal receipt question custody",
                ));
            }
            parsed.human_questions
        }
        "not_started" => {
            let parsed = NotStartedReceiptV1::from_slice(&receipt.raw_bytes)
                .map_err(|error| LiveCaseworkError::Contract(error.to_string()))?;
            parsed
                .validate()
                .map_err(|error| LiveCaseworkError::Contract(error.to_string()))?;
            if serde_jcs::to_vec(&parsed)
                .map_err(|error| LiveCaseworkError::Projection(error.to_string()))?
                != receipt.raw_bytes
                || parsed.receipt_digest != receipt.receipt_digest
                || parsed.work_item_id != receipt.work_item_id
                || receipt.attempt_id.is_some()
            {
                return Err(LiveCaseworkError::Identity(
                    "accepted not-started receipt question custody",
                ));
            }
            parsed.human_questions
        }
        _ => {
            return Err(LiveCaseworkError::Contract(
                "accepted receipt kind is not closed".to_owned(),
            ))
        }
    };
    Ok(questions)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::{collections::BTreeMap, fs};

    use chrono::{Duration, TimeZone as _};
    use nightshift_foreman::{
        AdapterEventKindV1, AdapterEventV1, AdapterRegistrationV2, CapacityAdmissionEvidenceV1,
        CapacityCostClassV1, DeferredProviderDispatchV1, DeferredWakeBasisV1,
        DeterministicProviderAdmissionEvidenceV1, DeterministicProviderAdmissionOutcomeV1,
        ExactAvailabilityEvidenceV1, ExactMapperSnapshotV1, ExecutionAvailabilityObservationV1,
        ExecutionAvailabilityPolicyV1, ExecutionAvailabilityStateV1, ExecutionProfileV2,
        ForemanAdmissionV1, ForemanCapacityAdmissionV1, ForemanCapacityRequirementV1,
        ForemanExecutionAvailabilityRequirementV1, ForemanStore, NotStartedReceiptV1,
        ParkedResourceLockPolicyV1, ProviderAdmissionDispositionKindV1,
        ProviderAdmissionDispositionV1, ProviderAdmissionOwnerPinsV1,
        ProviderDispositionEvidenceV1, ProviderExecutionIdentityV1, ProviderMechanismStateV1,
        ProviderModelSelectionV1, ReceiptRepositoryV1, TeardownDeclarationV1, WorkItemExecutionV1,
        DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1,
        EXECUTION_AVAILABILITY_POLICY_SCHEMA_V1, FOREMAN_ADMISSION_SCHEMA_V1,
        FOREMAN_CAPACITY_ADMISSION_SCHEMA_V1, FOREMAN_CAPACITY_REQUIREMENT_SCHEMA_V1,
        FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1, FOREMAN_EXECUTION_PROFILE_SCHEMA_V2,
        PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2, WORKER_ADAPTER_EVENT_SCHEMA_V1,
        WORKER_TERMINAL_RECEIPT_SCHEMA_V1, WORK_ITEM_NOT_STARTED_RECEIPT_SCHEMA_V1,
    };

    use nightshift_provider_capacity::{
        decide_capacity, CapacityObservationV1, CapacityPolicyV1, CapacityWindow, Confidence,
        ObservationDisposition, ObservationEvidence, SourceClass, WindowType,
        CAPACITY_OBSERVATION_SCHEMA_V1,
    };

    use super::*;

    const PACKET: &[u8] = include_bytes!(
        "../../../qualification/nightshift-operational-spine-ecad-v2-20260829/packet.v1.json"
    );

    pub(crate) fn instant() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 31, 0, 0, 0).unwrap()
    }

    pub(crate) fn fixture() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let packet = NightshiftPacketV1::from_slice(PACKET).unwrap();
        packet.validate_integrity().unwrap();
        let mut admission = ForemanAdmissionV1 {
            schema: FOREMAN_ADMISSION_SCHEMA_V1.to_owned(),
            admission_digest: format!("sha256:{}", "0".repeat(64)),
            run_id: "ledger/live:fixture".to_owned(),
            packet_digest: packet.packet_digest.clone(),
            operator_basis_digest: format!("sha256:{}", "a".repeat(64)),
            admitted_at: instant() - Duration::hours(1),
            expires_at: instant() + Duration::hours(1),
            local_runtime_identity: "ledger-fixture".to_owned(),
            maximum_concurrent_workers: 2,
            allowed_adapter_ids: vec!["fixture-adapter".to_owned()],
            allowed_provider_model_classes: vec!["bounded".to_owned()],
            maximum_new_attempts_per_work_item: 1,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
            target_effects_authorized: false,
        };
        admission.seal().unwrap();
        let work_items = packet
            .work_items
            .iter()
            .map(|item| {
                (
                    item.id.clone(),
                    WorkItemExecutionV1 {
                        adapter_id: "fixture-adapter".to_owned(),
                        workspace_identity: format!("workspace:{}", item.id),
                        resource_lock_keys: vec![format!("resource:{}", item.id)],
                        provider_model_class: "bounded".to_owned(),
                    },
                )
            })
            .collect();
        let mut profile = ExecutionProfileV2 {
            schema: FOREMAN_EXECUTION_PROFILE_SCHEMA_V2.to_owned(),
            profile_digest: format!("sha256:{}", "0".repeat(64)),
            packet_digest: packet.packet_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            adapters: BTreeMap::from([(
                "fixture-adapter".to_owned(),
                AdapterRegistrationV2 {
                    adapter_id: "fixture-adapter".to_owned(),
                    protocol: "fixture.adapter/v1".to_owned(),
                    adapter_version: "fixture.adapter/v1".to_owned(),
                    executable_identity: format!("sha256:{}", "b".repeat(64)),
                    bounded_arguments: Vec::new(),
                },
            )]),
            work_items,
            budget_policy_ref: "policy:fixture".to_owned(),
            log_custody_root: "/tmp/ledger-fixture/log".to_owned(),
            receipt_custody_root: "/tmp/ledger-fixture/receipts".to_owned(),
            maximum_event_bytes: 65_536,
            maximum_worker_output_bytes: None,
            maximum_receipt_bytes: 65_536,
            adapter_timeout_seconds: 60,
            closeout_policy: "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED".to_owned(),
        };
        profile.seal().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("foreman.sqlite");
        ForemanStore::open(&path)
            .unwrap()
            .admit(
                PACKET,
                &serde_jcs::to_vec(&admission).unwrap(),
                &serde_jcs::to_vec(&profile).unwrap(),
                instant(),
            )
            .unwrap();
        (directory, path, admission.run_id)
    }

    fn recorded_execution_requirement_fixture_with_adapter(
        qualification_adapter: bool,
    ) -> (tempfile::TempDir, std::path::PathBuf, String) {
        let packet = NightshiftPacketV1::from_slice(PACKET).unwrap();
        let (adapter_id, adapter_protocol, adapter_version, executable_identity) =
            if qualification_adapter {
                (
                    nightshift_foreman::HOLDING_QUALIFICATION_PRODUCER_ID,
                    DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1,
                    nightshift_foreman::HOLDING_QUALIFICATION_PRODUCER_VERSION,
                    nightshift_foreman::HOLDING_QUALIFICATION_EXECUTABLE_SHA256,
                )
            } else {
                (
                    "switchyard-codex",
                    "switchyard.codex-app-server/v2",
                    "2.0.0",
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
            };
        let mut admission = ForemanAdmissionV1 {
            schema: FOREMAN_ADMISSION_SCHEMA_V1.to_owned(),
            admission_digest: format!("sha256:{}", "0".repeat(64)),
            run_id: "holding/casework:fixture".to_owned(),
            packet_digest: packet.packet_digest.clone(),
            operator_basis_digest: format!("sha256:{}", "a".repeat(64)),
            admitted_at: instant() - Duration::hours(1),
            expires_at: instant() + Duration::hours(1),
            local_runtime_identity: "holding-casework-fixture".to_owned(),
            maximum_concurrent_workers: 2,
            allowed_adapter_ids: vec![adapter_id.to_owned()],
            allowed_provider_model_classes: packet
                .work_items
                .iter()
                .map(|item| item.model_routing.class.clone())
                .collect(),
            maximum_new_attempts_per_work_item: 1,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
            target_effects_authorized: false,
        };
        admission.allowed_provider_model_classes.sort();
        admission.allowed_provider_model_classes.dedup();
        admission.seal().unwrap();
        let work_items = packet
            .work_items
            .iter()
            .map(|item| {
                (
                    item.id.clone(),
                    WorkItemExecutionV1 {
                        adapter_id: adapter_id.to_owned(),
                        workspace_identity: format!("workspace:{}", item.id),
                        resource_lock_keys: vec![format!("resource:{}", item.id)],
                        provider_model_class: item.model_routing.class.clone(),
                    },
                )
            })
            .collect();
        let mut profile = ExecutionProfileV2 {
            schema: FOREMAN_EXECUTION_PROFILE_SCHEMA_V2.to_owned(),
            profile_digest: format!("sha256:{}", "0".repeat(64)),
            packet_digest: packet.packet_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            adapters: BTreeMap::from([(
                adapter_id.to_owned(),
                AdapterRegistrationV2 {
                    adapter_id: adapter_id.to_owned(),
                    protocol: adapter_protocol.to_owned(),
                    adapter_version: adapter_version.to_owned(),
                    executable_identity: executable_identity.to_owned(),
                    bounded_arguments: vec![],
                },
            )]),
            work_items,
            budget_policy_ref: "holding-policy".to_owned(),
            log_custody_root: "/tmp/holding-casework/log".to_owned(),
            receipt_custody_root: "/tmp/holding-casework/receipts".to_owned(),
            maximum_event_bytes: 1024 * 1024,
            maximum_worker_output_bytes: None,
            maximum_receipt_bytes: 1024 * 1024,
            adapter_timeout_seconds: 60,
            closeout_policy: "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED".to_owned(),
        };
        profile.seal().unwrap();
        let mut policy = ExecutionAvailabilityPolicyV1 {
            schema: EXECUTION_AVAILABILITY_POLICY_SCHEMA_V1.to_owned(),
            policy_digest: format!("sha256:{}", "0".repeat(64)),
            policy_id: profile.budget_policy_ref.clone(),
            maximum_dispatch_occurrences_per_attempt: 4,
            backoff_seconds: vec![5, 10, 20, 40],
            maximum_total_deferral_seconds: 600,
            parked_resource_lock_policy: ParkedResourceLockPolicyV1::ReleaseAndReacquire,
            provider_capacity_released_while_parked: true,
            reconcile_indeterminate: true,
            allow_ordered_model_fallback: true,
            automatic_semantic_retry: false,
            approval_response_authorized: false,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        };
        policy.seal().unwrap();
        let selections = packet
            .work_items
            .iter()
            .map(|item| {
                (
                    item.id.clone(),
                    vec![
                        ProviderModelSelectionV1 {
                            provider_id: "openai".to_owned(),
                            model_id: "fixture-model".to_owned(),
                            model_class: item.model_routing.class.clone(),
                        },
                        ProviderModelSelectionV1 {
                            provider_id: "openai".to_owned(),
                            model_id: "fixture-fallback".to_owned(),
                            model_class: item.model_routing.class.clone(),
                        },
                    ],
                )
            })
            .collect();
        let adapter = &profile.adapters[adapter_id];
        let mut requirement = ForemanExecutionAvailabilityRequirementV1 {
            schema: FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1.to_owned(),
            requirement_digest: format!("sha256:{}", "0".repeat(64)),
            packet_digest: packet.packet_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            profile_digest: profile.profile_digest.clone(),
            run_id: admission.run_id.clone(),
            adapter_id: adapter.adapter_id.clone(),
            adapter_protocol: adapter.protocol.clone(),
            adapter_version: adapter.adapter_version.clone(),
            adapter_executable_identity: adapter.executable_identity.clone(),
            owner_pins: ProviderAdmissionOwnerPinsV1::accepted(),
            policy_id: policy.policy_id.clone(),
            policy_digest: policy.policy_digest.clone(),
            work_item_model_selections: selections,
            admitted_at: admission.admitted_at,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        };
        requirement.seal().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("foreman.sqlite");
        ForemanStore::open(&path)
            .unwrap()
            .admit_with_execution_availability(
                PACKET,
                &serde_jcs::to_vec(&admission).unwrap(),
                &serde_jcs::to_vec(&profile).unwrap(),
                &serde_jcs::to_vec(&requirement).unwrap(),
                &serde_jcs::to_vec(&policy).unwrap(),
                admission.admitted_at,
            )
            .unwrap();
        (directory, path, admission.run_id)
    }

    fn recorded_execution_requirement_fixture() -> (tempfile::TempDir, std::path::PathBuf, String) {
        recorded_execution_requirement_fixture_with_adapter(false)
    }

    fn recorded_qualification_execution_requirement_fixture(
    ) -> (tempfile::TempDir, std::path::PathBuf, String) {
        recorded_execution_requirement_fixture_with_adapter(true)
    }

    fn recorded_execution_dispatch_fixture() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let (directory, path, run_id) = recorded_execution_requirement_fixture();
        let packet = NightshiftPacketV1::from_slice(PACKET).unwrap();
        let work_item_id = packet
            .work_items
            .iter()
            .find(|item| item.dependencies.is_empty())
            .unwrap()
            .id
            .clone();
        ForemanStore::open(&path)
            .unwrap()
            .prepare_provider_attempt(
                &run_id,
                &work_item_id,
                "casework-dispatch-1",
                "casework-process-1",
                "casework-session-1",
                0,
                instant() - Duration::minutes(30),
            )
            .unwrap();
        (directory, path, run_id)
    }

    fn recorded_qualification_execution_dispatch_fixture(
    ) -> (tempfile::TempDir, std::path::PathBuf, String) {
        let (directory, path, run_id) = recorded_qualification_execution_requirement_fixture();
        let packet = NightshiftPacketV1::from_slice(PACKET).unwrap();
        let work_item_id = packet
            .work_items
            .iter()
            .find(|item| item.dependencies.is_empty())
            .unwrap()
            .id
            .clone();
        ForemanStore::open(&path)
            .unwrap()
            .prepare_provider_attempt(
                &run_id,
                &work_item_id,
                "casework-dispatch-1",
                "casework-process-1",
                "casework-session-1",
                0,
                instant() - Duration::minutes(30),
            )
            .unwrap();
        (directory, path, run_id)
    }

    fn qualification_rate_limit(
        opened: &nightshift_foreman::OpenedProviderDispatchV1,
        received_at: DateTime<Utc>,
    ) -> DeterministicProviderAdmissionEvidenceV1 {
        let retry_after = received_at + Duration::seconds(5);
        let raw = serde_jcs::to_vec(&serde_json::json!({
            "outcome": "RATE_LIMITED", "response_created": false,
            "non_admission_proven": true, "retry_after": retry_after,
            "observed_at": received_at,
        }))
        .unwrap();
        let mut evidence = DeterministicProviderAdmissionEvidenceV1 {
            schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1.to_owned(),
            evidence_digest: format!("sha256:{}", "0".repeat(64)),
            producer_id: nightshift_foreman::HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
            producer_version: nightshift_foreman::HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned(),
            executable_id: nightshift_foreman::HOLDING_QUALIFICATION_EXECUTABLE_ID.to_owned(),
            executable_sha256: nightshift_foreman::HOLDING_QUALIFICATION_EXECUTABLE_SHA256
                .to_owned(),
            work_attempt_id: opened.dispatch.work_attempt_id.clone(),
            dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
            provider_request_occurrence_id: "casework-request-1".to_owned(),
            provider_id: opened.dispatch.selection.provider_id.clone(),
            model_id: opened.dispatch.selection.model_id.clone(),
            outcome: DeterministicProviderAdmissionOutcomeV1::RateLimited,
            response_created: false,
            non_admission_proven: true,
            retry_after: Some(retry_after),
            observed_at: received_at,
            received_at,
            raw_evidence: ExactAvailabilityEvidenceV1::from_bytes(
                "EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES",
                &raw,
            )
            .unwrap(),
            authority_effect: "QUALIFICATION_MECHANISM_EVIDENCE_ONLY".to_owned(),
        };
        evidence.seal().unwrap();
        evidence
    }

    fn replace_fixture_strings(value: &mut serde_json::Value, replacements: &[(&str, &str)]) {
        match value {
            serde_json::Value::String(text) => {
                if let Some((_, replacement)) = replacements.iter().find(|(from, _)| text == from) {
                    *text = (*replacement).to_owned();
                }
            }
            serde_json::Value::Array(values) => values
                .iter_mut()
                .for_each(|value| replace_fixture_strings(value, replacements)),
            serde_json::Value::Object(values) => values
                .values_mut()
                .for_each(|value| replace_fixture_strings(value, replacements)),
            _ => {}
        }
    }

    fn seal_fixture_value(
        mut value: serde_json::Value,
        field: &str,
        domain: &[u8],
    ) -> serde_json::Value {
        value[field] = serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
        let mut basis = value.clone();
        basis.as_object_mut().unwrap().remove(field);
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(serde_jcs::to_vec(&basis).unwrap());
        value[field] = serde_json::Value::String(format!("sha256:{:x}", hash.finalize()));
        value
    }

    fn substitute_resource_edge(
        row: &mut nightshift_foreman::ReadOnlyEventRowV1,
        field: &str,
        digest: &str,
        release_event_id: bool,
    ) {
        let mut event: serde_json::Value = serde_json::from_slice(&row.raw_bytes).unwrap();
        event["payload"][field] = serde_json::json!(digest);
        if release_event_id {
            row.event_id = format!("provider-resources-released-{digest}");
            event["event_id"] = serde_json::json!(row.event_id);
        }
        row.raw_bytes = serde_jcs::to_vec(&event).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"nightshift.foreman-retained-raw.digest/v1\0");
        hash.update(&row.raw_bytes);
        row.raw_digest = format!("sha256:{:x}", hash.finalize());
    }

    fn substitute_requirement_selection(snapshot: &mut nightshift_foreman::ReadOnlyRunSnapshotV1) {
        let mut requirement = snapshot
            .execution_availability
            .as_ref()
            .unwrap()
            .requirement
            .clone();
        let dispatched_work_item = snapshot.execution_availability.as_ref().unwrap().dispatches[1]
            .work_item_id
            .clone();
        requirement
            .work_item_model_selections
            .get_mut(&dispatched_work_item)
            .unwrap()[1]
            .model_id = "substituted-fallback".to_owned();
        requirement.seal().unwrap();
        let requirement_bytes = serde_jcs::to_vec(&requirement).unwrap();
        let history = snapshot.execution_availability.as_mut().unwrap();
        history.requirement = requirement.clone();
        history.requirement_bytes.clone_from(&requirement_bytes);
        let row = snapshot
            .events
            .iter_mut()
            .find(|row| row.kind == "execution_availability_requirement")
            .unwrap();
        let mut event: serde_json::Value = serde_json::from_slice(&row.raw_bytes).unwrap();
        event["payload"]["requirement"] = serde_json::to_value(requirement).unwrap();
        event["payload"]["requirement_bytes"] = serde_json::to_value(requirement_bytes).unwrap();
        row.raw_bytes = serde_jcs::to_vec(&event).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"nightshift.foreman-retained-raw.digest/v1\0");
        hash.update(&row.raw_bytes);
        row.raw_digest = format!("sha256:{:x}", hash.finalize());
    }

    fn switchyard_snapshot(name: &str) -> serde_json::Value {
        if name == "waiting" {
            let mut snapshot: serde_json::Value = serde_json::from_slice(include_bytes!(
                "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-approval-interrupted.snapshot.v1.json"
            )).unwrap();
            let execution = snapshot["provider_execution_identity"].clone();
            let mut wire = serde_json::to_vec(&serde_json::json!({
                "method":"item/commandExecution/requestApproval",
                "params":{"threadId":"thread-holding-1","turnId":"turn-holding-1"}
            }))
            .unwrap();
            wire.push(b'\n');
            let approval = &mut snapshot["records"][3];
            approval["kind"] = serde_json::json!("WAITING_APPROVAL");
            approval["method"] = serde_json::json!("item/commandExecution/requestApproval");
            approval["raw"] = serde_json::json!({
                "representation":"EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR",
                "byte_length":wire.len(),"sha256":format!("sha256:{:x}",Sha256::digest(&wire)),
                "encoding":"hex","bytes_hex":hex::encode(wire)
            });
            approval["normalized"] = serde_json::json!({
                "approval_response_sent":false,"protected_effect_absent":true,
                "provider_execution_identity":execution
            });
            snapshot["records"].as_array_mut().unwrap().truncate(4);
            snapshot["acquisition_cut"] = serde_json::Value::Null;
            snapshot["admission_disposition"] = serde_json::json!("EXECUTION_ADMITTED");
            snapshot["mechanism_state"] = serde_json::json!("WAITING_APPROVAL");
            return snapshot;
        }
        let bytes: &[u8] = match name {
            "indeterminate" => include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-admission-indeterminate.snapshot.v1.json"),
            "interrupted" => include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-post-admission-interrupted.snapshot.v1.json"),
            "approval" => include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-approval-interrupted.snapshot.v1.json"),
            "completed" => include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json"),
            _ => panic!("unknown snapshot"),
        };
        serde_json::from_slice(bytes).unwrap()
    }

    fn retarget_switchyard_snapshot(
        mut snapshot: serde_json::Value,
        opened: &nightshift_foreman::OpenedProviderDispatchV1,
    ) -> Vec<u8> {
        let replacements = [
            (
                "attempt-holding-1",
                opened.dispatch.work_attempt_id.as_str(),
            ),
            (
                "dispatch-holding-1",
                opened.dispatch.dispatch_occurrence_id.as_str(),
            ),
            (
                "adapter-process-holding-1",
                opened.dispatch.adapter_process_occurrence_id.as_str(),
            ),
            (
                "fixture-estate-holding-1",
                opened.dispatch.app_server_session_identity.as_str(),
            ),
            ("gpt-5.6-sol", opened.dispatch.selection.model_id.as_str()),
        ];
        replace_fixture_strings(&mut snapshot, &replacements);
        for record in snapshot["records"].as_array_mut().unwrap() {
            if !record["raw"].is_null() {
                let bytes = hex::decode(record["raw"]["bytes_hex"].as_str().unwrap()).unwrap();
                let mut wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                replace_fixture_strings(&mut wire, &replacements);
                let mut exact = serde_json::to_vec(&wire).unwrap();
                exact.push(b'\n');
                record["raw"] = serde_json::json!({
                    "representation":"EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR",
                    "byte_length":exact.len(), "sha256":format!("sha256:{:x}", Sha256::digest(&exact)),
                    "encoding":"hex", "bytes_hex":hex::encode(exact),
                });
            }
        }
        snapshot["binding"] = seal_fixture_value(
            snapshot["binding"].clone(),
            "binding_digest",
            b"switchyard.codex-provider-admission-binding.digest/v1\0",
        );
        let binding_digest = snapshot["binding"]["binding_digest"].clone();
        for record in snapshot["records"].as_array_mut().unwrap() {
            record["binding_digest"] = binding_digest.clone();
            *record = seal_fixture_value(
                record.clone(),
                "evidence_digest",
                b"switchyard.codex-provider-admission-evidence.digest/v1\0",
            );
        }
        snapshot = seal_fixture_value(
            snapshot,
            "snapshot_digest",
            b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
        );
        serde_jcs::to_vec(&snapshot).unwrap()
    }

    fn switchyard_records(
        requirement: &ForemanExecutionAvailabilityRequirementV1,
        opened: &nightshift_foreman::OpenedProviderDispatchV1,
        name: &str,
        received_at: DateTime<Utc>,
    ) -> (
        ExecutionAvailabilityObservationV1,
        ProviderAdmissionDispositionV1,
    ) {
        let snapshot_bytes = retarget_switchyard_snapshot(switchyard_snapshot(name), opened);
        let snapshot: serde_json::Value = serde_json::from_slice(&snapshot_bytes).unwrap();
        let execution = snapshot["provider_execution_identity"]
            .as_object()
            .map(|identity| ProviderExecutionIdentityV1 {
                provider_id: identity["provider"].as_str().unwrap().to_owned(),
                model_id: identity["model"].as_str().unwrap().to_owned(),
                app_server_session_identity: identity["app_server_session_identity"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                thread_id: identity["thread_id"].as_str().unwrap().to_owned(),
                turn_id: identity["turn_id"].as_str().unwrap().to_owned(),
                first_response_id: identity["first_response_id"].as_str().unwrap().to_owned(),
            });
        let disposition_kind = match snapshot["admission_disposition"].as_str().unwrap() {
            "EXECUTION_ADMITTED" => ProviderAdmissionDispositionKindV1::ExecutionAdmitted,
            "ADMISSION_INDETERMINATE" => ProviderAdmissionDispositionKindV1::AdmissionIndeterminate,
            _ => panic!("unexpected disposition"),
        };
        let mechanism_state = match snapshot["mechanism_state"].as_str().unwrap() {
            "ADMISSION_INDETERMINATE" => ProviderMechanismStateV1::AdmissionIndeterminate,
            "POST_ADMISSION_INTERRUPTED" => ProviderMechanismStateV1::PostAdmissionInterrupted,
            "WAITING_APPROVAL" => ProviderMechanismStateV1::WaitingApproval,
            "PROVIDER_COMPLETED" => ProviderMechanismStateV1::ProviderCompleted,
            _ => panic!("unexpected mechanism state"),
        };
        let request_id = snapshot["records"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|record| record["normalized"]["request_occurrence_id"].as_str())
            .unwrap_or("request-0")
            .to_owned();
        let mut disposition = ProviderAdmissionDispositionV1 {
            schema: nightshift_foreman::PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1.to_owned(),
            disposition_digest: format!("sha256:{}", "0".repeat(64)),
            dispatch_digest: opened.dispatch.dispatch_digest.clone(),
            requirement_digest: requirement.requirement_digest.clone(),
            policy_digest: requirement.policy_digest.clone(),
            packet_digest: requirement.packet_digest.clone(),
            run_id: requirement.run_id.clone(),
            work_item_id: opened.dispatch.work_item_id.clone(),
            work_attempt_id: opened.dispatch.work_attempt_id.clone(),
            dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
            provider_id: opened.dispatch.selection.provider_id.clone(),
            model_id: opened.dispatch.selection.model_id.clone(),
            provider_request_occurrence_id: request_id,
            adapter_process_occurrence_id: opened.dispatch.adapter_process_occurrence_id.clone(),
            app_server_session_identity: opened.dispatch.app_server_session_identity.clone(),
            thread_id: snapshot["binding"]["thread_id"]
                .as_str()
                .unwrap()
                .to_owned(),
            turn_id: snapshot["binding"]["turn_id"].as_str().unwrap().to_owned(),
            disposition: disposition_kind,
            mechanism_state,
            received_at,
            response_created: execution.is_some(),
            will_retry: false,
            acquisition_complete: snapshot["acquisition_cut"]["clean"]
                .as_bool()
                .unwrap_or(false),
            provider_retry_after: None,
            provider_execution: execution,
            mapper_snapshot_schema: "switchyard.codex-provider-admission-snapshot/v1".to_owned(),
            mapper_snapshot_digest: snapshot["snapshot_digest"].as_str().unwrap().to_owned(),
            mapper_snapshot: ExactMapperSnapshotV1::from_bytes(&snapshot_bytes).unwrap(),
            approval_response_sent: false,
            protected_effect_absent: true,
            authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
        };
        disposition.seal().unwrap();
        let source_kind = match disposition.disposition {
            ProviderAdmissionDispositionKindV1::ExecutionAdmitted => "PROVIDER_EXECUTION_STEP",
            ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => "ADMISSION_DISCREPANCY",
            _ => unreachable!(),
        };
        let source = snapshot["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["kind"] == source_kind)
            .unwrap();
        let exact_evidence = if source["raw"].is_null() {
            None
        } else {
            Some(serde_json::from_value(source["raw"].clone()).unwrap())
        };
        let observed_at = source["normalized"]["observed_at_ms"]
            .as_i64()
            .and_then(DateTime::<Utc>::from_timestamp_millis)
            .unwrap_or(received_at);
        let state = match disposition.disposition {
            ProviderAdmissionDispositionKindV1::ExecutionAdmitted => {
                ExecutionAvailabilityStateV1::Available
            }
            ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => {
                ExecutionAvailabilityStateV1::Unknown
            }
            _ => unreachable!(),
        };
        let mut observation = ExecutionAvailabilityObservationV1 {
            schema: nightshift_foreman::EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1.to_owned(),
            observation_digest: format!("sha256:{}", "0".repeat(64)),
            provider_id: disposition.provider_id.clone(),
            model_id: disposition.model_id.clone(),
            model_class: opened.dispatch.selection.model_class.clone(),
            observed_at,
            received_at,
            expires_at: received_at + Duration::minutes(10),
            state,
            source_identity: "switchyard:provider-admission".to_owned(),
            source_version: "v1".to_owned(),
            provider_retry_after: None,
            exact_evidence,
            authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
        };
        observation.seal().unwrap();
        (observation, disposition)
    }

    fn recorded_switchyard_state_fixture(
        name: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf, String) {
        let (directory, path, run_id) = recorded_execution_dispatch_fixture();
        let snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let history = snapshot.execution_availability.unwrap();
        let opened = nightshift_foreman::OpenedProviderDispatchV1 {
            worker_start_request: history.worker_start_requests[0].clone(),
            dispatch: history.dispatches[0].clone(),
        };
        let (observation, disposition) = switchyard_records(
            &history.requirement,
            &opened,
            name,
            instant() + Duration::hours(8) + Duration::seconds(1),
        );
        let observation_bytes = serde_jcs::to_vec(&observation).unwrap();
        let disposition_bytes = serde_jcs::to_vec(&disposition).unwrap();
        ForemanStore::open(&path)
            .unwrap()
            .record_provider_disposition(
                &run_id,
                &disposition.work_item_id,
                &disposition.work_attempt_id,
                ProviderDispositionEvidenceV1 {
                    observation_bytes: &observation_bytes,
                    disposition_bytes: &disposition_bytes,
                    deferred_bytes: None,
                },
                None,
            )
            .unwrap();
        (directory, path, run_id)
    }

    fn recorded_execution_resume_fixture() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let (directory, path, run_id) = recorded_switchyard_state_fixture("interrupted");
        let snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let history = snapshot.execution_availability.unwrap();
        let disposition = &history.dispositions[0];
        let execution = disposition.provider_execution.as_ref().unwrap();
        ForemanStore::open(&path)
            .unwrap()
            .resume_provider_execution(
                &run_id,
                &disposition.work_item_id,
                &disposition.work_attempt_id,
                "casework-resume-1",
                &disposition.disposition_digest,
                "casework-process-resume-1",
                execution,
                disposition.received_at + Duration::seconds(1),
            )
            .unwrap();
        (directory, path, run_id)
    }

    fn qualification_parked_records(
        requirement: &ForemanExecutionAvailabilityRequirementV1,
        policy: &ExecutionAvailabilityPolicyV1,
        opened: &nightshift_foreman::OpenedProviderDispatchV1,
        received_at: DateTime<Utc>,
    ) -> (
        ExecutionAvailabilityObservationV1,
        ProviderAdmissionDispositionV1,
        DeferredProviderDispatchV1,
    ) {
        let evidence = qualification_rate_limit(opened, received_at);
        let evidence_bytes = serde_jcs::to_vec(&evidence).unwrap();
        let mut disposition = ProviderAdmissionDispositionV1 {
            schema: PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2.to_owned(),
            disposition_digest: format!("sha256:{}", "0".repeat(64)),
            dispatch_digest: opened.dispatch.dispatch_digest.clone(),
            requirement_digest: requirement.requirement_digest.clone(),
            policy_digest: policy.policy_digest.clone(),
            packet_digest: requirement.packet_digest.clone(),
            run_id: requirement.run_id.clone(),
            work_item_id: opened.dispatch.work_item_id.clone(),
            work_attempt_id: opened.dispatch.work_attempt_id.clone(),
            dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
            provider_id: opened.dispatch.selection.provider_id.clone(),
            model_id: opened.dispatch.selection.model_id.clone(),
            provider_request_occurrence_id: evidence.provider_request_occurrence_id.clone(),
            adapter_process_occurrence_id: opened.dispatch.adapter_process_occurrence_id.clone(),
            app_server_session_identity: opened.dispatch.app_server_session_identity.clone(),
            thread_id: "qualification-thread".to_owned(),
            turn_id: "qualification-turn".to_owned(),
            disposition: ProviderAdmissionDispositionKindV1::NotAdmittedRateLimited,
            mechanism_state: ProviderMechanismStateV1::ParkedNotAdmitted,
            received_at,
            response_created: false,
            will_retry: false,
            acquisition_complete: true,
            provider_retry_after: evidence.retry_after,
            provider_execution: None,
            mapper_snapshot_schema: evidence.schema.clone(),
            mapper_snapshot_digest: evidence.evidence_digest.clone(),
            mapper_snapshot: ExactMapperSnapshotV1::from_qualification_evidence_bytes(
                &evidence_bytes,
            )
            .unwrap(),
            approval_response_sent: false,
            protected_effect_absent: true,
            authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
        };
        disposition.seal().unwrap();
        let mut observation = ExecutionAvailabilityObservationV1 {
            schema: nightshift_foreman::EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1.to_owned(),
            observation_digest: format!("sha256:{}", "0".repeat(64)),
            provider_id: disposition.provider_id.clone(),
            model_id: disposition.model_id.clone(),
            model_class: opened.dispatch.selection.model_class.clone(),
            observed_at: received_at,
            received_at,
            expires_at: received_at + Duration::minutes(10),
            state: ExecutionAvailabilityStateV1::RateLimited,
            source_identity: nightshift_foreman::HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
            source_version: nightshift_foreman::HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned(),
            provider_retry_after: disposition.provider_retry_after,
            exact_evidence: Some(evidence.raw_evidence.clone()),
            authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
        };
        observation.seal().unwrap();
        let mut deferred = DeferredProviderDispatchV1 {
            schema: nightshift_foreman::DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1.to_owned(),
            deferred_dispatch_digest: format!("sha256:{}", "0".repeat(64)),
            requirement_digest: requirement.requirement_digest.clone(),
            policy_digest: policy.policy_digest.clone(),
            disposition_digest: disposition.disposition_digest.clone(),
            packet_digest: requirement.packet_digest.clone(),
            run_id: requirement.run_id.clone(),
            work_item_id: disposition.work_item_id.clone(),
            work_attempt_id: disposition.work_attempt_id.clone(),
            last_dispatch_occurrence_id: disposition.dispatch_occurrence_id.clone(),
            provider_id: disposition.provider_id.clone(),
            model_id: disposition.model_id.clone(),
            selected_model_ordinal: opened.dispatch.selected_model_ordinal,
            remaining_model_ordinals: vec![1],
            refusal_received_at: received_at,
            wake_basis: DeferredWakeBasisV1::ProviderRetryAfter,
            backoff_ordinal: opened.dispatch.dispatch_ordinal - 1,
            backoff_seconds: 5,
            provider_retry_after: disposition.provider_retry_after,
            wake_at: disposition.provider_retry_after.unwrap(),
            parked_resource_lock_policy: policy.parked_resource_lock_policy,
            provider_capacity_released: true,
            semantic_retry: false,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        };
        deferred.seal().unwrap();
        (observation, disposition, deferred)
    }

    fn recorded_execution_parked_fixture() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let (directory, path, run_id) = recorded_qualification_execution_dispatch_fixture();
        let snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let history = snapshot.execution_availability.unwrap();
        let opened = nightshift_foreman::OpenedProviderDispatchV1 {
            worker_start_request: history.worker_start_requests[0].clone(),
            dispatch: history.dispatches[0].clone(),
        };
        let received_at = instant() - Duration::minutes(29);
        let (observation, disposition, deferred) = qualification_parked_records(
            &history.requirement,
            &history.policy,
            &opened,
            received_at,
        );
        let observation_bytes = serde_jcs::to_vec(&observation).unwrap();
        let disposition_bytes = serde_jcs::to_vec(&disposition).unwrap();
        let deferred_bytes = serde_jcs::to_vec(&deferred).unwrap();
        ForemanStore::open(&path)
            .unwrap()
            .record_provider_disposition(
                &run_id,
                &disposition.work_item_id,
                &disposition.work_attempt_id,
                ProviderDispositionEvidenceV1 {
                    observation_bytes: &observation_bytes,
                    disposition_bytes: &disposition_bytes,
                    deferred_bytes: Some(&deferred_bytes),
                },
                None,
            )
            .unwrap();
        (directory, path, run_id)
    }

    fn recorded_execution_wake_fixture() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let (directory, path, run_id) = recorded_execution_parked_fixture();
        let snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let history = snapshot.execution_availability.unwrap();
        let first = &history.dispatches[0];
        ForemanStore::open(&path)
            .unwrap()
            .wake_provider_dispatch(
                &run_id,
                &first.work_item_id,
                &first.work_attempt_id,
                "casework-wake-1",
                "casework-dispatch-2",
                "casework-process-2",
                "casework-session-2",
                1,
                instant() - Duration::minutes(28),
            )
            .unwrap();
        (directory, path, run_id)
    }

    pub(crate) fn closed_fixture() -> (tempfile::TempDir, std::path::PathBuf, String, Vec<u8>) {
        let (directory, path, run_id) = fixture();
        let packet = NightshiftPacketV1::from_slice(PACKET).unwrap();
        let store = ForemanStore::open(&path).unwrap();
        for item in &packet.work_items {
            let mut receipt = NotStartedReceiptV1 {
                schema: WORK_ITEM_NOT_STARTED_RECEIPT_SCHEMA_V1.to_owned(),
                receipt_digest: format!("sha256:{}", "0".repeat(64)),
                packet_digest: packet.packet_digest.clone(),
                run_id: run_id.clone(),
                work_item_id: item.id.clone(),
                recorded_at: instant(),
                state: "NOT-STARTED-FIXTURE".to_owned(),
                result_classification: "INDEPENDENT-FIXTURE".to_owned(),
                evidence: vec!["bounded entry evidence".to_owned()],
                remaining_trigger: "explicit successor evidence".to_owned(),
                next_lawful_action: "inspect exact receipt".to_owned(),
                human_questions: Vec::new(),
                extensions: BTreeMap::new(),
            };
            receipt.seal().unwrap();
            store
                .accept_not_started(&serde_jcs::to_vec(&receipt).unwrap())
                .unwrap();
        }
        let final_bytes = store.close(&run_id, instant()).unwrap();
        (directory, path, run_id, final_bytes)
    }

    fn database_census(path: &Path) -> BTreeMap<String, Vec<u8>> {
        let directory = path.parent().unwrap();
        let mut census = BTreeMap::new();
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                census.insert(
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
        census
    }

    #[test]
    fn live_projection_is_exact_separate_and_query_only() {
        let (_directory, path, run_id) = fixture();
        let before = database_census(&path);
        let loaded = load_live_run_at(&path, &run_id, instant()).unwrap();
        let after = database_census(&path);

        assert_eq!(before, after);
        assert_eq!(loaded.packet_bytes, PACKET);
        assert_eq!(loaded.projection.schema, CASEWORK_LIVE_RUN_SCHEMA_V1);
        assert_eq!(loaded.projection.run_id, "ledger/live:fixture");
        assert_eq!(loaded.projection.navigation_id.len(), 64);
        assert_eq!(loaded.projection.foreman.lifecycle, "OPEN");
        assert_eq!(loaded.provider_execution.status, "NOT_RECORDED_BY_FOREMAN");
        assert!(loaded.provider_execution.requirement.is_none());
        assert_eq!(
            loaded.projection.provider_capacity.status,
            "NOT_RECORDED_BY_FOREMAN"
        );
        assert!(loaded
            .projection
            .work_items
            .iter()
            .all(|item| item.accepted_outcome.is_none()
                && item.accepted_outcome_absent_reason.is_some()));
        assert!(loaded
            .journal_framing_bytes
            .starts_with(FOREMAN_JOURNAL_FRAMING_V1));
        assert_eq!(
            loaded.accepted_receipts_framing_bytes,
            FOREMAN_ACCEPTED_RECEIPTS_FRAMING_V1
        );
        assert_eq!(loaded.projection.events.len(), 1);
        assert_eq!(
            loaded.event_bytes[&loaded.projection.events[0].sequence],
            loaded.journal_framing_bytes[FOREMAN_JOURNAL_FRAMING_V1.len() + 16..]
        );
    }

    #[test]
    fn recorded_execution_requirement_is_exact_restartable_and_query_only() {
        let (_directory, path, run_id) = recorded_execution_requirement_fixture();
        let before = database_census(&path);
        let first = load_live_run_at(&path, &run_id, instant()).unwrap();
        let second = load_live_run_at(&path, &run_id, instant()).unwrap();
        let after = database_census(&path);
        assert_eq!(before, after);
        assert_eq!(first.provider_execution, second.provider_execution);
        let projected = first.provider_execution;
        assert_eq!(projected.status, "EXACT_RECORDED_FOREMAN_HISTORY");
        assert_eq!(
            projected.independent_provider_capacity_status,
            "NOT_RECORDED_BY_FOREMAN"
        );
        let requirement = projected.requirement.unwrap();
        assert_eq!(requirement.provider_id, "openai");
        assert_eq!(
            requirement.adapter_protocol,
            "switchyard.codex-app-server/v2"
        );
        assert_eq!(requirement.journal_sequence, 2);
        assert!(requirement
            .work_item_model_selections
            .values()
            .all(|selections| {
                selections.len() == 2
                    && selections[0].provider_id == "openai"
                    && selections[0].model_id == "fixture-model"
                    && selections[1].provider_id == "openai"
                    && selections[1].model_id == "fixture-fallback"
                    && selections[0].model_class == selections[1].model_class
            }));
        assert!(!requirement.automatic_semantic_retry);
        assert!(!requirement.approval_response_authorized);
        assert!(projected.dispatches.is_empty());
        assert!(projected.dispositions.is_empty());
        assert!(projected.resource_transitions.is_empty());
    }

    #[test]
    fn recorded_provider_dispatch_retains_distinct_attempt_and_occurrence_custody() {
        let (_directory, path, run_id) = recorded_execution_dispatch_fixture();
        let before = database_census(&path);
        let loaded = load_live_run_at(&path, &run_id, instant()).unwrap();
        assert_eq!(before, database_census(&path));
        let dispatch = &loaded.provider_execution.dispatches[0];
        assert_eq!(dispatch.dispatch_occurrence_id, "casework-dispatch-1");
        assert_ne!(dispatch.work_attempt_id, dispatch.dispatch_occurrence_id);
        assert_eq!(dispatch.adapter_process_occurrence_id, "casework-process-1");
        assert_eq!(dispatch.app_server_session_identity, "casework-session-1");
        assert_eq!(dispatch.provider_id, "openai");
        assert!(dispatch.provider_execution_identity_absent_at_start);
        assert!(dispatch.journal_exact_bytes_sha256.starts_with("sha256:"));
        assert!(dispatch
            .start_request_exact_bytes_sha256
            .starts_with("sha256:"));
        assert!(loaded.provider_execution.dispositions.is_empty());
    }

    #[test]
    fn recorded_parked_disposition_retains_backoff_currentness_and_resource_release() {
        let (_directory, path, run_id) = recorded_execution_parked_fixture();
        let before = database_census(&path);
        let loaded = load_live_run_at(&path, &run_id, instant()).unwrap();
        assert_eq!(before, database_census(&path));
        let disposition = &loaded.provider_execution.dispositions[0];
        assert_eq!(disposition.availability_state, "RATE_LIMITED");
        assert_eq!(
            disposition.admission_disposition,
            "NOT_ADMITTED_RATE_LIMITED"
        );
        assert_eq!(disposition.mechanism_state, "PARKED_NOT_ADMITTED");
        assert_eq!(disposition.currentness, "EXPIRED");
        assert!(!disposition.response_created);
        assert!(disposition.provider_execution.is_none());
        let deferred = &loaded.provider_execution.deferrals[0];
        assert_eq!(deferred.wake_basis, "PROVIDER_RETRY_AFTER");
        assert_eq!(deferred.backoff_seconds, 5);
        assert_eq!(
            deferred.parked_resource_lock_policy,
            "RELEASE_AND_REACQUIRE"
        );
        assert_eq!(
            loaded.provider_execution.resource_transitions[0].transition,
            "RELEASED"
        );
        assert_eq!(
            loaded.provider_execution.resource_transitions[0]
                .disposition_digest
                .as_deref(),
            Some(disposition.disposition_digest.as_str())
        );
        assert!(loaded.provider_execution.resource_transitions[0]
            .deferred_dispatch_digest
            .is_none());
        assert_eq!(
            loaded
                .provider_execution
                .independent_provider_capacity_status,
            "NOT_RECORDED_BY_FOREMAN"
        );
    }

    #[test]
    fn recorded_wake_retains_fresh_dispatch_and_resource_reacquisition() {
        let (_directory, path, run_id) = recorded_execution_wake_fixture();
        let loaded = load_live_run_at(&path, &run_id, instant()).unwrap();
        assert_eq!(loaded.provider_execution.dispatches.len(), 2);
        let wake = &loaded.provider_execution.wakes[0];
        let next = &loaded.provider_execution.dispatches[1];
        assert_eq!(wake.wake_occurrence_id, "casework-wake-1");
        assert_eq!(wake.next_dispatch_digest, next.dispatch_digest);
        assert_eq!(next.dispatch_occurrence_id, "casework-dispatch-2");
        assert_eq!(next.selected_model_ordinal, 1);
        assert_eq!(next.model_id, "fixture-fallback");
        assert_eq!(
            loaded.provider_execution.resource_transitions[1].transition,
            "REACQUIRED"
        );
        assert_eq!(
            loaded.provider_execution.resource_transitions[1]
                .wake_occurrence_id
                .as_deref(),
            Some("casework-wake-1")
        );
        assert_eq!(
            loaded.provider_execution.resource_transitions[1]
                .deferred_dispatch_digest
                .as_deref(),
            loaded.provider_execution.deferrals[0]
                .deferred_dispatch_digest
                .as_str()
                .into()
        );
        assert!(loaded.provider_execution.resource_transitions[1]
            .disposition_digest
            .is_none());
    }

    #[test]
    fn exact_switchyard_states_remain_distinct_and_never_gain_authority() {
        for (fixture, mechanism, admitted) in [
            ("indeterminate", "ADMISSION_INDETERMINATE", false),
            ("interrupted", "POST_ADMISSION_INTERRUPTED", true),
            ("waiting", "WAITING_APPROVAL", true),
            ("approval", "POST_ADMISSION_INTERRUPTED", true),
            ("completed", "PROVIDER_COMPLETED", true),
        ] {
            let (_directory, path, run_id) = recorded_switchyard_state_fixture(fixture);
            let loaded = load_live_run_at(&path, &run_id, instant()).unwrap();
            let disposition = &loaded.provider_execution.dispositions[0];
            assert_eq!(disposition.mechanism_state, mechanism);
            assert_eq!(disposition.provider_execution.is_some(), admitted);
            assert!(!disposition.approval_response_sent);
            assert!(disposition.protected_effect_absent);
            assert_eq!(
                loaded.provider_execution.authority_effect,
                "READ_ONLY_MECHANISM_PROJECTION"
            );
        }
    }

    #[test]
    fn post_admission_resume_retains_same_execution_and_fresh_process_occurrence() {
        let (_directory, path, run_id) = recorded_execution_resume_fixture();
        let loaded = load_live_run_at(&path, &run_id, instant()).unwrap();
        let disposition = &loaded.provider_execution.dispositions[0];
        let resume = &loaded.provider_execution.resumes[0];
        assert_eq!(resume.disposition_digest, disposition.disposition_digest);
        assert_eq!(
            resume.execution_identity,
            disposition.provider_execution.clone().unwrap()
        );
        assert_eq!(resume.resume_occurrence_id, "casework-resume-1");
        assert_eq!(
            resume.adapter_process_occurrence_id,
            "casework-process-resume-1"
        );
        assert_eq!(loaded.provider_execution.dispatches.len(), 1);
    }

    #[test]
    fn provider_execution_nested_raw_substitution_refuses_before_projection() {
        let (_directory, path, run_id) = recorded_execution_requirement_fixture();
        let mut snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let row = snapshot
            .events
            .iter_mut()
            .find(|row| row.kind == "execution_availability_requirement")
            .unwrap();
        let mut event: serde_json::Value = serde_json::from_slice(&row.raw_bytes).unwrap();
        event["payload"]["requirement_bytes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!(32));
        row.raw_bytes = serde_jcs::to_vec(&event).unwrap();
        let mut digest = Sha256::new();
        digest.update(b"nightshift.foreman-retained-raw.digest/v1\0");
        digest.update(&row.raw_bytes);
        row.raw_digest = format!("sha256:{:x}", digest.finalize());
        let packet = NightshiftPacketV1::from_slice(&snapshot.packet_bytes).unwrap();
        let admission = ForemanAdmissionV1::from_slice(&snapshot.admission_bytes).unwrap();
        let profile = ExecutionProfileV2::from_slice(&snapshot.profile_bytes).unwrap();
        assert!(crate::live_execution::project_provider_execution(
            &snapshot,
            &packet,
            &admission,
            &profile,
            instant(),
            "NOT_RECORDED_BY_FOREMAN",
        )
        .is_err());
    }

    #[test]
    fn provider_execution_ordered_selection_substitution_refuses_exact_journal() {
        let (_directory, path, run_id) = recorded_execution_requirement_fixture();
        let mut snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let history = snapshot.execution_availability.as_mut().unwrap();
        history
            .requirement
            .work_item_model_selections
            .values_mut()
            .next()
            .unwrap()[1]
            .model_id = "substituted-fallback".to_owned();
        let packet = NightshiftPacketV1::from_slice(&snapshot.packet_bytes).unwrap();
        let admission = ForemanAdmissionV1::from_slice(&snapshot.admission_bytes).unwrap();
        let profile = ExecutionProfileV2::from_slice(&snapshot.profile_bytes).unwrap();

        assert!(crate::live_execution::project_provider_execution(
            &snapshot,
            &packet,
            &admission,
            &profile,
            instant(),
            "NOT_RECORDED_BY_FOREMAN",
        )
        .is_err());
    }

    #[test]
    fn coherent_ordered_selection_and_raw_journal_substitution_refuses_dispatch_graph() {
        let (_directory, path, run_id) = recorded_execution_wake_fixture();
        let mut snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        substitute_requirement_selection(&mut snapshot);
        let packet = NightshiftPacketV1::from_slice(&snapshot.packet_bytes).unwrap();
        let admission = ForemanAdmissionV1::from_slice(&snapshot.admission_bytes).unwrap();
        let profile = ExecutionProfileV2::from_slice(&snapshot.profile_bytes).unwrap();

        assert!(crate::live_execution::project_provider_execution(
            &snapshot,
            &packet,
            &admission,
            &profile,
            instant(),
            "NOT_RECORDED_BY_FOREMAN",
        )
        .is_err());
    }

    #[test]
    fn provider_resource_predecessor_substitution_refuses_exact_journal() {
        let (_directory, path, run_id) = recorded_execution_parked_fixture();
        let mut snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        snapshot
            .execution_availability
            .as_mut()
            .unwrap()
            .resource_transitions[0]
            .disposition_digest = Some(format!("sha256:{}", "f".repeat(64)));
        let packet = NightshiftPacketV1::from_slice(&snapshot.packet_bytes).unwrap();
        let admission = ForemanAdmissionV1::from_slice(&snapshot.admission_bytes).unwrap();
        let profile = ExecutionProfileV2::from_slice(&snapshot.profile_bytes).unwrap();

        assert!(crate::live_execution::project_provider_execution(
            &snapshot,
            &packet,
            &admission,
            &profile,
            instant(),
            "NOT_RECORDED_BY_FOREMAN",
        )
        .is_err());
    }

    #[test]
    fn coherent_resource_edge_and_raw_journal_substitutions_refuse() {
        let substituted = format!("sha256:{}", "e".repeat(64));
        let (_directory, path, run_id) = recorded_execution_parked_fixture();
        let mut snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let row = snapshot
            .events
            .iter_mut()
            .find(|row| row.kind == "provider_resources_released")
            .unwrap();
        substitute_resource_edge(row, "disposition_digest", &substituted, true);
        snapshot
            .execution_availability
            .as_mut()
            .unwrap()
            .resource_transitions[0]
            .disposition_digest = Some(substituted.clone());
        let packet = NightshiftPacketV1::from_slice(&snapshot.packet_bytes).unwrap();
        let admission = ForemanAdmissionV1::from_slice(&snapshot.admission_bytes).unwrap();
        let profile = ExecutionProfileV2::from_slice(&snapshot.profile_bytes).unwrap();
        assert!(crate::live_execution::project_provider_execution(
            &snapshot,
            &packet,
            &admission,
            &profile,
            instant(),
            "NOT_RECORDED_BY_FOREMAN",
        )
        .is_err());

        let (_directory, path, run_id) = recorded_execution_wake_fixture();
        let mut snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let row = snapshot
            .events
            .iter_mut()
            .find(|row| row.kind == "provider_resources_reacquired")
            .unwrap();
        substitute_resource_edge(row, "deferred_dispatch_digest", &substituted, false);
        snapshot
            .execution_availability
            .as_mut()
            .unwrap()
            .resource_transitions[1]
            .deferred_dispatch_digest = Some(substituted);
        let packet = NightshiftPacketV1::from_slice(&snapshot.packet_bytes).unwrap();
        let admission = ForemanAdmissionV1::from_slice(&snapshot.admission_bytes).unwrap();
        let profile = ExecutionProfileV2::from_slice(&snapshot.profile_bytes).unwrap();
        assert!(crate::live_execution::project_provider_execution(
            &snapshot,
            &packet,
            &admission,
            &profile,
            instant(),
            "NOT_RECORDED_BY_FOREMAN",
        )
        .is_err());
    }

    #[test]
    fn absent_and_substituted_read_sources_fail_closed_without_files() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent.sqlite");
        assert!(load_live_run_at(&absent, "run", instant()).is_err());
        assert!(!absent.exists());

        let (_owned, path, _) = fixture();
        assert!(load_live_run_at(&path, "substituted-run", instant()).is_err());
    }

    #[test]
    fn canonical_accepted_receipt_content_mutation_refuses_casework_projection() {
        let (_directory, path, run_id, _) = closed_fixture();
        let mut snapshot = nightshift_foreman::read_only_run_snapshot(&path, &run_id).unwrap();
        let receipt_row = snapshot.terminal_receipts.first_mut().unwrap();
        let mut receipt = NotStartedReceiptV1::from_slice(&receipt_row.raw_bytes).unwrap();
        receipt.next_lawful_action = "canonical content mutation without resealing".to_owned();
        receipt_row.raw_bytes = serde_jcs::to_vec(&receipt).unwrap();
        assert!(accepted_receipt_questions(receipt_row).is_err());
    }

    #[test]
    fn same_question_id_with_disagreeing_receipt_and_mechanism_refuses() {
        let (_directory, path, run_id) = fixture();
        let packet = NightshiftPacketV1::from_slice(PACKET).unwrap();
        let work_item_id = packet
            .work_items
            .iter()
            .find(|item| item.dependencies.is_empty())
            .unwrap()
            .id
            .clone();
        let store = ForemanStore::open(&path).unwrap();
        let request = store
            .prepare_attempt(&run_id, &work_item_id, instant())
            .unwrap();
        store
            .record_dispatch_requested(&run_id, &work_item_id, &request.attempt_id, instant())
            .unwrap();
        let mechanism_question = HumanQuestionV1 {
            question_id: "question:receipt-mechanism-agreement".to_owned(),
            question: "Which exact local qualification basis applies?".to_owned(),
            exhausted_evidence: "The retained mechanism evidence is complete.".to_owned(),
            safe_default: "Keep the lane stopped.".to_owned(),
            consequences: "No protected effect occurs.".to_owned(),
            resume_point: "Create a successor occurrence after exact evidence exists.".to_owned(),
        };
        let mut event = AdapterEventV1 {
            schema: WORKER_ADAPTER_EVENT_SCHEMA_V1.to_owned(),
            event_digest: format!("sha256:{}", "0".repeat(64)),
            event_id: "casework-question-event".to_owned(),
            packet_digest: packet.packet_digest.clone(),
            run_id: run_id.clone(),
            work_item_id: work_item_id.clone(),
            attempt_id: request.attempt_id.clone(),
            adapter_id: "fixture-adapter".to_owned(),
            adapter_version: "fixture.adapter/v1".to_owned(),
            occurred_at: instant(),
            kind: AdapterEventKindV1::HumanQuestion,
            provider_identity: Some("provider:fixture".to_owned()),
            model_identity: Some("model:fixture".to_owned()),
            session_identity: Some("session:fixture".to_owned()),
            thread_identity: None,
            turn_identity: None,
            queue_identity: None,
            message: None,
            human_question: Some(mechanism_question.clone()),
            extensions: BTreeMap::new(),
        };
        event.seal().unwrap();
        store
            .accept_adapter_event(&serde_jcs::to_vec(&event).unwrap())
            .unwrap();

        let mut receipt_question = mechanism_question;
        receipt_question.safe_default = "Disagreeing substituted safe default.".to_owned();
        let mut receipt = TerminalReceiptV1 {
            schema: WORKER_TERMINAL_RECEIPT_SCHEMA_V1.to_owned(),
            receipt_digest: format!("sha256:{}", "0".repeat(64)),
            packet_digest: packet.packet_digest.clone(),
            run_id: run_id.clone(),
            work_item_id: work_item_id.clone(),
            attempt_id: request.attempt_id.clone(),
            adapter_id: "fixture-adapter".to_owned(),
            adapter_version: "fixture.adapter/v1".to_owned(),
            provider_identity: "provider:fixture".to_owned(),
            model_identity: "model:fixture".to_owned(),
            session_identity: Some("session:fixture".to_owned()),
            thread_identity: None,
            turn_identity: None,
            queue_identity: None,
            started_at: instant(),
            ended_at: instant() + Duration::seconds(1),
            state: "BLOCKED-HUMAN-EXACT".to_owned(),
            result_classification: "SECOND-WATCH-QUESTION".to_owned(),
            repositories: vec![ReceiptRepositoryV1 {
                repository: "nightshift".to_owned(),
                branch: "campaign/second-watch-fixture".to_owned(),
                head: "f".repeat(40),
                push_status: "sole-local fixture".to_owned(),
            }],
            tests: vec!["question disagreement fixture".to_owned()],
            evidence: vec!["exact receipt question".to_owned()],
            live_or_production_mutations: Vec::new(),
            remaining_trigger: "exact question agreement".to_owned(),
            next_lawful_action: "inspect the exact disagreement".to_owned(),
            human_questions: vec![receipt_question],
            teardown: TeardownDeclarationV1 {
                live_runtime: "none".to_owned(),
                secrets: "none".to_owned(),
                teardown: "none".to_owned(),
            },
            extensions: BTreeMap::new(),
        };
        receipt.seal().unwrap();
        store
            .accept_terminal_receipt(&serde_jcs::to_vec(&receipt).unwrap())
            .unwrap();
        drop(store);
        assert!(load_live_run_at(&path, &run_id, instant() + Duration::seconds(1)).is_err());
    }

    #[test]
    fn repeated_lane_local_question_ids_have_distinct_navigation_ids() {
        let first = question_navigation_id("lane-a", "question:shared");
        let second = question_navigation_id("lane-b", "question:shared");
        assert_ne!(first, second);
        assert_eq!(first, question_navigation_id("lane-a", "question:shared"));
        assert_eq!(first.len(), 64);
    }

    fn recorded_capacity_fixture() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let packet = NightshiftPacketV1::from_slice(PACKET).unwrap();
        packet.validate_integrity().unwrap();
        let mut admission = ForemanAdmissionV1 {
            schema: FOREMAN_ADMISSION_SCHEMA_V1.to_owned(),
            admission_digest: format!("sha256:{}", "0".repeat(64)),
            run_id: "capacity-glass/live:fixture".to_owned(),
            packet_digest: packet.packet_digest.clone(),
            operator_basis_digest: format!("sha256:{}", "a".repeat(64)),
            admitted_at: instant() - Duration::hours(1),
            expires_at: instant() + Duration::hours(1),
            local_runtime_identity: "capacity-glass-fixture".to_owned(),
            maximum_concurrent_workers: 2,
            allowed_adapter_ids: vec!["fixture-adapter".to_owned()],
            allowed_provider_model_classes: vec!["large".to_owned()],
            maximum_new_attempts_per_work_item: 1,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
            target_effects_authorized: false,
        };
        admission.seal().unwrap();
        let policy = CapacityPolicyV1::default();
        let work_items = packet
            .work_items
            .iter()
            .map(|item| {
                (
                    item.id.clone(),
                    WorkItemExecutionV1 {
                        adapter_id: "fixture-adapter".to_owned(),
                        workspace_identity: format!("workspace:{}", item.id),
                        resource_lock_keys: vec![format!("resource:{}", item.id)],
                        provider_model_class: item.model_routing.class.clone(),
                    },
                )
            })
            .collect();
        let mut profile = ExecutionProfileV2 {
            schema: FOREMAN_EXECUTION_PROFILE_SCHEMA_V2.to_owned(),
            profile_digest: format!("sha256:{}", "0".repeat(64)),
            packet_digest: packet.packet_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            adapters: BTreeMap::from([(
                "fixture-adapter".to_owned(),
                AdapterRegistrationV2 {
                    adapter_id: "fixture-adapter".to_owned(),
                    protocol: "fixture.adapter/v1".to_owned(),
                    adapter_version: "fixture.adapter/v1".to_owned(),
                    executable_identity: format!("sha256:{}", "b".repeat(64)),
                    bounded_arguments: Vec::new(),
                },
            )]),
            work_items,
            budget_policy_ref: policy.policy_id.clone(),
            log_custody_root: "/tmp/capacity-glass-fixture/log".to_owned(),
            receipt_custody_root: "/tmp/capacity-glass-fixture/receipts".to_owned(),
            maximum_event_bytes: 65_536,
            maximum_worker_output_bytes: None,
            maximum_receipt_bytes: 65_536,
            adapter_timeout_seconds: 60,
            closeout_policy: "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED".to_owned(),
        };
        profile.seal().unwrap();
        let mut requirement = ForemanCapacityRequirementV1 {
            schema: FOREMAN_CAPACITY_REQUIREMENT_SCHEMA_V1.to_owned(),
            capacity_requirement_digest: format!("sha256:{}", "0".repeat(64)),
            packet_digest: packet.packet_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            profile_digest: profile.profile_digest.clone(),
            run_id: admission.run_id.clone(),
            policy_id: policy.policy_id.clone(),
            provider_id: "provider:fixture".to_owned(),
            model_cost_classes: BTreeMap::from([(
                "large".to_owned(),
                CapacityCostClassV1::Expensive,
            )]),
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        };
        requirement.seal().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("foreman.sqlite");
        let store = ForemanStore::open(&path).unwrap();
        store
            .admit_with_capacity_requirement(
                PACKET,
                &serde_jcs::to_vec(&admission).unwrap(),
                &serde_jcs::to_vec(&profile).unwrap(),
                &serde_jcs::to_vec(&requirement).unwrap(),
                instant() - Duration::minutes(1),
            )
            .unwrap();
        let at = instant();
        let mut observation = CapacityObservationV1 {
            schema: CAPACITY_OBSERVATION_SCHEMA_V1.to_owned(),
            provider_id: "provider:fixture".to_owned(),
            account_profile_locator: "fixture-profile".to_owned(),
            model_family: Some("large".to_owned()),
            observed_at: at - Duration::seconds(1),
            expires_at: at + Duration::minutes(10),
            source_class: SourceClass::Observed,
            confidence: Confidence::High,
            disposition: ObservationDisposition::Usable,
            unknown_reasons: Vec::new(),
            windows: vec![
                CapacityWindow {
                    window_id: "five-hour".to_owned(),
                    window_type: WindowType::FiveHour,
                    remaining_fraction: Some(0.75),
                    remaining_units: None,
                    resets_at: Some(at + Duration::hours(1)),
                },
                CapacityWindow {
                    window_id: "weekly".to_owned(),
                    window_type: WindowType::Weekly,
                    remaining_fraction: Some(0.75),
                    remaining_units: None,
                    resets_at: Some(at + Duration::days(1)),
                },
            ],
            evidence: ObservationEvidence {
                probe_id: "capacity-glass-fixture".to_owned(),
                protocol_method: "fixture/read".to_owned(),
                protocol_version: Some("fixture/v1".to_owned()),
                executable_path: Some("/fixture/provider-observer".to_owned()),
                executable_digest: Some(format!("sha256:{}", "1".repeat(64))),
                raw_source_digest: format!("sha256:{}", "2".repeat(64)),
            },
            observation_digest: String::new(),
        };
        observation.observation_digest = observation.compute_digest().unwrap();
        let decision = decide_capacity(&observation, &policy, at).unwrap();
        let mut capacity_admission = ForemanCapacityAdmissionV1 {
            schema: FOREMAN_CAPACITY_ADMISSION_SCHEMA_V1.to_owned(),
            capacity_admission_digest: format!("sha256:{}", "0".repeat(64)),
            packet_digest: packet.packet_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            profile_digest: profile.profile_digest.clone(),
            capacity_requirement_digest: requirement.capacity_requirement_digest.clone(),
            run_id: admission.run_id.clone(),
            work_item_id: "foreman-core".to_owned(),
            adapter_id: "fixture-adapter".to_owned(),
            provider_id: observation.provider_id.clone(),
            packet_model_class: "large".to_owned(),
            profile_model_class: "large".to_owned(),
            cost_class: CapacityCostClassV1::Expensive,
            policy_id: policy.policy_id.clone(),
            observation_digest: observation.observation_digest.clone(),
            policy_digest: policy.policy_digest.clone(),
            decision_digest: decision.decision_digest.clone(),
            evaluated_at: at,
            speculative_requested: false,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        };
        capacity_admission.seal().unwrap();
        let admission_bytes = serde_jcs::to_vec(&capacity_admission).unwrap();
        let observation_bytes = serde_jcs::to_vec(&observation).unwrap();
        let policy_bytes = serde_jcs::to_vec(&policy).unwrap();
        let decision_bytes = serde_jcs::to_vec(&decision).unwrap();
        store
            .prepare_attempt_with_capacity(
                &admission.run_id,
                "foreman-core",
                CapacityAdmissionEvidenceV1 {
                    admission_bytes: &admission_bytes,
                    observation_bytes: &observation_bytes,
                    policy_bytes: &policy_bytes,
                    decision_bytes: &decision_bytes,
                },
                at,
            )
            .unwrap();
        (directory, path, admission.run_id)
    }

    fn retained_event_digest(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"nightshift.foreman-retained-raw.digest/v1\0");
        hasher.update(bytes);
        format!("sha256:{:x}", hasher.finalize())
    }

    #[test]
    fn recorded_capacity_is_exact_ordered_restartable_and_substitution_closed() {
        let (_directory, path, run_id) = recorded_capacity_fixture();
        let before = database_census(&path);
        let first = load_live_run_at(&path, &run_id, instant()).unwrap();
        let restarted = load_live_run_at(&path, &run_id, instant()).unwrap();
        let after = database_census(&path);
        assert_eq!(before, after);
        assert_eq!(first.projection, restarted.projection);
        assert_eq!(
            first.projection.provider_capacity.status,
            "EXACT_RECORDED_BY_FOREMAN"
        );
        assert_eq!(
            first.projection.execution_profile.capacity_binding_status,
            "EXACT_RECORDED_CAPACITY_REQUIREMENT"
        );
        let requirement = first
            .projection
            .provider_capacity
            .requirement
            .as_ref()
            .unwrap();
        assert_eq!(requirement.provider_id, "provider:fixture");
        assert_eq!(requirement.model_cost_classes["large"], "EXPENSIVE");
        let attempts = &first.projection.provider_capacity.attempts;
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].work_item_id, "foreman-core");
        assert_eq!(attempts[0].capacity_state, "ABUNDANT");
        assert_eq!(attempts[0].admission_disposition, "ORDINARY_BOUNDED");
        assert_eq!(attempts[0].source_class, "OBSERVED");
        assert_eq!(attempts[0].confidence, "HIGH");
        assert_eq!(attempts[0].currentness, "CURRENT");

        let snapshot = read_only_run_snapshot(&path, &run_id).unwrap();
        let historical = project(snapshot.clone(), instant() + Duration::minutes(11)).unwrap();
        assert_eq!(
            historical.projection.provider_capacity.attempts[0].currentness,
            "EXPIRED"
        );
        let mut split_requirement = snapshot.clone();
        let requirement_event = split_requirement
            .events
            .iter_mut()
            .find(|event| event.kind == "capacity_requirement")
            .unwrap();
        let mut event_value: Value = serde_json::from_slice(&requirement_event.raw_bytes).unwrap();
        let mut nested_requirement: ForemanCapacityRequirementV1 =
            serde_json::from_value(event_value["payload"]["requirement"].clone()).unwrap();
        nested_requirement.provider_id = "provider:split-journal".to_owned();
        nested_requirement.seal().unwrap();
        let nested_requirement_bytes = serde_jcs::to_vec(&nested_requirement).unwrap();
        event_value["payload"]["requirement"] = serde_json::to_value(&nested_requirement).unwrap();
        event_value["payload"]["requirement_bytes"] =
            serde_json::to_value(&nested_requirement_bytes).unwrap();
        requirement_event.raw_bytes = serde_jcs::to_vec(&event_value).unwrap();
        requirement_event.raw_digest = retained_event_digest(&requirement_event.raw_bytes);
        assert!(project(split_requirement, instant()).is_err());

        let mut split_admission = snapshot.clone();
        let admission_event = split_admission
            .events
            .iter_mut()
            .find(|event| event.kind == "capacity_admission")
            .unwrap();
        let mut event_value: Value = serde_json::from_slice(&admission_event.raw_bytes).unwrap();
        let mut nested_admission: ForemanCapacityAdmissionV1 =
            serde_json::from_value(event_value["payload"]["capacity_admission"].clone()).unwrap();
        nested_admission.provider_id = "provider:split-journal".to_owned();
        nested_admission.seal().unwrap();
        let nested_admission_bytes = serde_jcs::to_vec(&nested_admission).unwrap();
        event_value["payload"]["capacity_admission"] =
            serde_json::to_value(&nested_admission).unwrap();
        event_value["payload"]["admission_bytes"] =
            serde_json::to_value(&nested_admission_bytes).unwrap();
        admission_event.raw_bytes = serde_jcs::to_vec(&event_value).unwrap();
        admission_event.raw_digest = retained_event_digest(&admission_event.raw_bytes);
        assert!(project(split_admission, instant()).is_err());

        let mut substituted = snapshot.clone();
        substituted.capacity_admissions[0]
            .capacity_admission
            .provider_id = "provider:substituted".to_owned();
        assert!(project(substituted, instant()).is_err());
        let mut mutated = snapshot;
        mutated.capacity_admissions[0].observation_bytes.push(b' ');
        assert!(project(mutated, instant()).is_err());
    }

    #[test]
    #[ignore = "set NIGHTSHIFT_CASEWORK_PROVIDER_EXECUTION_FIXTURE_DIR for schema qualification"]
    fn emit_provider_execution_schema_fixture() {
        let output = std::env::var_os("NIGHTSHIFT_CASEWORK_PROVIDER_EXECUTION_FIXTURE_DIR")
            .map(std::path::PathBuf::from)
            .expect(
                "NIGHTSHIFT_CASEWORK_PROVIDER_EXECUTION_FIXTURE_DIR must name an explicit temporary directory",
            );
        assert!(output.is_dir());
        let (_directory, path, run_id) = recorded_execution_wake_fixture();
        let projection = load_live_run_at(&path, &run_id, instant())
            .unwrap()
            .provider_execution;
        fs::write(
            output.join("provider-execution.v1.json"),
            serde_json::to_vec(&projection).unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[ignore = "set NIGHTSHIFT_LEDGER_FIXTURE_DIR for the installed-browser qualification journey"]
    fn emit_installed_browser_fixture() {
        let output = std::env::var_os("NIGHTSHIFT_LEDGER_FIXTURE_DIR")
            .map(std::path::PathBuf::from)
            .expect("NIGHTSHIFT_LEDGER_FIXTURE_DIR must name an explicit temporary directory");
        assert!(output.is_dir());
        let (source, database, run_id, final_bytes) = closed_fixture();
        for entry in fs::read_dir(source.path()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                fs::copy(entry.path(), output.join(entry.file_name())).unwrap();
            }
        }
        let case = output.join("sealed-case");
        fs::create_dir(&case).unwrap();
        fs::write(case.join("packet.v1.json"), PACKET).unwrap();
        fs::write(case.join("run-receipts.v1.json"), final_bytes).unwrap();
        assert!(output.join(database.file_name().unwrap()).is_file());
        assert_eq!(run_id, "ledger/live:fixture");
    }
}
