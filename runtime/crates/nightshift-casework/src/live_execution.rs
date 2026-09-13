use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use nightshift_foreman::{
    reopen_execution_availability_journal_event, DeferredProviderDispatchV1,
    ExecutionAvailabilityObservationV1, ExecutionProfileV2, ForemanAdmissionV1,
    ProviderAdmissionDispositionV1, ProviderDispatchOccurrenceV1, ProviderExecutionIdentityV1,
    ReadOnlyEventRowV1, ReadOnlyExecutionAvailabilityHistoryV1,
    ReadOnlyExecutionAvailabilityJournalEventV1, ReadOnlyRunSnapshotV1, WorkerStartRequestV3,
};
use nightshiftd::packet::NightshiftPacketV1;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{live_loader::LiveCaseworkError, live_model::*};

const EVENT_KINDS: &[&str] = &[
    "execution_availability_requirement",
    "provider_dispatch",
    "provider_disposition",
    "provider_wake",
    "provider_resume",
    "provider_resources_released",
    "provider_resources_reacquired",
];

pub(crate) fn project_provider_execution(
    snapshot: &ReadOnlyRunSnapshotV1,
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    evaluated_at: DateTime<Utc>,
    capacity_status: &str,
) -> Result<CaseworkLiveProviderExecutionV1, LiveCaseworkError> {
    let Some(history) = snapshot.execution_availability.as_ref() else {
        if snapshot
            .events
            .iter()
            .any(|event| EVENT_KINDS.contains(&event.kind.as_str()))
        {
            return Err(identity("provider execution rows without owner history"));
        }
        return seal(CaseworkLiveProviderExecutionV1 {
            schema: CASEWORK_LIVE_PROVIDER_EXECUTION_SCHEMA_V1.to_owned(),
            projection_digest: String::new(),
            run_id: snapshot.run_id.clone(),
            packet_digest: packet.packet_digest.clone(),
            evaluated_at: evaluated_at.to_rfc3339(),
            status: "NOT_RECORDED_BY_FOREMAN".to_owned(),
            requirement: None,
            dispatches: vec![], dispositions: vec![], deferrals: vec![], wakes: vec![],
            resumes: vec![], resource_transitions: vec![],
            independent_provider_capacity_status: capacity_status.to_owned(),
            explanation: "No provider-execution availability requirement is recorded in this foreman journal.".to_owned(),
            authority_effect: "READ_ONLY_MECHANISM_PROJECTION".to_owned(),
        });
    };

    bind_requirement(snapshot, packet, admission, profile, history)?;
    let provider_id = exact_provider_id(history)?;
    let mut result = empty_recorded(snapshot, packet, evaluated_at, capacity_status);
    result.requirement = Some(project_requirement(history, &provider_id));
    reopen_rows(snapshot, history, evaluated_at, &mut result)?;
    seal(result)
}

fn project_dispatch(
    row: &ReadOnlyEventRowV1,
    start_bytes: &[u8],
    dispatch_bytes: &[u8],
    start: &WorkerStartRequestV3,
    dispatch: &ProviderDispatchOccurrenceV1,
) -> LiveProviderDispatchV1 {
    LiveProviderDispatchV1 {
        journal_sequence: row.sequence,
        journal_event_id: row.event_id.clone(),
        journal_exact_bytes_sha256: plain_sha256(&row.raw_bytes),
        journal_retained_raw_digest: row.raw_digest.clone(),
        work_item_id: dispatch.work_item_id.clone(),
        work_attempt_id: dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
        dispatch_ordinal: dispatch.dispatch_ordinal,
        selected_model_ordinal: dispatch.selected_model_ordinal,
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
        model_class: dispatch.selection.model_class.clone(),
        adapter_id: dispatch.adapter_id.clone(),
        adapter_version: dispatch.adapter_version.clone(),
        adapter_protocol: dispatch.adapter_protocol.clone(),
        adapter_process_occurrence_id: dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: dispatch.app_server_session_identity.clone(),
        worker_start_request_digest: start.request_digest.clone(),
        worker_brief_digest: dispatch.worker_brief_digest.clone(),
        dispatch_digest: dispatch.dispatch_digest.clone(),
        opened_at: dispatch.opened_at.to_rfc3339(),
        start_request_exact_bytes_sha256: plain_sha256(start_bytes),
        dispatch_exact_bytes_sha256: plain_sha256(dispatch_bytes),
        provider_execution_identity_absent_at_start: dispatch.provider_execution_id.is_none(),
    }
}

fn project_disposition(
    row: &ReadOnlyEventRowV1,
    evaluated_at: DateTime<Utc>,
    observation_bytes: &[u8],
    disposition_bytes: &[u8],
    observation: &ExecutionAvailabilityObservationV1,
    disposition: &ProviderAdmissionDispositionV1,
    reconciles: Option<String>,
) -> LiveProviderDispositionV1 {
    LiveProviderDispositionV1 {
        journal_sequence: row.sequence,
        journal_event_id: row.event_id.clone(),
        journal_exact_bytes_sha256: plain_sha256(&row.raw_bytes),
        journal_retained_raw_digest: row.raw_digest.clone(),
        work_item_id: disposition.work_item_id.clone(),
        work_attempt_id: disposition.work_attempt_id.clone(),
        dispatch_occurrence_id: disposition.dispatch_occurrence_id.clone(),
        dispatch_digest: disposition.dispatch_digest.clone(),
        disposition_digest: disposition.disposition_digest.clone(),
        reconciles_disposition_digest: reconciles,
        provider_id: disposition.provider_id.clone(),
        model_id: disposition.model_id.clone(),
        availability_state: enum_string(observation.state),
        admission_disposition: enum_string(disposition.disposition),
        mechanism_state: enum_string(disposition.mechanism_state),
        observed_at: observation.observed_at.to_rfc3339(),
        evidence_received_at: observation.received_at.to_rfc3339(),
        expires_at: observation.expires_at.to_rfc3339(),
        disposition_received_at: disposition.received_at.to_rfc3339(),
        currentness: currentness(
            evaluated_at,
            observation.received_at,
            observation.expires_at,
        ),
        source_identity: observation.source_identity.clone(),
        source_version: observation.source_version.clone(),
        response_created: disposition.response_created,
        acquisition_complete: disposition.acquisition_complete,
        provider_retry_after: disposition
            .provider_retry_after
            .map(|value| value.to_rfc3339()),
        provider_request_occurrence_id: disposition.provider_request_occurrence_id.clone(),
        provider_execution: disposition
            .provider_execution
            .as_ref()
            .map(project_identity),
        mapper_snapshot_schema: disposition.mapper_snapshot_schema.clone(),
        mapper_snapshot_digest: disposition.mapper_snapshot_digest.clone(),
        approval_response_sent: disposition.approval_response_sent,
        protected_effect_absent: disposition.protected_effect_absent,
        observation_digest: observation.observation_digest.clone(),
        observation_exact_bytes_sha256: plain_sha256(observation_bytes),
        disposition_exact_bytes_sha256: plain_sha256(disposition_bytes),
    }
}

fn project_identity(value: &ProviderExecutionIdentityV1) -> LiveProviderExecutionIdentityV1 {
    LiveProviderExecutionIdentityV1 {
        provider_id: value.provider_id.clone(),
        model_id: value.model_id.clone(),
        app_server_session_identity: value.app_server_session_identity.clone(),
        thread_id: value.thread_id.clone(),
        turn_id: value.turn_id.clone(),
        first_response_id: value.first_response_id.clone(),
    }
}

fn project_deferral(
    row: &ReadOnlyEventRowV1,
    bytes: &[u8],
    value: &DeferredProviderDispatchV1,
) -> LiveProviderDeferralV1 {
    LiveProviderDeferralV1 {
        journal_sequence: row.sequence,
        journal_event_id: row.event_id.clone(),
        journal_exact_bytes_sha256: plain_sha256(&row.raw_bytes),
        disposition_digest: value.disposition_digest.clone(),
        deferred_dispatch_digest: value.deferred_dispatch_digest.clone(),
        work_item_id: value.work_item_id.clone(),
        work_attempt_id: value.work_attempt_id.clone(),
        last_dispatch_occurrence_id: value.last_dispatch_occurrence_id.clone(),
        provider_id: value.provider_id.clone(),
        model_id: value.model_id.clone(),
        selected_model_ordinal: value.selected_model_ordinal,
        remaining_model_ordinals: value.remaining_model_ordinals.clone(),
        refusal_received_at: value.refusal_received_at.to_rfc3339(),
        wake_basis: enum_string(value.wake_basis),
        backoff_ordinal: value.backoff_ordinal,
        backoff_seconds: value.backoff_seconds,
        provider_retry_after: value.provider_retry_after.map(|time| time.to_rfc3339()),
        wake_at: value.wake_at.to_rfc3339(),
        parked_resource_lock_policy: enum_string(value.parked_resource_lock_policy),
        provider_capacity_released: value.provider_capacity_released,
        deferred_exact_bytes_sha256: plain_sha256(bytes),
    }
}

fn reopen_occurrence(
    row: &ReadOnlyEventRowV1,
    value: ReadOnlyExecutionAvailabilityJournalEventV1,
    history: &ReadOnlyExecutionAvailabilityHistoryV1,
    result: &mut CaseworkLiveProviderExecutionV1,
    wakes: &mut usize,
    resumes: &mut usize,
    resources: &mut usize,
) -> Result<(), LiveCaseworkError> {
    let work_item_id = row
        .work_item_id
        .clone()
        .ok_or_else(|| identity("provider occurrence work item"))?;
    let attempt_id = row
        .attempt_id
        .clone()
        .ok_or_else(|| identity("provider occurrence attempt"))?;
    match value {
        ReadOnlyExecutionAvailabilityJournalEventV1::Wake {
            wake_occurrence_id,
            deferred_dispatch_digest,
            next_dispatch_digest,
        } => {
            if history.wake_occurrence_ids.get(*wakes) != Some(&wake_occurrence_id)
                || history.wake_work_attempt_ids.get(*wakes) != Some(&attempt_id)
                || history.wake_next_dispatch_digests.get(*wakes) != Some(&next_dispatch_digest)
            {
                return Err(identity("provider wake journal equality"));
            }
            result.wakes.push(LiveProviderWakeV1 {
                journal_sequence: row.sequence,
                journal_event_id: row.event_id.clone(),
                journal_exact_bytes_sha256: plain_sha256(&row.raw_bytes),
                work_item_id,
                work_attempt_id: attempt_id,
                wake_occurrence_id,
                deferred_dispatch_digest,
                next_dispatch_digest,
                recorded_at: row.recorded_at.clone(),
            });
            *wakes += 1;
        }
        ReadOnlyExecutionAvailabilityJournalEventV1::Resume {
            resume_occurrence_id,
            disposition_digest,
            adapter_process_occurrence_id,
            execution_identity,
        } => {
            if history.resume_occurrence_ids.get(*resumes) != Some(&resume_occurrence_id)
                || history.resume_work_item_ids.get(*resumes) != Some(&work_item_id)
                || history.resume_work_attempt_ids.get(*resumes) != Some(&attempt_id)
                || history.resume_disposition_digests.get(*resumes) != Some(&disposition_digest)
                || history.resume_adapter_process_occurrence_ids.get(*resumes)
                    != Some(&adapter_process_occurrence_id)
                || history.resume_execution_identities.get(*resumes) != Some(&*execution_identity)
                || history
                    .resume_recorded_at
                    .get(*resumes)
                    .map(DateTime::to_rfc3339)
                    .as_ref()
                    != Some(&row.recorded_at)
            {
                return Err(identity("provider resume journal equality"));
            }
            result.resumes.push(LiveProviderResumeV1 {
                journal_sequence: row.sequence,
                journal_event_id: row.event_id.clone(),
                journal_exact_bytes_sha256: plain_sha256(&row.raw_bytes),
                work_item_id,
                work_attempt_id: attempt_id,
                resume_occurrence_id,
                disposition_digest,
                adapter_process_occurrence_id,
                execution_identity: project_identity(&execution_identity),
                recorded_at: row.recorded_at.clone(),
            });
            *resumes += 1;
        }
        other => reopen_resource(
            row,
            other,
            history,
            result,
            resources,
            work_item_id,
            attempt_id,
        )?,
    }
    Ok(())
}

fn reopen_resource(
    row: &ReadOnlyEventRowV1,
    value: ReadOnlyExecutionAvailabilityJournalEventV1,
    history: &ReadOnlyExecutionAvailabilityHistoryV1,
    result: &mut CaseworkLiveProviderExecutionV1,
    index: &mut usize,
    work_item_id: String,
    attempt_id: String,
) -> Result<(), LiveCaseworkError> {
    let (
        transition,
        dispatch_digest,
        disposition_digest,
        deferred_dispatch_digest,
        policy_digest,
        wake_id,
        locks,
    ) = match value {
        ReadOnlyExecutionAvailabilityJournalEventV1::ResourcesReleased {
            disposition_digest,
            dispatch_digest,
            policy_digest,
            resource_lock_keys,
        } => (
            "RELEASED",
            dispatch_digest,
            Some(disposition_digest),
            None,
            policy_digest,
            None,
            resource_lock_keys,
        ),
        ReadOnlyExecutionAvailabilityJournalEventV1::ResourcesReacquired {
            wake_occurrence_id,
            deferred_dispatch_digest,
            next_dispatch_digest,
            policy_digest,
            resource_lock_keys,
        } => (
            "REACQUIRED",
            next_dispatch_digest,
            None,
            Some(deferred_dispatch_digest),
            policy_digest,
            Some(wake_occurrence_id),
            resource_lock_keys,
        ),
        _ => return Err(identity("provider occurrence kind")),
    };
    let retained = history
        .resource_transitions
        .get(*index)
        .ok_or_else(|| identity("provider resource transition count"))?;
    if retained.transition != transition
        || retained.work_item_id != work_item_id
        || retained.work_attempt_id != attempt_id
        || retained.dispatch_digest != dispatch_digest
        || retained.disposition_digest != disposition_digest
        || retained.deferred_dispatch_digest != deferred_dispatch_digest
        || retained.policy_digest != policy_digest
        || retained.wake_occurrence_id != wake_id
        || retained.resource_lock_keys != locks
        || retained.recorded_at.to_rfc3339() != row.recorded_at
    {
        return Err(identity("provider resource transition journal equality"));
    }
    let predecessor_is_exact = match (&disposition_digest, &deferred_dispatch_digest) {
        (Some(digest), None) => result.dispositions.iter().any(|value| {
            value.disposition_digest == *digest && value.dispatch_digest == dispatch_digest
        }),
        (None, Some(digest)) => result
            .deferrals
            .iter()
            .any(|value| value.deferred_dispatch_digest == *digest),
        _ => false,
    };
    if !predecessor_is_exact {
        return Err(identity("provider resource transition predecessor"));
    }
    result
        .resource_transitions
        .push(LiveProviderResourceTransitionV1 {
            journal_sequence: row.sequence,
            journal_event_id: row.event_id.clone(),
            journal_exact_bytes_sha256: plain_sha256(&row.raw_bytes),
            transition: transition.to_owned(),
            work_item_id,
            work_attempt_id: attempt_id,
            dispatch_digest,
            disposition_digest,
            deferred_dispatch_digest,
            policy_digest,
            wake_occurrence_id: wake_id,
            resource_lock_keys: locks,
            recorded_at: row.recorded_at.clone(),
        });
    *index += 1;
    Ok(())
}

fn seal(
    mut value: CaseworkLiveProviderExecutionV1,
) -> Result<CaseworkLiveProviderExecutionV1, LiveCaseworkError> {
    let mut preimage = serde_json::to_value(&value).map_err(contract)?;
    let object = preimage
        .as_object_mut()
        .ok_or_else(|| contract("provider-execution projection must be an object"))?;
    object.remove("projection_digest");
    let bytes = serde_jcs::to_vec(&preimage).map_err(contract)?;
    let mut hasher = Sha256::new();
    hasher.update(CASEWORK_LIVE_PROVIDER_EXECUTION_DIGEST_DOMAIN_V1);
    hasher.update(bytes);
    value.projection_digest = format!("sha256:{:x}", hasher.finalize());
    Ok(value)
}

fn currentness(now: DateTime<Utc>, received: DateTime<Utc>, expires: DateTime<Utc>) -> String {
    if now < received {
        "NOT_YET_CURRENT"
    } else if now >= expires {
        "EXPIRED"
    } else {
        "CURRENT"
    }
    .to_owned()
}

fn enum_string<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("owner enum serializes")
        .as_str()
        .expect("owner enum is string")
        .to_owned()
}

fn plain_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn identity(message: &'static str) -> LiveCaseworkError {
    LiveCaseworkError::Identity(message)
}
fn contract(error: impl ToString) -> LiveCaseworkError {
    LiveCaseworkError::Contract(error.to_string())
}

fn bind_requirement(
    snapshot: &ReadOnlyRunSnapshotV1,
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    history: &ReadOnlyExecutionAvailabilityHistoryV1,
) -> Result<(), LiveCaseworkError> {
    let requirement = &history.requirement;
    requirement.validate().map_err(contract)?;
    history.policy.validate().map_err(contract)?;
    if requirement.run_id != snapshot.run_id
        || requirement.packet_digest != packet.packet_digest
        || requirement.admission_digest != admission.admission_digest
        || requirement.profile_digest != profile.profile_digest
        || requirement.policy_id != history.policy.policy_id
        || requirement.policy_digest != history.policy.policy_digest
        || serde_jcs::to_vec(requirement).map_err(contract)? != history.requirement_bytes
        || serde_jcs::to_vec(&history.policy).map_err(contract)? != history.policy_bytes
    {
        return Err(identity("provider execution requirement graph"));
    }
    let adapter = profile
        .adapters
        .get(&requirement.adapter_id)
        .ok_or_else(|| identity("provider execution adapter registration"))?;
    if adapter.protocol != requirement.adapter_protocol
        || adapter.adapter_version != requirement.adapter_version
        || adapter.executable_identity != requirement.adapter_executable_identity
        || requirement.work_item_model_selections.len() != packet.work_items.len()
        || requirement
            .work_item_model_selections
            .keys()
            .any(|work_id| {
                !profile.work_items.contains_key(work_id)
                    || !packet.work_items.iter().any(|work| work.id == *work_id)
            })
    {
        return Err(identity("provider execution requirement bindings"));
    }
    Ok(())
}

fn exact_provider_id(
    history: &ReadOnlyExecutionAvailabilityHistoryV1,
) -> Result<String, LiveCaseworkError> {
    let providers: BTreeSet<_> = history
        .requirement
        .work_item_model_selections
        .values()
        .flatten()
        .map(|selection| selection.provider_id.as_str())
        .collect();
    if providers.len() != 1 {
        return Err(identity("provider execution exact provider identity"));
    }
    Ok(providers.into_iter().next().unwrap().to_owned())
}

fn empty_recorded(
    snapshot: &ReadOnlyRunSnapshotV1,
    packet: &NightshiftPacketV1,
    evaluated_at: DateTime<Utc>,
    capacity_status: &str,
) -> CaseworkLiveProviderExecutionV1 {
    CaseworkLiveProviderExecutionV1 {
        schema: CASEWORK_LIVE_PROVIDER_EXECUTION_SCHEMA_V1.to_owned(),
        projection_digest: String::new(),
        run_id: snapshot.run_id.clone(),
        packet_digest: packet.packet_digest.clone(),
        evaluated_at: evaluated_at.to_rfc3339(),
        status: "EXACT_RECORDED_FOREMAN_HISTORY".to_owned(),
        requirement: None,
        dispatches: vec![], dispositions: vec![], deferrals: vec![], wakes: vec![],
        resumes: vec![], resource_transitions: vec![],
        independent_provider_capacity_status: capacity_status.to_owned(),
        explanation: "Exact foreman provider-execution mechanism history; provider capacity remains an independent projection.".to_owned(),
        authority_effect: "READ_ONLY_MECHANISM_PROJECTION".to_owned(),
    }
}

fn project_requirement(
    history: &ReadOnlyExecutionAvailabilityHistoryV1,
    provider_id: &str,
) -> LiveProviderExecutionRequirementV1 {
    let requirement = &history.requirement;
    let policy = &history.policy;
    LiveProviderExecutionRequirementV1 {
        journal_sequence: 0,
        requirement_digest: requirement.requirement_digest.clone(),
        policy_id: requirement.policy_id.clone(),
        policy_digest: requirement.policy_digest.clone(),
        provider_id: provider_id.to_owned(),
        work_item_model_selections: requirement
            .work_item_model_selections
            .iter()
            .map(|(work_item_id, selections)| {
                (
                    work_item_id.clone(),
                    selections
                        .iter()
                        .map(|selection| LiveProviderModelSelectionV1 {
                            provider_id: selection.provider_id.clone(),
                            model_id: selection.model_id.clone(),
                            model_class: selection.model_class.clone(),
                        })
                        .collect(),
                )
            })
            .collect(),
        adapter_id: requirement.adapter_id.clone(),
        adapter_protocol: requirement.adapter_protocol.clone(),
        adapter_version: requirement.adapter_version.clone(),
        adapter_executable_identity: requirement.adapter_executable_identity.clone(),
        codex_owner_head: requirement.owner_pins.codex_owner_head.clone(),
        provider_admission_owner_head: requirement.owner_pins.adapter_owner_head().to_owned(),
        provider_admission_schema_sha256: requirement.owner_pins.adapter_schema_sha256().to_owned(),
        deterministic_fixture_sha256: requirement.owner_pins.deterministic_fixture_sha256.clone(),
        admitted_at: requirement.admitted_at.to_rfc3339(),
        requirement_exact_bytes_sha256: plain_sha256(&history.requirement_bytes),
        policy_exact_bytes_sha256: plain_sha256(&history.policy_bytes),
        parked_resource_lock_policy: enum_string(policy.parked_resource_lock_policy),
        allow_ordered_model_fallback: policy.allow_ordered_model_fallback,
        automatic_semantic_retry: policy.automatic_semantic_retry,
        approval_response_authorized: policy.approval_response_authorized,
        authority_effect: "READ_ONLY_MECHANISM_PROJECTION".to_owned(),
    }
}

fn reopen_rows(
    snapshot: &ReadOnlyRunSnapshotV1,
    history: &ReadOnlyExecutionAvailabilityHistoryV1,
    evaluated_at: DateTime<Utc>,
    result: &mut CaseworkLiveProviderExecutionV1,
) -> Result<(), LiveCaseworkError> {
    let mut requirements = 0_usize;
    let mut dispatches = 0_usize;
    let mut dispositions = 0_usize;
    let mut deferrals = 0_usize;
    let mut wakes = 0_usize;
    let mut resumes = 0_usize;
    let mut resources = 0_usize;
    for row in snapshot
        .events
        .iter()
        .filter(|row| EVENT_KINDS.contains(&row.kind.as_str()))
    {
        let reopened =
            reopen_execution_availability_journal_event(row, &snapshot.run_id).map_err(contract)?;
        match reopened {
            ReadOnlyExecutionAvailabilityJournalEventV1::Requirement {
                requirement,
                requirement_bytes,
                policy,
                policy_bytes,
            } => {
                requirements += 1;
                if *requirement != history.requirement
                    || requirement_bytes != history.requirement_bytes
                    || *policy != history.policy
                    || policy_bytes != history.policy_bytes
                {
                    return Err(identity("provider requirement journal equality"));
                }
                result.requirement.as_mut().unwrap().journal_sequence = row.sequence;
            }
            ReadOnlyExecutionAvailabilityJournalEventV1::Dispatch {
                start_request,
                start_request_bytes,
                dispatch,
                dispatch_bytes,
            } => {
                if history.worker_start_requests.get(dispatches) != Some(&*start_request)
                    || history.dispatches.get(dispatches) != Some(&*dispatch)
                    || history
                        .requirement
                        .work_item_model_selections
                        .get(&dispatch.work_item_id)
                        .and_then(|selections| {
                            selections.get(usize::from(dispatch.selected_model_ordinal))
                        })
                        != Some(&dispatch.selection)
                {
                    return Err(identity("provider dispatch journal equality"));
                }
                result.dispatches.push(project_dispatch(
                    row,
                    &start_request_bytes,
                    &dispatch_bytes,
                    &start_request,
                    &dispatch,
                ));
                dispatches += 1;
            }
            ReadOnlyExecutionAvailabilityJournalEventV1::Disposition {
                observation,
                observation_bytes,
                disposition,
                disposition_bytes,
                deferred,
                deferred_bytes,
                reconciles_disposition_digest,
            } => {
                if history.observations.get(dispositions) != Some(&*observation)
                    || history.dispositions.get(dispositions) != Some(&*disposition)
                {
                    return Err(identity("provider disposition journal equality"));
                }
                result.dispositions.push(project_disposition(
                    row,
                    evaluated_at,
                    &observation_bytes,
                    &disposition_bytes,
                    &observation,
                    &disposition,
                    reconciles_disposition_digest,
                ));
                if let (Some(record), Some(bytes)) = (deferred, deferred_bytes) {
                    if history.deferred.get(deferrals) != Some(&*record) {
                        return Err(identity("provider deferral journal equality"));
                    }
                    result
                        .deferrals
                        .push(project_deferral(row, &bytes, &record));
                    deferrals += 1;
                }
                dispositions += 1;
            }
            other => reopen_occurrence(
                row,
                other,
                history,
                result,
                &mut wakes,
                &mut resumes,
                &mut resources,
            )?,
        }
    }
    if requirements != 1
        || dispatches != history.dispatches.len()
        || dispositions != history.dispositions.len()
        || deferrals != history.deferred.len()
        || wakes != history.wake_occurrence_ids.len()
        || resumes != history.resume_occurrence_ids.len()
        || resources != history.resource_transitions.len()
    {
        return Err(identity("provider execution complete journal equality"));
    }
    Ok(())
}
