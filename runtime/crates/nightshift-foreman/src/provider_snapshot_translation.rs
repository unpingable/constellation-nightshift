//! Thin translation of retained real mapper evidence into existing owner records.
use super::*;

/// Construct the existing park record from explicit owner policy, then reopen
/// the whole graph. This neither admits another dispatch nor schedules a retry.
pub fn derive_provider_deferral(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    policy: &ExecutionAvailabilityPolicyV1,
    dispatch: &ProviderDispatchOccurrenceV1,
    observation: &ExecutionAvailabilityObservationV1,
    disposition: &ProviderAdmissionDispositionV1,
    history: &[ProviderDeferralHistoryEntryV1],
) -> Result<Option<DeferredProviderDispatchV1>, ContractError> {
    requirement.validate()?;
    policy.validate()?;
    dispatch.validate()?;
    disposition.validate()?;
    let deferred = if disposition.permits_automatic_park() {
        let index = dispatch
            .dispatch_ordinal
            .checked_sub(1)
            .ok_or(ContractError::InvalidField("dispatch ordinal"))?;
        let seconds = *policy
            .backoff_seconds
            .get(usize::from(index))
            .ok_or(ContractError::InvalidField("policy backoff ordinal"))?;
        let wake_at = match disposition.provider_retry_after {
            Some(value) => value,
            None => disposition
                .received_at
                .checked_add_signed(Duration::seconds(seconds as i64))
                .ok_or(ContractError::InvalidField("wake timestamp overflow"))?,
        };
        let backoff_seconds = u64::try_from((wake_at - disposition.received_at).num_seconds())
            .map_err(|_| ContractError::InvalidField("negative provider backoff"))?;
        let selections = requirement
            .work_item_model_selections
            .get(&dispatch.work_item_id)
            .ok_or(ContractError::InvalidField("work item model selections"))?;
        let mut value = DeferredProviderDispatchV1 {
            schema: DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1.to_owned(),
            deferred_dispatch_digest: format!("sha256:{}", "0".repeat(64)),
            requirement_digest: requirement.requirement_digest.clone(),
            policy_digest: policy.policy_digest.clone(),
            disposition_digest: disposition.disposition_digest.clone(),
            packet_digest: requirement.packet_digest.clone(),
            run_id: requirement.run_id.clone(),
            work_item_id: dispatch.work_item_id.clone(),
            work_attempt_id: dispatch.work_attempt_id.clone(),
            last_dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
            provider_id: dispatch.selection.provider_id.clone(),
            model_id: dispatch.selection.model_id.clone(),
            selected_model_ordinal: dispatch.selected_model_ordinal,
            remaining_model_ordinals: if policy.allow_ordered_model_fallback {
                ((dispatch.selected_model_ordinal + 1)..selections.len() as u16).collect()
            } else {
                Vec::new()
            },
            refusal_received_at: disposition.received_at,
            wake_basis: if disposition.provider_retry_after.is_some() {
                DeferredWakeBasisV1::ProviderRetryAfter
            } else {
                DeferredWakeBasisV1::PolicyBackoff
            },
            backoff_ordinal: index,
            backoff_seconds,
            provider_retry_after: disposition.provider_retry_after,
            wake_at,
            parked_resource_lock_policy: policy.parked_resource_lock_policy,
            provider_capacity_released: true,
            semantic_retry: false,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        };
        value.seal()?;
        Some(value)
    } else {
        None
    };
    validate_execution_availability_graph(
        requirement,
        policy,
        dispatch,
        observation,
        disposition,
        history,
        deferred.as_ref(),
    )?;
    Ok(deferred)
}

/// Derive mechanism records, not a worker result or permission to redispatch.
/// Exact mapper replay and the complete requirement graph are still validated
/// by the existing disposition/store boundary. Callers supply an explicit
/// observation expiry, not a fabricated upstream timestamp.
pub fn derive_provider_snapshot_evidence(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    dispatch: &ProviderDispatchOccurrenceV1,
    raw: &[u8],
    received_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<
    (
        ProviderAdmissionDispositionV1,
        ExecutionAvailabilityObservationV1,
    ),
    ContractError,
> {
    requirement.validate()?;
    dispatch.validate()?;
    let retained = ExactMapperSnapshotV1::from_bytes(raw)?;
    let snapshot: Value = serde_json::from_slice(raw).map_err(json_error)?;
    let binding = &snapshot["binding"];
    if binding["codex_source_head"].as_str()
        != Some(requirement.owner_pins.codex_owner_head.as_str())
    {
        return Err(ContractError::InvalidField("snapshot enrolled owner"));
    }
    let disposition: ProviderAdmissionDispositionKindV1 =
        serde_json::from_value(snapshot["admission_disposition"].clone()).map_err(json_error)?;
    let mechanism_state: ProviderMechanismStateV1 =
        serde_json::from_value(snapshot["mechanism_state"].clone()).map_err(json_error)?;
    let execution = match snapshot.get("provider_execution_identity") {
        Some(Value::Null) => None,
        Some(value) => Some(ProviderExecutionIdentityV1 {
            provider_id: string(value, "provider")?.to_owned(),
            model_id: string(value, "model")?.to_owned(),
            app_server_session_identity: string(value, "app_server_session_identity")?.to_owned(),
            thread_id: string(value, "thread_id")?.to_owned(),
            turn_id: string(value, "turn_id")?.to_owned(),
            first_response_id: string(value, "first_response_id")?.to_owned(),
        }),
        None => return Err(ContractError::InvalidField("snapshot execution identity")),
    };
    let records = snapshot["records"]
        .as_array()
        .ok_or(ContractError::InvalidField("snapshot records"))?;
    let request = records
        .iter()
        .find_map(|record| record["normalized"]["request_occurrence_id"].as_str());
    // A discrepancy before any local provider request has no request identity.
    // Preserve that as an explicit local marker, never as an upstream request.
    let request = request.unwrap_or("not-observed").to_owned();
    let retry_after = records
        .iter()
        .find_map(|record| record["normalized"]["retry_after_ms"].as_i64())
        .map(|milliseconds| {
            received_at
                .checked_add_signed(Duration::milliseconds(milliseconds))
                .ok_or(ContractError::InvalidField("retry timestamp overflow"))
        })
        .transpose()?;
    let mut result = ProviderAdmissionDispositionV1 {
        schema: PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1.to_owned(),
        disposition_digest: format!("sha256:{}", "0".repeat(64)),
        dispatch_digest: dispatch.dispatch_digest.clone(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: dispatch.work_item_id.clone(),
        work_attempt_id: dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
        provider_request_occurrence_id: request,
        adapter_process_occurrence_id: dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: dispatch.app_server_session_identity.clone(),
        thread_id: string(binding, "thread_id")?.to_owned(),
        turn_id: string(binding, "turn_id")?.to_owned(),
        disposition,
        mechanism_state,
        received_at,
        response_created: execution.is_some(),
        will_retry: false,
        acquisition_complete: snapshot["acquisition_cut"]["clean"]
            .as_bool()
            .unwrap_or(false),
        provider_retry_after: retry_after,
        provider_execution: execution,
        mapper_snapshot_schema: string(&snapshot, "schema")?.to_owned(),
        mapper_snapshot_digest: string(&snapshot, "snapshot_digest")?.to_owned(),
        mapper_snapshot: retained,
        approval_response_sent: false,
        protected_effect_absent: true,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    result.seal()?;
    result.validate()?;
    let source = disposition_source_observation(&result)?;
    let state = match result.disposition {
        ProviderAdmissionDispositionKindV1::ExecutionAdmitted => {
            ExecutionAvailabilityStateV1::Available
        }
        ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity => {
            ExecutionAvailabilityStateV1::ModelAtCapacity
        }
        _ => ExecutionAvailabilityStateV1::Unknown,
    };
    let mut observation = ExecutionAvailabilityObservationV1 {
        schema: EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1.to_owned(),
        observation_digest: format!("sha256:{}", "0".repeat(64)),
        provider_id: result.provider_id.clone(),
        model_id: result.model_id.clone(),
        model_class: dispatch.selection.model_class.clone(),
        observed_at: source.observed_at,
        received_at,
        expires_at,
        state,
        source_identity: source.identity.to_owned(),
        source_version: source.version.to_owned(),
        provider_retry_after: result.provider_retry_after,
        exact_evidence: source.evidence,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    observation.seal()?;
    Ok((result, observation))
}
