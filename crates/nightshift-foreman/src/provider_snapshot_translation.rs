//! Thin translation of retained real mapper evidence into existing owner records.
use super::*;

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
