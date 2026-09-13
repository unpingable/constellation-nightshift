//! Local pre-launch closure testimony. This is not provider admission evidence.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{contract::ContractError, ProviderDispatchOccurrenceV1, WorkerStartRequestV3};

pub const PRELAUNCH_CLOSURE_SCHEMA: &str = "switchyard.provider-prelaunch-closure/v1";
pub const PRELAUNCH_CLOSURE_DOMAIN: &[u8] = b"switchyard.provider-prelaunch-closure.digest/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrelaunchBindingV1 {
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub dispatch_occurrence_id: String,
    pub adapter_process_occurrence_id: String,
    pub request_digest: String,
    pub request_sha256: String,
    pub worker_brief_digest: String,
    pub brief_sha256: String,
    pub backend_sha256: String,
    pub dispatch_digest: String,
    pub dispatch_sha256: String,
    pub switchyard_owner_head: String,
    pub codex_owner_head: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrelaunchSupervisorAttestationV1 {
    pub schema: String,
    pub binding: PrelaunchBindingV1,
    pub supervisor_identity: String,
    pub host: String,
    pub unit: String,
    pub invocation_id: String,
    pub active_state: String,
    pub result: String,
    pub exit_code: u32,
    pub observed_at: DateTime<Utc>,
    pub original_runner_sha256: String,
    pub unit_evidence_sha256: String,
    pub failure_evidence_sha256: String,
    pub boundary: String,
    pub original_producer_terminated: bool,
    pub alternate_writers_excluded: bool,
    pub trust_basis: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrelaunchClosureV1 {
    pub schema: String,
    pub closure_digest: String,
    pub binding: PrelaunchBindingV1,
    pub closed_at: DateTime<Utc>,
    pub evidence_mode: String,
    pub failure_code: String,
    pub supervisor_attestation: Option<PrelaunchSupervisorAttestationV1>,
    pub observer_source_head: String,
    pub observer_runner_sha256: String,
    pub state: String,
    pub provider_claim_absent: bool,
    pub backend_started: bool,
    pub authority_effect: String,
}

fn sha256(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

fn hexadecimal(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn is_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|v| hexadecimal(v, 64))
}

impl PrelaunchClosureV1 {
    pub fn from_slice(raw: &[u8]) -> Result<Self, ContractError> {
        if raw.len() > 32 * 1024 {
            return Err(ContractError::InvalidField("prelaunch closure size"));
        }
        let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
        let value: Self =
            serde_json::from_slice(raw).map_err(|e| ContractError::Json(e.to_string()))?;
        if serde_jcs::to_vec(&value).map_err(|e| ContractError::Json(e.to_string()))? != raw {
            return Err(ContractError::InvalidField("canonical prelaunch closure"));
        }
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let refusal = || ContractError::InvalidField("local prelaunch closure");
        if self.schema != PRELAUNCH_CLOSURE_SCHEMA
            || self.state != "PRELAUNCH_CLOSED"
            || !matches!(
                self.failure_code.as_str(),
                "EXECUTABLE_CAPTURE_FAILED" | "REQUEST_PREFLIGHT_FAILED"
            )
            || !self.provider_claim_absent
            || self.backend_started
            || self.authority_effect != "LOCAL_PRELAUNCH_CLOSURE_ONLY"
            || !hexadecimal(&self.observer_source_head, 40)
            || !is_digest(&self.observer_runner_sha256)
            || !hexadecimal(&self.binding.switchyard_owner_head, 40)
            || !hexadecimal(&self.binding.codex_owner_head, 40)
        {
            return Err(refusal());
        }
        for value in [
            &self.binding.packet_digest,
            &self.binding.request_digest,
            &self.binding.request_sha256,
            &self.binding.worker_brief_digest,
            &self.binding.brief_sha256,
            &self.binding.backend_sha256,
            &self.binding.dispatch_digest,
            &self.binding.dispatch_sha256,
        ] {
            if !is_digest(value) {
                return Err(refusal());
            }
        }
        for value in [
            &self.binding.run_id,
            &self.binding.work_item_id,
            &self.binding.work_attempt_id,
            &self.binding.dispatch_occurrence_id,
            &self.binding.adapter_process_occurrence_id,
        ] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(refusal());
            }
        }
        match (self.evidence_mode.as_str(), &self.supervisor_attestation) {
            ("OBSERVED_CAPTURE_FAILURE", None)
                if self.failure_code == "EXECUTABLE_CAPTURE_FAILED" => {}
            ("SUPERVISOR_ATTESTED_PRECLAIM_FAILURE", Some(proof)) => {
                if proof.schema != "switchyard.prelaunch-supervisor-attestation/v1"
                    || proof.binding != self.binding
                    || !matches!(proof.active_state.as_str(), "inactive" | "failed")
                    || proof.result != "exit-code"
                    || proof.exit_code == 0
                    || proof.boundary != "BEFORE_PROVIDER_CLAIM"
                    || !proof.original_producer_terminated
                    || !proof.alternate_writers_excluded
                    || proof.trust_basis != "OWNER_ATTESTATION_NOT_INDEPENDENT_PROCESS_PROOF"
                    || proof.observed_at > self.closed_at
                    || !hexadecimal(&proof.invocation_id, 32)
                    || !is_digest(&proof.original_runner_sha256)
                    || !is_digest(&proof.unit_evidence_sha256)
                    || !is_digest(&proof.failure_evidence_sha256)
                {
                    return Err(refusal());
                }
                for value in [&proof.supervisor_identity, &proof.host, &proof.unit] {
                    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
                    {
                        return Err(refusal());
                    }
                }
            }
            _ => return Err(refusal()),
        }
        let mut basis =
            serde_json::to_value(self).map_err(|e| ContractError::Json(e.to_string()))?;
        basis
            .as_object_mut()
            .ok_or_else(refusal)?
            .remove("closure_digest");
        let mut raw = PRELAUNCH_CLOSURE_DOMAIN.to_vec();
        raw.extend(serde_jcs::to_vec(&basis).map_err(|e| ContractError::Json(e.to_string()))?);
        if sha256(&raw) != self.closure_digest {
            return Err(ContractError::DigestMismatch("closure_digest"));
        }
        Ok(())
    }

    pub fn validate_prepared(
        &self,
        request: &WorkerStartRequestV3,
        dispatch: &ProviderDispatchOccurrenceV1,
        brief: &[u8],
    ) -> Result<(), ContractError> {
        self.validate()?;
        let binding = &self.binding;
        let canonical = |value: &serde_json::Value| {
            serde_jcs::to_vec(value).map_err(|e| ContractError::Json(e.to_string()))
        };
        let request_raw = canonical(
            &serde_json::to_value(request).map_err(|e| ContractError::Json(e.to_string()))?,
        )?;
        let dispatch_raw = canonical(
            &serde_json::to_value(dispatch).map_err(|e| ContractError::Json(e.to_string()))?,
        )?;
        if binding.packet_digest != request.packet_digest
            || binding.run_id != request.run_id
            || binding.work_item_id != request.work_item_id
            || binding.work_attempt_id != request.work_attempt_id
            || binding.dispatch_occurrence_id != request.dispatch_occurrence_id
            || binding.adapter_process_occurrence_id != dispatch.adapter_process_occurrence_id
            || binding.request_digest != request.request_digest
            || binding.request_sha256 != sha256(&request_raw)
            || binding.worker_brief_digest != request.worker_brief_digest
            || binding.brief_sha256 != sha256(brief)
            || binding.dispatch_digest != dispatch.dispatch_digest
            || binding.dispatch_sha256 != sha256(&dispatch_raw)
            || binding.switchyard_owner_head != request.switchyard_owner_head
            || binding.codex_owner_head != request.codex_owner_head
            || self.closed_at < dispatch.opened_at
        {
            return Err(ContractError::InvalidField(
                "prelaunch prepared dispatch binding",
            ));
        }
        Ok(())
    }
}
