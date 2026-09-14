//! Durable, non-authorizing attention projection for retained saved checks.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

use crate::saved_check_runtime::SavedCheckEvaluationV1;

pub const POLICY_SCHEMA: &str = "nightshift.saved-check-attention-policy/v1";
pub const RECEIPT_SCHEMA: &str = "nightshift.saved-check-attention-receipt/v1";
pub const BUNDLE_SCHEMA: &str = "nightshift.saved-check-attention-replay-bundle/v1";
pub const REPLAY_SCHEMA: &str = "nightshift.saved-check-attention-replay/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckAttentionPolicyV1 {
    pub schema: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub max_event_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SavedCheckAttentionDispositionV1 {
    NoAttention,
    AttentionRequired,
    LossOfAssurance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SavedCheckAttentionReasonV1 {
    SavedCheckPassed,
    SavedCheckFailedCovered,
    SavedCheckFailedOverrun,
    SavedCheckFailedUncovered,
    ConditionIndeterminate,
    ConditionRefused,
    SourceStale,
    SourceFuture,
    MaintenanceUnavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckAttentionReceiptV1 {
    pub schema: String,
    pub receipt_digest: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub evaluation_id: String,
    pub condition_sha256: String,
    pub projection_at: String,
    pub event_current_until: String,
    pub evaluated_at: String,
    pub source_currentness: String,
    pub original_result_state: String,
    pub original_outcome: String,
    pub maintenance: Value,
    pub disposition: SavedCheckAttentionDispositionV1,
    pub reason: SavedCheckAttentionReasonV1,
    pub delivery_eligible: bool,
    pub inspection_reference: String,
    pub authority: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckAttentionReplayBundleV1 {
    pub schema: String,
    pub policy: SavedCheckAttentionPolicyV1,
    pub evaluation: SavedCheckEvaluationV1,
    pub receipt: SavedCheckAttentionReceiptV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckAttentionReplayV1 {
    pub schema: String,
    pub matches: bool,
    pub expected_receipt_digest: String,
    pub recomputed_receipt_digest: String,
}

fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_jcs::to_vec(value).map_err(|e| e.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn validate_receipt_digest(receipt: &SavedCheckAttentionReceiptV1) -> Result<(), String> {
    let mut material = receipt.clone();
    material.receipt_digest.clear();
    if receipt.receipt_digest != digest(&material)? {
        return Err("saved-check attention receipt digest mismatch".into());
    }
    Ok(())
}

impl SavedCheckAttentionPolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != POLICY_SCHEMA
            || self.policy_id.is_empty()
            || self.policy_id.len() > 256
            || self.max_event_age_seconds == 0
            || self.max_event_age_seconds > 300
        {
            return Err("invalid saved-check attention policy".into());
        }
        let mut material = self.clone();
        material.policy_digest.clear();
        if self.policy_digest != digest(&material)? {
            return Err("saved-check attention policy digest mismatch".into());
        }
        Ok(())
    }
}

fn field<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("saved-check condition omits {pointer}"))
}

fn exact_output(value: &Value, encoded: &str, expected_digest: &str) -> Result<(), String> {
    let bytes = hex::decode(encoded).map_err(|e| e.to_string())?;
    if format!("sha256:{:x}", Sha256::digest(&bytes)) != expected_digest {
        return Err("retained JSON output digest mismatch".into());
    }
    let payload = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    if serde_jcs::to_vec(value).map_err(|e| e.to_string())? != payload {
        return Err(
            "retained JSON output is not exact JCS with an optional output delimiter".into(),
        );
    }
    Ok(())
}

fn validate_evaluation(evaluation: &SavedCheckEvaluationV1) -> Result<(), String> {
    if evaluation.schema != "nightshift.saved-check-evaluation/v1"
        || evaluation.authority != "none"
        || evaluation.state != "terminal"
        || evaluation.evaluation_id != evaluation.due_request.evaluation_id
        || evaluation.policy_digest != evaluation.due_request.policy_digest
        || evaluation.slot_id != evaluation.due_request.slot.slot_id.as_str()
    {
        return Err("saved-check evaluation identity is invalid".into());
    }
    let result = evaluation.nq_result.as_ref().ok_or("NQ result is absent")?;
    exact_output(
        result,
        evaluation
            .nq_result_bytes_hex
            .as_deref()
            .ok_or("NQ result bytes are absent")?,
        evaluation
            .nq_result_sha256
            .as_deref()
            .ok_or("NQ result digest is absent")?,
    )?;
    if result.get("evaluation_id").and_then(Value::as_str) != Some(&evaluation.evaluation_id)
        || !matches!(
            result.get("outcome").and_then(Value::as_str),
            Some("passed" | "failed" | "refused" | "claimed")
        )
        || result.pointer("/detail/binding") != evaluation.nq_request_binding.as_ref()
    {
        return Err("NQ result does not bind the retained evaluation and request".into());
    }
    let binding = evaluation
        .nq_request_binding
        .as_ref()
        .ok_or("NQ request binding is absent")?;
    if binding.get("definition_digest")
        != Some(&Value::String(
            evaluation.due_request.definition_digest.clone(),
        ))
        || binding.get("source_identity")
            != Some(&Value::String(
                evaluation.due_request.source_identity.clone(),
            ))
        || binding
            .get("source_observed_at_assertion")
            .and_then(Value::as_str)
            != evaluation.source_observed_at.as_deref()
    {
        return Err(
            "NQ request does not bind the scheduled definition and retained source observation"
                .into(),
        );
    }
    Ok(())
}

pub fn evaluate_saved_check_attention(
    policy: &SavedCheckAttentionPolicyV1,
    evaluation: &SavedCheckEvaluationV1,
    evaluated_at: DateTime<Utc>,
) -> Result<SavedCheckAttentionReceiptV1, String> {
    policy.validate()?;
    validate_evaluation(evaluation)?;
    let condition = evaluation
        .condition
        .as_ref()
        .ok_or("saved-check condition is absent")?;
    if condition.get("schema").and_then(Value::as_str) != Some("nq.saved-check-condition/v1")
        || condition.get("evaluation_id").and_then(Value::as_str)
            != Some(evaluation.evaluation_id.as_str())
        || condition.get("authority").and_then(Value::as_str) != Some("none")
    {
        return Err("unsupported or mismatched saved-check condition".into());
    }
    exact_output(
        condition,
        evaluation
            .condition_bytes_hex
            .as_deref()
            .ok_or("condition bytes absent")?,
        evaluation
            .condition_sha256
            .as_deref()
            .ok_or("condition digest absent")?,
    )?;
    let projection_text = evaluation
        .projection_at
        .as_ref()
        .ok_or("projection time absent")?;
    let projection = DateTime::parse_from_rfc3339(projection_text)
        .map_err(|e| e.to_string())?
        .with_timezone(&Utc);
    if field(condition, "/caller_mapping/at")? != projection_text
        || field(condition, "/caller_mapping/mapping_owner")? != "caller"
        || condition
            .get("automatic_nightshift_integration")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("condition projection coordinate or mapping is not retained exactly".into());
    }
    let until = projection
        .checked_add_signed(Duration::seconds(
            i64::try_from(policy.max_event_age_seconds).map_err(|_| "event age overflow")?,
        ))
        .ok_or("event age overflow")?;
    let source = field(condition, "/source_assertion/state")?;
    let result_state = field(condition, "/original_result/state")?;
    let outcome = field(condition, "/original_result/outcome")?;
    let projection_state = field(condition, "/projection_state")?;
    let maintenance = condition
        .get("maintenance")
        .cloned()
        .ok_or("maintenance annotation absent")?;
    let maintenance_state = field(condition, "/maintenance/state")?;
    let read_attempt = field(condition, "/read_attempt/state")?;
    if !matches!(source, "fresh" | "stale" | "future")
        || !matches!(
            result_state,
            "passed" | "failed" | "refused" | "indeterminate" | "unavailable"
        )
        || !matches!(outcome, "passed" | "failed" | "refused" | "claimed")
        || !matches!(projection_state, "available" | "indeterminate" | "refused")
        || !matches!(
            maintenance_state,
            "covered" | "overrun" | "uncovered" | "unavailable"
        )
        || !matches!(
            read_attempt,
            "recorded" | "not_yet_observed" | "indeterminate" | "not_established" | "unavailable"
        )
    {
        return Err("saved-check condition contains unsupported state vocabulary".into());
    }
    let result = evaluation.nq_result.as_ref().unwrap();
    let binding = evaluation.nq_request_binding.as_ref().unwrap();
    if condition.pointer("/original_result/outcome") != result.get("outcome")
        || condition.pointer("/original_result/detail") != result.get("detail")
        || condition.pointer("/definition_identity/reference")
            != Some(&Value::String(
                evaluation.due_request.definition_reference.clone(),
            ))
        || condition.pointer("/definition_identity/digest")
            != Some(&Value::String(
                evaluation.due_request.definition_digest.clone(),
            ))
        || condition.pointer("/source_assertion/identity") != binding.get("source_identity")
        || condition.pointer("/source_assertion/observed_at")
            != binding.get("source_observed_at_assertion")
        || condition.pointer("/source_assertion/currentness_seconds")
            != binding.get("currentness_seconds")
    {
        return Err("condition differs from retained definition, result, or source binding".into());
    }
    let read_at = condition
        .pointer("/read_attempt/at")
        .and_then(Value::as_str);
    let result_read_at = result
        .pointer("/detail/read_attempted_at")
        .and_then(Value::as_str);
    match result_state {
        "passed" | "failed"
            if matches!(read_attempt, "recorded" | "not_yet_observed")
                && read_at.is_some()
                && read_at == result_read_at => {}
        "refused" if read_attempt == "not_established" && read_at.is_none() => {}
        "indeterminate" if read_attempt == "indeterminate" && read_at.is_none() => {}
        "unavailable" if read_attempt == "unavailable" && read_at.is_none() => {}
        _ => return Err("saved-check result and read-attempt semantics do not match".into()),
    }
    let (disposition, reason) = if source == "stale" {
        (
            SavedCheckAttentionDispositionV1::LossOfAssurance,
            SavedCheckAttentionReasonV1::SourceStale,
        )
    } else if source == "future" {
        (
            SavedCheckAttentionDispositionV1::LossOfAssurance,
            SavedCheckAttentionReasonV1::SourceFuture,
        )
    } else if maintenance_state == "unavailable" {
        (
            SavedCheckAttentionDispositionV1::LossOfAssurance,
            SavedCheckAttentionReasonV1::MaintenanceUnavailable,
        )
    } else if projection_state == "indeterminate" || result_state == "indeterminate" {
        (
            SavedCheckAttentionDispositionV1::LossOfAssurance,
            SavedCheckAttentionReasonV1::ConditionIndeterminate,
        )
    } else if projection_state == "refused" || result_state == "refused" {
        (
            SavedCheckAttentionDispositionV1::LossOfAssurance,
            SavedCheckAttentionReasonV1::ConditionRefused,
        )
    } else if projection_state == "available" && source == "fresh" && outcome == "passed" {
        (
            SavedCheckAttentionDispositionV1::NoAttention,
            SavedCheckAttentionReasonV1::SavedCheckPassed,
        )
    } else if projection_state == "available" && source == "fresh" && outcome == "failed" {
        let reason = match maintenance_state {
            "covered" => SavedCheckAttentionReasonV1::SavedCheckFailedCovered,
            "overrun" => SavedCheckAttentionReasonV1::SavedCheckFailedOverrun,
            "uncovered" => SavedCheckAttentionReasonV1::SavedCheckFailedUncovered,
            _ => return Err("unsupported maintenance annotation".into()),
        };
        (SavedCheckAttentionDispositionV1::AttentionRequired, reason)
    } else {
        return Err("ambiguous saved-check condition".into());
    };
    let current = projection <= evaluated_at && evaluated_at <= until;
    let mut receipt = SavedCheckAttentionReceiptV1 {
        schema: RECEIPT_SCHEMA.into(),
        receipt_digest: String::new(),
        policy_id: policy.policy_id.clone(),
        policy_digest: policy.policy_digest.clone(),
        evaluation_id: evaluation.evaluation_id.clone(),
        condition_sha256: evaluation.condition_sha256.clone().unwrap(),
        projection_at: projection_text.clone(),
        event_current_until: until.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        evaluated_at: evaluated_at.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        source_currentness: source.into(),
        original_result_state: result_state.into(),
        original_outcome: outcome.into(),
        maintenance,
        delivery_eligible: current && disposition != SavedCheckAttentionDispositionV1::NoAttention,
        disposition,
        reason,
        inspection_reference: format!("saved-check:{}", evaluation.evaluation_id),
        authority: "none".into(),
    };
    receipt.receipt_digest = digest(&receipt)?;
    Ok(receipt)
}

pub fn replay_saved_check_attention(
    bundle: &SavedCheckAttentionReplayBundleV1,
) -> Result<SavedCheckAttentionReplayV1, String> {
    if bundle.schema != BUNDLE_SCHEMA {
        return Err("unsupported saved-check attention replay bundle".into());
    }
    let at = DateTime::parse_from_rfc3339(&bundle.receipt.evaluated_at)
        .map_err(|e| e.to_string())?
        .with_timezone(&Utc);
    let recomputed = evaluate_saved_check_attention(&bundle.policy, &bundle.evaluation, at)?;
    validate_receipt_digest(&bundle.receipt)?;
    Ok(SavedCheckAttentionReplayV1 {
        schema: REPLAY_SCHEMA.into(),
        matches: recomputed == bundle.receipt,
        expected_receipt_digest: bundle.receipt.receipt_digest.clone(),
        recomputed_receipt_digest: recomputed.receipt_digest,
    })
}

pub struct SavedCheckAttentionStoreV1 {
    connection: Connection,
}
impl SavedCheckAttentionStoreV1 {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|e| e.to_string())?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS saved_check_attention_receipts (policy_digest TEXT NOT NULL, evaluation_id TEXT NOT NULL, condition_sha256 TEXT NOT NULL, receipt_json BLOB NOT NULL, PRIMARY KEY(policy_digest,evaluation_id));").map_err(|e| e.to_string())?;
        Ok(Self { connection })
    }
    pub fn open_read_only(path: &Path) -> Result<Self, String> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| e.to_string())?;
        let present: Option<String> = connection.query_row("SELECT name FROM sqlite_master WHERE type='table' AND name='saved_check_attention_receipts'", [], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
        if present.is_none() {
            return Err("saved-check attention table is absent".into());
        }
        Ok(Self { connection })
    }
    pub fn retain(
        &mut self,
        receipt: &SavedCheckAttentionReceiptV1,
    ) -> Result<SavedCheckAttentionReceiptV1, String> {
        let bytes = serde_jcs::to_vec(receipt).map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let prior: Option<(String, Vec<u8>)> = tx.query_row("SELECT condition_sha256,receipt_json FROM saved_check_attention_receipts WHERE policy_digest=?1 AND evaluation_id=?2", params![receipt.policy_digest,receipt.evaluation_id], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e| e.to_string())?;
        if let Some((condition, prior)) = prior {
            if condition != receipt.condition_sha256 || prior != bytes {
                return Err(
                    "saved-check attention identity conflicts with retained material".into(),
                );
            }
            let retained: SavedCheckAttentionReceiptV1 =
                serde_json::from_slice(&prior).map_err(|e| e.to_string())?;
            validate_receipt_digest(&retained)?;
            return Ok(retained);
        }
        tx.execute(
            "INSERT INTO saved_check_attention_receipts VALUES (?1,?2,?3,?4)",
            params![
                receipt.policy_digest,
                receipt.evaluation_id,
                receipt.condition_sha256,
                bytes
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(receipt.clone())
    }
    pub fn inspect(
        &self,
        policy_digest: &str,
        evaluation_id: &str,
    ) -> Result<Option<SavedCheckAttentionReceiptV1>, String> {
        let bytes: Option<Vec<u8>> = self.connection.query_row("SELECT receipt_json FROM saved_check_attention_receipts WHERE policy_digest=?1 AND evaluation_id=?2", params![policy_digest,evaluation_id], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
        bytes
            .map(|b| {
                let receipt = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
                validate_receipt_digest(&receipt)?;
                Ok(receipt)
            })
            .transpose()
    }
}

pub fn read_bundle<R: Read>(reader: R) -> Result<SavedCheckAttentionReplayBundleV1, String> {
    let mut bytes = Vec::new();
    reader
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("saved-check attention bundle exceeds byte bound".into());
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if serde_jcs::to_vec(&value).map_err(|e| e.to_string())? != bytes {
        return Err("saved-check attention bundle must be exact JCS JSON".into());
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_store::{RecurrenceSlotV1, RecurrenceTriggerV1};
    use crate::saved_check_recurrence::SavedCheckDueRequestV1;
    use serde_json::json;

    fn policy() -> SavedCheckAttentionPolicyV1 {
        let mut value = SavedCheckAttentionPolicyV1 {
            schema: POLICY_SCHEMA.into(),
            policy_id: "saved-capacity".into(),
            policy_digest: String::new(),
            max_event_age_seconds: 300,
        };
        value.policy_digest = digest(&value).unwrap();
        value
    }
    fn evaluation(
        outcome: &str,
        projection: &str,
        source: &str,
        maintenance: &str,
    ) -> SavedCheckEvaluationV1 {
        let definition_digest = format!("sha256:{}", "1".repeat(64));
        let binding = json!({"definition_digest":definition_digest,"target_reference":"/source.sqlite","source_identity":"source","currentness_seconds":300,"source_observed_at_assertion":"2026-09-14T00:00:00Z"});
        let read_time = if projection == "indeterminate" {
            "2026-09-14T00:00:03Z"
        } else {
            "2026-09-14T00:00:01Z"
        };
        let result = json!({"evaluation_id":"eval-1","outcome":outcome,"detail":{"binding":binding,"read_attempted_at":read_time,"refusal_reason":null},"indeterminate":false,"reference":"r","retained":false});
        let result_bytes = serde_jcs::to_vec(&result).unwrap();
        let condition = json!({
            "schema":"nq.saved-check-condition/v1","projection_state":projection,"evaluation_id":"eval-1",
            "definition_identity":{"id":"d","reference":"r","digest":format!("sha256:{}","1".repeat(64)),"installed_at":"2026-09-14T00:00:00Z"},
            "original_result":{"state":outcome,"outcome":outcome,"detail":{"binding":binding,"read_attempted_at":read_time,"refusal_reason":null}},
            "source_assertion":{"identity":"source","observed_at":"2026-09-14T00:00:00Z","currentness_seconds":300,"state":source},
            "read_attempt":{"state":if outcome=="refused" {"not_established"} else if projection=="indeterminate" {"not_yet_observed"} else {"recorded"},"at":if outcome=="refused" {Value::Null} else {json!(read_time)},"scope":"retained_local_read_evidence"},
            "maintenance":{"state":maintenance},"caller_mapping":{"component":"c","kind":"k","subject":"s","at":"2026-09-14T00:00:02Z","mapping_owner":"caller"},
            "authority":"none","automatic_nightshift_integration":false,"limitations":[]
        });
        let bytes = serde_jcs::to_vec(&condition).unwrap();
        let due = DateTime::parse_from_rfc3339("2026-09-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let slot = RecurrenceSlotV1::new(
            "p".into(),
            "1".into(),
            "subject".into(),
            "scope".into(),
            "clock".into(),
            due,
            due + Duration::seconds(10),
            1,
            RecurrenceTriggerV1::Scheduled,
            None,
        )
        .unwrap();
        let request = SavedCheckDueRequestV1 {
            schema: "nightshift.saved-check-due-request/v1".into(),
            policy_digest: format!("sha256:{}", "2".repeat(64)),
            slot,
            evaluation_id: "eval-1".into(),
            definition_reference: "r".into(),
            definition_digest: format!("sha256:{}", "1".repeat(64)),
            source_identity: "source".into(),
        };
        SavedCheckEvaluationV1 {
            schema: "nightshift.saved-check-evaluation/v1".into(),
            evaluation_id: "eval-1".into(),
            policy_digest: format!("sha256:{}", "2".repeat(64)),
            slot_id: request.slot.slot_id.as_str().into(),
            config_digest: format!("sha256:{}", "3".repeat(64)),
            state: "terminal".into(),
            projection_at: Some("2026-09-14T00:00:02Z".into()),
            due_request: request,
            monitor_inventory: Some(json!({})),
            monitor_inventory_bytes_hex: Some("7b7d".into()),
            monitor_inventory_sha256: Some(format!("sha256:{}", "4".repeat(64))),
            acquisition_acquired_at_unix_ms: Some(1),
            source_observed_at: Some("2026-09-14T00:00:00Z".into()),
            nq_request_binding: Some(binding),
            nq_result: Some(result),
            nq_result_bytes_hex: Some(hex::encode(&result_bytes)),
            nq_result_sha256: Some(format!("sha256:{:x}", Sha256::digest(&result_bytes))),
            condition: Some(condition),
            condition_bytes_hex: Some(hex::encode(&bytes)),
            condition_sha256: Some(format!("sha256:{:x}", Sha256::digest(&bytes))),
            assumption: "declared".into(),
            authority: "none".into(),
        }
    }

    #[test]
    fn failure_and_uncertainty_request_attention_without_authority() {
        let at = DateTime::parse_from_rfc3339("2026-09-14T00:00:03Z")
            .unwrap()
            .with_timezone(&Utc);
        let covered = evaluate_saved_check_attention(
            &policy(),
            &evaluation("failed", "available", "fresh", "covered"),
            at,
        )
        .unwrap();
        assert_eq!(
            covered.disposition,
            SavedCheckAttentionDispositionV1::AttentionRequired
        );
        assert_eq!(
            covered.reason,
            SavedCheckAttentionReasonV1::SavedCheckFailedCovered
        );
        assert!(covered.delivery_eligible);
        assert_eq!(covered.authority, "none");
        let stale = evaluate_saved_check_attention(
            &policy(),
            &evaluation("failed", "available", "stale", "uncovered"),
            at,
        )
        .unwrap();
        assert_eq!(
            stale.disposition,
            SavedCheckAttentionDispositionV1::LossOfAssurance
        );
        assert!(stale.delivery_eligible);
        assert_eq!(stale.original_outcome, "failed");
        let passed = evaluate_saved_check_attention(
            &policy(),
            &evaluation("passed", "available", "fresh", "uncovered"),
            at,
        )
        .unwrap();
        assert_eq!(
            passed.disposition,
            SavedCheckAttentionDispositionV1::NoAttention
        );
        assert!(!passed.delivery_eligible);
        for maintenance in ["covered", "overrun", "uncovered"] {
            let failed = evaluate_saved_check_attention(
                &policy(),
                &evaluation("failed", "available", "fresh", maintenance),
                at,
            )
            .unwrap();
            assert_eq!(
                failed.disposition,
                SavedCheckAttentionDispositionV1::AttentionRequired
            );
        }
        let refused = evaluate_saved_check_attention(
            &policy(),
            &evaluation("refused", "refused", "fresh", "uncovered"),
            at,
        )
        .unwrap();
        assert_eq!(
            refused.disposition,
            SavedCheckAttentionDispositionV1::LossOfAssurance
        );
        let indeterminate = evaluate_saved_check_attention(
            &policy(),
            &evaluation("failed", "indeterminate", "fresh", "uncovered"),
            at,
        )
        .unwrap();
        assert_eq!(
            indeterminate.reason,
            SavedCheckAttentionReasonV1::ConditionIndeterminate
        );
        let future = evaluate_saved_check_attention(
            &policy(),
            &evaluation("failed", "available", "future", "uncovered"),
            at,
        )
        .unwrap();
        assert_eq!(future.reason, SavedCheckAttentionReasonV1::SourceFuture);
    }

    #[test]
    fn duplicate_does_not_refresh_and_changed_coordinate_conflicts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.sqlite");
        let mut store = SavedCheckAttentionStoreV1::open(&path).unwrap();
        let at = DateTime::parse_from_rfc3339("2026-09-14T00:00:03Z")
            .unwrap()
            .with_timezone(&Utc);
        let receipt = evaluate_saved_check_attention(
            &policy(),
            &evaluation("failed", "available", "fresh", "uncovered"),
            at,
        )
        .unwrap();
        assert_eq!(store.retain(&receipt).unwrap(), receipt);
        assert_eq!(store.retain(&receipt).unwrap(), receipt);
        drop(store);
        let mut store = SavedCheckAttentionStoreV1::open(&path).unwrap();
        assert_eq!(store.retain(&receipt).unwrap(), receipt);
        let later = DateTime::parse_from_rfc3339("2026-09-14T00:00:04Z")
            .unwrap()
            .with_timezone(&Utc);
        let changed = evaluate_saved_check_attention(
            &policy(),
            &evaluation("failed", "available", "fresh", "uncovered"),
            later,
        )
        .unwrap();
        assert!(store.retain(&changed).unwrap_err().contains("conflicts"));
    }

    #[test]
    fn replay_recomputes_exact_receipt_and_refuses_bad_condition_digest() {
        let retained = evaluation("failed", "available", "fresh", "overrun");
        let policy = policy();
        let at = DateTime::parse_from_rfc3339("2026-09-14T00:00:03Z")
            .unwrap()
            .with_timezone(&Utc);
        let receipt = evaluate_saved_check_attention(&policy, &retained, at).unwrap();
        let bundle = SavedCheckAttentionReplayBundleV1 {
            schema: BUNDLE_SCHEMA.into(),
            policy,
            evaluation: retained.clone(),
            receipt,
        };
        assert!(replay_saved_check_attention(&bundle).unwrap().matches);
        let mut bad = retained;
        bad.condition_sha256 = Some(format!("sha256:{}", "0".repeat(64)));
        assert!(evaluate_saved_check_attention(&bundle.policy, &bad, at).is_err());

        let fractional = DateTime::parse_from_rfc3339("2026-09-14T00:00:03.123456789Z")
            .unwrap()
            .with_timezone(&Utc);
        let evaluation = evaluation("failed", "available", "fresh", "uncovered");
        let receipt =
            evaluate_saved_check_attention(&bundle.policy, &evaluation, fractional).unwrap();
        let fractional_bundle = SavedCheckAttentionReplayBundleV1 {
            schema: BUNDLE_SCHEMA.into(),
            policy: bundle.policy.clone(),
            evaluation,
            receipt,
        };
        assert!(
            replay_saved_check_attention(&fractional_bundle)
                .unwrap()
                .matches
        );
        let mut tampered = fractional_bundle;
        tampered.receipt.delivery_eligible = false;
        assert!(replay_saved_check_attention(&tampered).is_err());
    }

    #[test]
    fn mismatched_schema_binding_read_attempt_and_missing_store_refuse() {
        let at = DateTime::parse_from_rfc3339("2026-09-14T00:00:03Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut bad = evaluation("failed", "available", "fresh", "uncovered");
        bad.schema = "other".into();
        assert!(evaluate_saved_check_attention(&policy(), &bad, at).is_err());
        let mut bad = evaluation("failed", "available", "fresh", "uncovered");
        bad.condition.as_mut().unwrap()["caller_mapping"]["at"] = json!("2026-09-14T00:00:01Z");
        let bytes = serde_jcs::to_vec(bad.condition.as_ref().unwrap()).unwrap();
        bad.condition_bytes_hex = Some(hex::encode(&bytes));
        bad.condition_sha256 = Some(format!("sha256:{:x}", Sha256::digest(&bytes)));
        assert!(evaluate_saved_check_attention(&policy(), &bad, at).is_err());
        let mut bad = evaluation("failed", "available", "fresh", "uncovered");
        bad.condition.as_mut().unwrap()["read_attempt"]["state"] = json!("unavailable");
        let bytes = serde_jcs::to_vec(bad.condition.as_ref().unwrap()).unwrap();
        bad.condition_bytes_hex = Some(hex::encode(&bytes));
        bad.condition_sha256 = Some(format!("sha256:{:x}", Sha256::digest(&bytes)));
        assert!(evaluate_saved_check_attention(&policy(), &bad, at).is_err());
        let directory = tempfile::tempdir().unwrap();
        assert!(SavedCheckAttentionStoreV1::open_read_only(
            &directory.path().join("absent.sqlite")
        )
        .is_err());
    }
}
