use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use nightshift_foreman::{
    reopen_capacity_journal_event, ExecutionProfileV2, ForemanAdmissionV1,
    ForemanCapacityAdmissionV1, ForemanCapacityRequirementV1, ReadOnlyCapacityJournalEventV1,
    ReadOnlyRunSnapshotV1,
};
use nightshift_provider_capacity::{
    decide_capacity, AdmissionDisposition, CapacityDecisionV1, CapacityObservationV1,
    CapacityPolicyV1,
};
use nightshiftd::packet::NightshiftPacketV1;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{live_loader::LiveCaseworkError, live_model::*};

const MAXIMUM_CAPACITY_RECORD_BYTES: usize = 1024 * 1024;
const MAXIMUM_CAPACITY_HISTORY_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn project_provider_capacity(
    snapshot: &ReadOnlyRunSnapshotV1,
    packet: &NightshiftPacketV1,
    foreman_admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    evaluated_at: DateTime<Utc>,
) -> Result<LiveProviderCapacityV1, LiveCaseworkError> {
    let Some(retained_requirement) = snapshot.capacity_requirement.as_ref() else {
        if !snapshot.capacity_admissions.is_empty()
            || snapshot
                .events
                .iter()
                .any(|event| event.kind == "capacity_admission")
        {
            return Err(contract(
                "capacity admissions exist without a recorded requirement",
            ));
        }
        return Ok(LiveProviderCapacityV1 {
            status: "NOT_RECORDED_BY_FOREMAN".to_owned(),
            requirement: None,
            attempts: Vec::new(),
            explanation: "The execution profile retains only a policy reference; no exact capacity requirement or admission is recorded in this foreman journal."
                .to_owned(),
        });
    };

    let requirement =
        ForemanCapacityRequirementV1::from_slice(&retained_requirement.requirement_bytes)
            .map_err(|error| contract(error.to_string()))?;
    requirement
        .validate()
        .map_err(|error| contract(error.to_string()))?;
    require_canonical(
        "capacity requirement",
        &retained_requirement.requirement_bytes,
        &requirement,
    )?;
    if requirement != retained_requirement.requirement
        || requirement.packet_digest != packet.packet_digest
        || requirement.admission_digest != foreman_admission.admission_digest
        || requirement.profile_digest != profile.profile_digest
        || requirement.run_id != snapshot.run_id
        || requirement.policy_id != profile.budget_policy_ref
    {
        return Err(LiveCaseworkError::Identity("capacity requirement"));
    }
    let requirement_events: Vec<_> = snapshot
        .events
        .iter()
        .filter(|event| event.kind == "capacity_requirement")
        .collect();
    if requirement_events.len() != 1 {
        return Err(LiveCaseworkError::Identity(
            "capacity requirement journal placement",
        ));
    }
    match reopen_capacity_journal_event(requirement_events[0], &snapshot.run_id)
        .map_err(|error| contract(error.to_string()))?
    {
        ReadOnlyCapacityJournalEventV1::Requirement { record, .. }
            if *record == *retained_requirement => {}
        _ => {
            return Err(LiveCaseworkError::Identity(
                "capacity requirement journal typed/raw equality",
            ));
        }
    }

    let packet_classes: BTreeMap<_, _> = packet
        .work_items
        .iter()
        .map(|work| (work.id.as_str(), work.model_routing.class.as_str()))
        .collect();
    let required_classes: BTreeSet<_> = requirement
        .model_cost_classes
        .keys()
        .map(String::as_str)
        .collect();
    let exact_packet_classes: BTreeSet<_> = packet_classes.values().copied().collect();
    if required_classes != exact_packet_classes
        || packet_classes.len() != profile.work_items.len()
        || packet_classes.iter().any(|(work_id, packet_class)| {
            profile.work_items.get(*work_id).is_none_or(|execution| {
                execution.provider_model_class != **packet_class
                    || !requirement.model_cost_classes.contains_key(*packet_class)
            })
        })
    {
        return Err(LiveCaseworkError::Identity(
            "capacity model-class requirement",
        ));
    }

    let mut retained_bytes = retained_requirement.requirement_bytes.len();
    if retained_requirement.requirement_bytes.is_empty()
        || retained_requirement.requirement_bytes.len() > MAXIMUM_CAPACITY_RECORD_BYTES
    {
        return Err(contract("capacity requirement exceeds exact byte bound"));
    }
    let mut retained_by_attempt = BTreeMap::new();
    for retained in &snapshot.capacity_admissions {
        for (name, bytes) in [
            ("capacity admission", retained.admission_bytes.as_slice()),
            (
                "capacity observation",
                retained.observation_bytes.as_slice(),
            ),
            ("capacity policy", retained.policy_bytes.as_slice()),
            ("capacity decision", retained.decision_bytes.as_slice()),
        ] {
            if bytes.is_empty() || bytes.len() > MAXIMUM_CAPACITY_RECORD_BYTES {
                return Err(contract(format!("{name} exceeds exact byte bound")));
            }
            retained_bytes = retained_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| contract("capacity history byte count overflow"))?;
        }
        if retained_bytes > MAXIMUM_CAPACITY_HISTORY_BYTES {
            return Err(contract(
                "capacity history exceeds aggregate exact byte bound",
            ));
        }
        if retained_by_attempt
            .insert(retained.attempt_id.as_str(), retained)
            .is_some()
        {
            return Err(contract("duplicate capacity admission attempt"));
        }
    }
    let capacity_events: Vec<_> = snapshot
        .events
        .iter()
        .filter(|event| event.kind == "capacity_admission")
        .collect();
    if capacity_events.len() != retained_by_attempt.len() {
        return Err(contract(
            "capacity admission event and snapshot counts differ",
        ));
    }

    let mut attempts = Vec::with_capacity(capacity_events.len());
    for event in capacity_events {
        let attempt_id = event
            .attempt_id
            .as_deref()
            .ok_or_else(|| contract("capacity event has no attempt"))?;
        let retained = retained_by_attempt
            .remove(attempt_id)
            .ok_or_else(|| contract("capacity event has no exact retained admission"))?;
        match reopen_capacity_journal_event(event, &snapshot.run_id)
            .map_err(|error| contract(error.to_string()))?
        {
            ReadOnlyCapacityJournalEventV1::Admission { record, .. } if *record == *retained => {}
            _ => {
                return Err(LiveCaseworkError::Identity(
                    "capacity admission journal typed/raw equality",
                ));
            }
        }
        let binding = ForemanCapacityAdmissionV1::from_slice(&retained.admission_bytes)
            .map_err(|error| contract(error.to_string()))?;
        binding
            .validate()
            .map_err(|error| contract(error.to_string()))?;
        require_canonical("capacity admission", &retained.admission_bytes, &binding)?;
        if binding != retained.capacity_admission {
            return Err(LiveCaseworkError::Identity(
                "capacity admission typed duplicate",
            ));
        }
        let observation: CapacityObservationV1 =
            parse_capacity_record("capacity observation", &retained.observation_bytes)?;
        observation
            .validate()
            .map_err(|error| contract(error.to_string()))?;
        require_canonical(
            "capacity observation",
            &retained.observation_bytes,
            &observation,
        )?;
        let policy: CapacityPolicyV1 =
            parse_capacity_record("capacity policy", &retained.policy_bytes)?;
        policy
            .validate()
            .map_err(|error| contract(error.to_string()))?;
        require_canonical("capacity policy", &retained.policy_bytes, &policy)?;
        let decision: CapacityDecisionV1 =
            parse_capacity_record("capacity decision", &retained.decision_bytes)?;
        decision
            .validate()
            .map_err(|error| contract(error.to_string()))?;
        require_canonical("capacity decision", &retained.decision_bytes, &decision)?;
        let reproduced = decide_capacity(&observation, &policy, decision.decision_at)
            .map_err(|error| contract(error.to_string()))?;
        if reproduced != decision {
            return Err(contract(
                "capacity decision is not the exact deterministic owner result",
            ));
        }
        let work = packet
            .work_items
            .iter()
            .find(|work| work.id == retained.work_item_id)
            .ok_or(LiveCaseworkError::Identity("capacity work item"))?;
        let execution = profile
            .work_items
            .get(&retained.work_item_id)
            .ok_or(LiveCaseworkError::Identity("capacity profile work item"))?;
        let recorded_at = DateTime::parse_from_rfc3339(&retained.recorded_at)
            .map_err(|error| contract(error.to_string()))?
            .with_timezone(&Utc);
        if binding.capacity_requirement_digest != requirement.capacity_requirement_digest
            || binding.packet_digest != packet.packet_digest
            || binding.admission_digest != foreman_admission.admission_digest
            || binding.profile_digest != profile.profile_digest
            || binding.run_id != snapshot.run_id
            || binding.work_item_id != retained.work_item_id
            || binding.adapter_id != execution.adapter_id
            || binding.provider_id != requirement.provider_id
            || binding.provider_id != observation.provider_id
            || binding.provider_id != decision.provider_id
            || binding.packet_model_class != work.model_routing.class
            || binding.profile_model_class != execution.provider_model_class
            || requirement
                .model_cost_classes
                .get(&binding.packet_model_class)
                != Some(&binding.cost_class)
            || observation
                .model_family
                .as_deref()
                .is_some_and(|model| model != binding.packet_model_class)
            || binding.policy_id != requirement.policy_id
            || binding.policy_id != policy.policy_id
            || binding.observation_digest != observation.observation_digest
            || binding.policy_digest != policy.policy_digest
            || binding.decision_digest != decision.decision_digest
            || decision.observation_digest != observation.observation_digest
            || decision.policy_digest != policy.policy_digest
            || binding.evaluated_at != recorded_at
            || decision.decision_at != recorded_at
            || recorded_at < observation.observed_at
            || recorded_at >= observation.expires_at
        {
            return Err(LiveCaseworkError::Identity(
                "capacity attempt evidence graph",
            ));
        }
        let cost_class = enum_token(&binding.cost_class)?;
        if decision.admission == AdmissionDisposition::NoNewWork
            || (decision.admission == AdmissionDisposition::CheapBoundedOnly
                && cost_class != "CHEAP")
        {
            return Err(contract(
                "recorded capacity disposition does not admit this attempt",
            ));
        }
        attempts.push(LiveProviderCapacityAttemptV1 {
            journal_sequence: event.sequence,
            work_item_id: retained.work_item_id.clone(),
            attempt_id: retained.attempt_id.clone(),
            recorded_at: retained.recorded_at.clone(),
            provider_id: binding.provider_id.clone(),
            packet_model_class: binding.packet_model_class.clone(),
            profile_model_class: binding.profile_model_class.clone(),
            cost_class,
            capacity_state: enum_token(&decision.state)?,
            admission_disposition: enum_token(&decision.admission)?,
            source_class: enum_token(&observation.source_class)?,
            confidence: enum_token(&observation.confidence)?,
            observation_disposition: enum_token(&observation.disposition)?,
            observed_at: observation.observed_at.to_rfc3339(),
            expires_at: observation.expires_at.to_rfc3339(),
            decision_at: decision.decision_at.to_rfc3339(),
            evaluated_at: binding.evaluated_at.to_rfc3339(),
            currentness: capacity_currentness(
                evaluated_at,
                observation.observed_at,
                observation.expires_at,
            ),
            capacity_admission_digest: binding.capacity_admission_digest.clone(),
            observation_digest: observation.observation_digest.clone(),
            policy_digest: policy.policy_digest.clone(),
            decision_digest: decision.decision_digest.clone(),
            admission_exact_bytes_sha256: plain_sha256(&retained.admission_bytes),
            observation_exact_bytes_sha256: plain_sha256(&retained.observation_bytes),
            policy_exact_bytes_sha256: plain_sha256(&retained.policy_bytes),
            decision_exact_bytes_sha256: plain_sha256(&retained.decision_bytes),
        });
    }
    if !retained_by_attempt.is_empty() {
        return Err(contract(
            "retained capacity admission is absent from journal order",
        ));
    }
    let model_cost_classes = requirement
        .model_cost_classes
        .iter()
        .map(|(model, class)| Ok((model.clone(), enum_token(class)?)))
        .collect::<Result<BTreeMap<_, _>, LiveCaseworkError>>()?;
    Ok(LiveProviderCapacityV1 {
        status: "EXACT_RECORDED_BY_FOREMAN".to_owned(),
        requirement: Some(LiveProviderCapacityRequirementV1 {
            capacity_requirement_digest: requirement.capacity_requirement_digest,
            exact_bytes_sha256: plain_sha256(&retained_requirement.requirement_bytes),
            recorded_at: retained_requirement.recorded_at.clone(),
            policy_id: requirement.policy_id,
            provider_id: requirement.provider_id,
            model_cost_classes,
            authority_effect: requirement.authority_effect,
        }),
        attempts,
        explanation: "Exact journal-recorded provider-capacity requirement and per-attempt admission evidence; this mechanism record is not a campaign result or authority grant."
            .to_owned(),
    })
}

fn parse_capacity_record<T: DeserializeOwned>(
    name: &str,
    bytes: &[u8],
) -> Result<T, LiveCaseworkError> {
    serde_json::from_slice(bytes).map_err(|error| contract(format!("{name}: {error}")))
}

fn require_canonical<T: Serialize>(
    name: &str,
    bytes: &[u8],
    value: &T,
) -> Result<(), LiveCaseworkError> {
    let canonical =
        serde_jcs::to_vec(value).map_err(|error| contract(format!("{name}: {error}")))?;
    if canonical != bytes {
        return Err(contract(format!(
            "{name} bytes are not exact canonical owner bytes"
        )));
    }
    Ok(())
}

fn enum_token<T: Serialize>(value: &T) -> Result<String, LiveCaseworkError> {
    serde_json::to_value(value)
        .map_err(|error| LiveCaseworkError::Projection(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| LiveCaseworkError::Projection("closed enum is not a string".to_owned()))
}

fn capacity_currentness(
    now: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> String {
    if now < observed_at {
        "NOT_YET_CURRENT"
    } else if now >= expires_at {
        "EXPIRED"
    } else {
        "CURRENT"
    }
    .to_owned()
}

fn plain_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn contract(message: impl Into<String>) -> LiveCaseworkError {
    LiveCaseworkError::Contract(message.into())
}
