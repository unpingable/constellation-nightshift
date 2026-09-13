//! Narrow canonical Nightshift -> AG port.
//!
//! Nightshift may open a distinct occurrence, record one exact proposal, and
//! read status. It has no API for standing, authorization, dispatch, retry,
//! reconciliation, Docket custody, or human disposition.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::canonical_store::{
    AgOccurrenceReferenceV1, AgProgramCounterV1, AgRefusalReferenceV1, CanonicalStoreError,
    ObservationRecordV1, PreparedAgRequestV1, TypedCoarseIntentV2, AG_REFERENCE_SCHEMA_V1,
    AG_REFUSAL_SCHEMA_V1, PREPARED_AG_REQUEST_SCHEMA_V1,
};

pub const AG_OPEN_REQUEST_SCHEMA_V1: &str = "nightshift.ag_open_occurrence_request.v1";

fn digest_value(value: &serde_json::Value) -> Result<String, String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(value).map_err(|error| error.to_string())?)
    ))
}

fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a non-empty token"));
    }
    Ok(())
}

fn require_digest(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    }
    Ok(())
}

fn exact_object<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{name} must be an exact JSON object"))
}

fn exact_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{field} must be a string"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgOpenModeV1 {
    Genesis { genesis: serde_json::Value },
    Continuation { continuation: serde_json::Value },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgOpenOccurrenceRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub subject_digest: String,
    pub scope_digest: String,
    pub source_observation_id: String,
    pub source_support_id: String,
    pub source_posture_id: String,
    pub source_intent_id: String,
    pub mode: AgOpenModeV1,
    /// Exact `ag-loopctl record-proposal --input` document.
    pub proposal_input: serde_json::Value,
}

impl AgOpenOccurrenceRequestV1 {
    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = AG_OPEN_REQUEST_SCHEMA_V1.into();
        self.request_id.clear();
        let mut value = serde_json::to_value(&self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("AG open request is an object")
            .remove("request_id");
        self.request_id = digest_value(&value)?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != AG_OPEN_REQUEST_SCHEMA_V1 {
            return Err(format!(
                "unsupported AG open request schema {}",
                self.schema
            ));
        }
        require_digest("request_id", &self.request_id)?;
        require_digest("campaign_id", &self.campaign_id)?;
        require_digest("subject_digest", &self.subject_digest)?;
        require_digest("scope_digest", &self.scope_digest)?;
        uuid::Uuid::parse_str(&self.occurrence_id)
            .map_err(|_| "occurrence_id must be an independently allocated UUID".to_string())?;
        for (name, value) in [
            ("source_observation_id", &self.source_observation_id),
            ("source_support_id", &self.source_support_id),
            ("source_posture_id", &self.source_posture_id),
            ("source_intent_id", &self.source_intent_id),
        ] {
            require_digest(name, value)?;
        }
        match &self.mode {
            AgOpenModeV1::Genesis { genesis } => {
                let object = exact_object(genesis, "genesis")?;
                if exact_string(object, "campaign")? != self.campaign_id
                    || exact_string(object, "occurrence")? != self.occurrence_id
                {
                    return Err("AG genesis does not bind the exact new occurrence".into());
                }
            }
            AgOpenModeV1::Continuation { continuation } => {
                let object = exact_object(continuation, "continuation")?;
                let fields: BTreeSet<_> = ["expected_ag_work", "occurrence"].into_iter().collect();
                if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != fields
                    || exact_string(object, "occurrence")? != self.occurrence_id
                {
                    return Err(
                        "AG continuation does not bind exactly one new occurrence and work".into(),
                    );
                }
                require_digest(
                    "continuation.expected_ag_work",
                    exact_string(object, "expected_ag_work")?,
                )?;
            }
        }
        let input = exact_object(&self.proposal_input, "proposal_input")?;
        let expected_fields: BTreeSet<_> =
            ["class", "observation", "proposal"].into_iter().collect();
        if input.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_fields {
            return Err(
                "proposal input must contain exactly observation, proposal, and class".into(),
            );
        }
        let proposal_observation = exact_string(input, "observation")?;
        require_digest("proposal_input.observation", proposal_observation)?;
        if proposal_observation != self.source_observation_id {
            return Err("AG proposal substitutes a different observation basis".into());
        }
        let class = exact_string(input, "class")?;
        let expected_class = match self.mode {
            AgOpenModeV1::Genesis { .. } => "initial",
            AgOpenModeV1::Continuation { .. } => "successor",
        };
        if class != expected_class {
            return Err(
                "Nightshift recurrence may open only initial or ordinary successor work".into(),
            );
        }
        let proposal = exact_object(
            input
                .get("proposal")
                .ok_or_else(|| "proposal is missing".to_string())?,
            "proposal",
        )?;
        let proposal_fields: BTreeSet<_> = [
            "campaign",
            "repair",
            "schema",
            "scope",
            "subject",
            "work",
            "work_schema",
        ]
        .into_iter()
        .collect();
        if proposal.keys().map(String::as_str).collect::<BTreeSet<_>>() != proposal_fields {
            return Err("exact AG proposal has missing or unknown fields".into());
        }
        if exact_string(proposal, "schema")? != "ag.governed-loop.exact-work-proposal/v1"
            || exact_string(proposal, "campaign")? != self.campaign_id
            || exact_string(proposal, "subject")? != self.subject_digest
            || exact_string(proposal, "scope")? != self.scope_digest
        {
            return Err("exact AG proposal does not bind campaign/subject/scope".into());
        }
        let proposal_work = exact_string(proposal, "work")?;
        require_digest("proposal.work", proposal_work)?;
        require_token(
            "proposal.work_schema",
            exact_string(proposal, "work_schema")?,
        )?;
        let expected_work = match &self.mode {
            AgOpenModeV1::Genesis { genesis } => {
                exact_string(exact_object(genesis, "genesis")?, "expected_ag_work")?
            }
            AgOpenModeV1::Continuation { continuation } => exact_string(
                exact_object(continuation, "continuation")?,
                "expected_ag_work",
            )?,
        };
        if expected_work != proposal_work {
            return Err("AG occurrence expected work differs from the exact proposal work".into());
        }
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("AG open request is an object")
            .remove("request_id");
        if self.request_id != digest_value(&value)? {
            return Err("request_id does not match the exact AG request preimage".into());
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        observation: &ObservationRecordV1,
        intent: &TypedCoarseIntentV2,
    ) -> Result<(), String> {
        self.validate()?;
        intent
            .validate_for_observation(observation)
            .map_err(|error| error.to_string())?;
        if self.subject_digest != intent.subject_digest
            || self.scope_digest != observation.posture.policy.subject.scope.digest
            || self.source_observation_id != observation.observation_id
            || self.source_support_id != observation.support.support_id
            || self.source_posture_id != observation.posture.posture_id
            || self.source_intent_id != intent.intent_id
        {
            return Err("AG request does not bind the exact Nightshift basis".into());
        }
        // The exact proposal's work must be the AG executable-work identity
        // the sealed intent derived from the actual executor plan.
        let proposal_work = exact_object(&self.proposal_input, "proposal_input")?
            .get("proposal")
            .and_then(|proposal| proposal.get("work"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "exact proposal work must be a digest".to_string())?;
        if proposal_work != intent.expected_ag_work {
            return Err(
                "AG request proposal work does not bind the intent's expected AG work".into(),
            );
        }
        Ok(())
    }

    pub fn prepared(&self) -> Result<PreparedAgRequestV1, CanonicalStoreError> {
        self.validate().map_err(CanonicalStoreError::Invalid)?;
        let exact_request = serde_json::to_value(self)?;
        Ok(PreparedAgRequestV1 {
            schema: PREPARED_AG_REQUEST_SCHEMA_V1.into(),
            request_digest: digest_value(&exact_request).map_err(CanonicalStoreError::Invalid)?,
            campaign_id: self.campaign_id.clone(),
            occurrence_id: self.occurrence_id.clone(),
            source_intent_id: self.source_intent_id.clone(),
            exact_request,
        })
    }
}

pub trait AgOccurrencePortV1 {
    fn open_occurrence(
        &mut self,
        request: &AgOpenOccurrenceRequestV1,
    ) -> Result<AgOccurrenceReferenceV1, String>;

    fn status(
        &mut self,
        campaign_id: &str,
        occurrence_id: &str,
    ) -> Result<AgOccurrenceReferenceV1, String>;
}

#[derive(Clone, Debug)]
pub struct AgLoopCtlPortV1 {
    program: PathBuf,
    database: PathBuf,
    observation_resolver: PathBuf,
    expected_observation_resolver_id: String,
    runtime_profile: PathBuf,
}

impl AgLoopCtlPortV1 {
    pub fn new(
        program: impl Into<PathBuf>,
        database: impl Into<PathBuf>,
        observation_resolver: impl Into<PathBuf>,
        expected_observation_resolver_id: impl Into<String>,
        runtime_profile: impl Into<PathBuf>,
    ) -> Result<Self, String> {
        let program = program.into();
        if program.file_name().and_then(|name| name.to_str()) != Some("ag-loopctl") {
            return Err("canonical AG adapter accepts only the ag-loopctl executable".into());
        }
        let database = database.into();
        let observation_resolver = observation_resolver.into();
        let expected_observation_resolver_id = expected_observation_resolver_id.into();
        let runtime_profile = runtime_profile.into();
        if database.as_os_str().is_empty()
            || observation_resolver.as_os_str().is_empty()
            || runtime_profile.as_os_str().is_empty()
            || expected_observation_resolver_id.trim().is_empty()
            || expected_observation_resolver_id
                .chars()
                .any(char::is_whitespace)
        {
            return Err(
                "AG database, observation resolver, resolver identity, and runtime profile must be non-empty".into(),
            );
        }
        Ok(Self {
            program,
            database,
            observation_resolver,
            expected_observation_resolver_id,
            runtime_profile,
        })
    }

    fn run(&self, arguments: &[&str]) -> Result<serde_json::Value, String> {
        let output = Command::new(&self.program)
            .args(arguments)
            .output()
            .map_err(|error| format!("ag-loopctl invocation failed: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "ag-loopctl refused: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&output.stdout);
        let value = serde_json::Value::deserialize(&mut deserializer)
            .map_err(|error| format!("ag-loopctl returned invalid JSON: {error}"))?;
        deserializer
            .end()
            .map_err(|error| format!("ag-loopctl returned trailing data: {error}"))?;
        Ok(value)
    }

    fn run_with_input(
        &self,
        command: &str,
        input: &serde_json::Value,
        include_observation_resolver: bool,
    ) -> Result<serde_json::Value, String> {
        let mut file = tempfile::NamedTempFile::new()
            .map_err(|error| format!("AG exact-input tempfile failed: {error}"))?;
        use std::io::Write as _;
        file.write_all(&serde_jcs::to_vec(input).map_err(|error| error.to_string())?)
            .map_err(|error| format!("AG exact-input write failed: {error}"))?;
        let database = self.database.to_string_lossy();
        let input_path = file.path().to_string_lossy();
        if include_observation_resolver {
            let resolver = self.observation_resolver.to_string_lossy();
            let resolver_id = &self.expected_observation_resolver_id;
            self.run(&[
                command,
                "--database",
                &database,
                "--input",
                &input_path,
                "--observation-resolver",
                &resolver,
                "--expected-observation-resolver-id",
                resolver_id,
            ])
        } else if command == "init" {
            let profile = self.runtime_profile.to_string_lossy();
            self.run(&[
                command,
                "--database",
                &database,
                "--genesis",
                &input_path,
                "--runtime-profile",
                &profile,
            ])
        } else {
            self.run(&[command, "--database", &database, "--input", &input_path])
        }
    }

    fn read_status(&self) -> Result<serde_json::Value, String> {
        let database = self.database.to_string_lossy();
        self.run(&["status", "--database", &database])
    }
}

impl AgOccurrencePortV1 for AgLoopCtlPortV1 {
    fn open_occurrence(
        &mut self,
        request: &AgOpenOccurrenceRequestV1,
    ) -> Result<AgOccurrenceReferenceV1, String> {
        request.validate()?;
        let initial_status = self.read_status().ok().and_then(|value| {
            parse_ag_snapshot(value, &request.campaign_id, &request.occurrence_id).ok()
        });
        let opened = if let Some(status) = initial_status {
            status
        } else {
            let value = match &request.mode {
                AgOpenModeV1::Genesis { genesis } => self.run_with_input("init", genesis, false)?,
                AgOpenModeV1::Continuation { continuation } => {
                    self.run_with_input("continue", continuation, false)?
                }
            };
            parse_ag_snapshot(value, &request.campaign_id, &request.occurrence_id)?
        };
        if opened.program_counter == AgProgramCounterV1::ObservationRequired {
            let value = self.run_with_input("record-proposal", &request.proposal_input, true)?;
            parse_ag_snapshot(value, &request.campaign_id, &request.occurrence_id)
        } else {
            Ok(opened)
        }
    }

    fn status(
        &mut self,
        campaign_id: &str,
        occurrence_id: &str,
    ) -> Result<AgOccurrenceReferenceV1, String> {
        parse_ag_snapshot(self.read_status()?, campaign_id, occurrence_id)
    }
}

fn parse_program_counter(state: &serde_json::Value) -> Result<AgProgramCounterV1, String> {
    let object = exact_object(state, "AG state")?;
    if object.len() != 1 {
        return Err("AG state must contain one closed program-counter variant".into());
    }
    match object.keys().next().map(String::as_str) {
        Some("observation_required") => Ok(AgProgramCounterV1::ObservationRequired),
        Some("proposal_recorded") => Ok(AgProgramCounterV1::ProposalRecorded),
        Some("standing_required") => Ok(AgProgramCounterV1::StandingRequired),
        Some("admissible_pending_authorization") => {
            Ok(AgProgramCounterV1::AdmissiblePendingAuthorization)
        }
        Some("authorization_consumed") => Ok(AgProgramCounterV1::AuthorizationConsumed),
        Some("dispatched") => Ok(AgProgramCounterV1::Dispatched),
        Some("reconciliation_required") => Ok(AgProgramCounterV1::ReconciliationRequired),
        Some("settled_observation_required") => Ok(AgProgramCounterV1::SettledObservationRequired),
        Some("halted") => Ok(AgProgramCounterV1::Halted),
        Some("completed") => Ok(AgProgramCounterV1::Completed),
        Some(value) => Err(format!("unknown AG program counter {value}")),
        None => Err("AG state is empty".into()),
    }
}

fn current_key_at_minimum_meta_depth(value: &serde_json::Value) -> Option<(String, String)> {
    fn visit(value: &serde_json::Value, depth: usize, found: &mut Vec<(usize, String, String)>) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(meta) = object.get("meta").and_then(serde_json::Value::as_object) {
                    if let Some(key) = meta.get("key").and_then(serde_json::Value::as_object) {
                        if let (Some(campaign), Some(occurrence)) = (
                            key.get("campaign").and_then(serde_json::Value::as_str),
                            key.get("occurrence").and_then(serde_json::Value::as_str),
                        ) {
                            found.push((depth, campaign.into(), occurrence.into()));
                        }
                    }
                }
                for child in object.values() {
                    visit(child, depth + 1, found);
                }
            }
            serde_json::Value::Array(array) => {
                for child in array {
                    visit(child, depth + 1, found);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    visit(value, 0, &mut found);
    let minimum = found.iter().map(|item| item.0).min()?;
    let mut keys: BTreeSet<_> = found
        .into_iter()
        .filter(|item| item.0 == minimum)
        .map(|(_, campaign, occurrence)| (campaign, occurrence))
        .collect();
    if keys.len() == 1 {
        keys.pop_first()
    } else {
        None
    }
}

fn unique_named_string(value: &serde_json::Value, field: &str) -> Option<String> {
    fn visit(value: &serde_json::Value, field: &str, found: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(value) = object.get(field).and_then(serde_json::Value::as_str) {
                    found.insert(value.into());
                }
                for child in object.values() {
                    visit(child, field, found);
                }
            }
            serde_json::Value::Array(array) => {
                for child in array {
                    visit(child, field, found);
                }
            }
            _ => {}
        }
    }
    let mut found = BTreeSet::new();
    visit(value, field, &mut found);
    (found.len() == 1).then(|| found.pop_first().expect("one value"))
}

pub fn parse_ag_snapshot(
    snapshot: serde_json::Value,
    campaign_id: &str,
    occurrence_id: &str,
) -> Result<AgOccurrenceReferenceV1, String> {
    require_digest("campaign_id", campaign_id)?;
    uuid::Uuid::parse_str(occurrence_id)
        .map_err(|_| "occurrence_id must be an independently allocated UUID".to_string())?;
    let object = exact_object(&snapshot, "AG snapshot")?;
    let state_digest = exact_string(object, "state_digest")?.to_owned();
    require_digest("AG state_digest", &state_digest)?;
    let state = object
        .get("state")
        .ok_or_else(|| "AG snapshot has no state".to_string())?;
    let program_counter = parse_program_counter(state)?;
    if current_key_at_minimum_meta_depth(state)
        != Some((campaign_id.to_owned(), occurrence_id.to_owned()))
    {
        return Err("AG snapshot names the wrong current campaign/occurrence".into());
    }
    let value = AgOccurrenceReferenceV1 {
        schema: AG_REFERENCE_SCHEMA_V1.into(),
        campaign_id: campaign_id.into(),
        occurrence_id: occurrence_id.into(),
        state_digest,
        snapshot_digest: digest_value(&snapshot)?,
        program_counter,
        docket_attempt_id: unique_named_string(state, "attempt"),
        settlement_id: unique_named_string(state, "settlement"),
        external_decision_request_id: None,
        exact_snapshot: snapshot,
    };
    value.validate().map_err(|error| error.to_string())?;
    Ok(value)
}

pub fn parse_ag_refusal(
    outcome: serde_json::Value,
    campaign_id: &str,
    occurrence_id: &str,
) -> Result<AgRefusalReferenceV1, String> {
    require_digest("campaign_id", campaign_id)?;
    uuid::Uuid::parse_str(occurrence_id)
        .map_err(|_| "occurrence_id must be an independently allocated UUID".to_string())?;
    let object = exact_object(&outcome, "AG refusal outcome")?;
    let expected_fields: BTreeSet<_> = ["at_state_digest", "code", "evidence", "key"]
        .into_iter()
        .collect();
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_fields {
        return Err("AG refusal outcome has missing or unknown fields".into());
    }
    let key = exact_object(
        object
            .get("key")
            .ok_or_else(|| "AG refusal key is missing".to_string())?,
        "AG refusal key",
    )?;
    if exact_string(key, "campaign")? != campaign_id
        || exact_string(key, "occurrence")? != occurrence_id
    {
        return Err("AG refusal names the wrong campaign or occurrence".into());
    }
    let at_state_digest = exact_string(object, "at_state_digest")?.to_owned();
    require_digest("at_state_digest", &at_state_digest)?;
    let code = exact_string(object, "code")?.to_owned();
    let allowed: BTreeSet<_> = [
        "stale_observation",
        "contradiction",
        "absent_standing",
        "standing_not_current",
        "inadmissible_exact_work",
        "budget_exhausted",
        "residual_unresolved",
        "human_decision_required",
        "profile_law_violation",
        "recovery_required",
    ]
    .into_iter()
    .collect();
    if !allowed.contains(code.as_str()) {
        return Err("unknown AG refusal code".into());
    }
    let evidence = match object.get("evidence") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => {
            require_digest("refusal evidence", value)?;
            Some(value.clone())
        }
        _ => return Err("AG refusal evidence must be null or an exact digest".into()),
    };
    let refusal = AgRefusalReferenceV1 {
        schema: AG_REFUSAL_SCHEMA_V1.into(),
        refusal_digest: digest_value(&outcome)?,
        campaign_id: campaign_id.into(),
        occurrence_id: occurrence_id.into(),
        at_state_digest,
        code,
        evidence,
        exact_outcome: outcome,
    };
    refusal.validate().map_err(|error| error.to_string())?;
    Ok(refusal)
}

pub fn fresh_occurrence_id() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn request() -> AgOpenOccurrenceRequestV1 {
        let campaign = digest('a');
        let occurrence = "00000000-0000-4000-8000-000000000001".to_string();
        AgOpenOccurrenceRequestV1 {
            schema: String::new(),
            request_id: String::new(),
            campaign_id: campaign.clone(),
            occurrence_id: occurrence.clone(),
            subject_digest: digest('b'),
            scope_digest: digest('c'),
            source_observation_id: digest('d'),
            source_support_id: digest('e'),
            source_posture_id: digest('f'),
            source_intent_id: digest('1'),
            mode: AgOpenModeV1::Genesis {
                genesis: serde_json::json!({
                    "campaign": campaign.clone(),
                    "occurrence": occurrence,
                    "program": digest('2'),
                    "expected_ag_work": digest('3'),
                    "residuals": [],
                    "budget": {"retry_limit": 1, "retries_used": 0, "probe_limit": 1, "probes_used": 0, "escalation_limit": 1, "escalations_used": 0}
                }),
            },
            proposal_input: serde_json::json!({
                "observation": digest('d'),
                "proposal": {
                    "schema": "ag.governed-loop.exact-work-proposal/v1",
                    "campaign": campaign,
                    "subject": digest('b'),
                    "scope": digest('c'),
                    "work_schema": "example.exact-work.v1",
                    "work": digest('3'),
                    "repair": null
                },
                "class": "initial"
            }),
        }
        .seal()
        .unwrap()
    }

    #[test]
    fn typed_request_has_no_standing_or_authorization_fields() {
        let value = serde_json::to_string(&request()).unwrap();
        assert!(!value.contains("standing"));
        assert!(!value.contains("authorization"));
        assert!(!value.contains("docket"));
    }

    #[test]
    fn recurrence_request_cannot_claim_retry() {
        let mut value = request();
        value.proposal_input["class"] = serde_json::json!("retry");
        value.request_id.clear();
        let mut encoded = serde_json::to_value(&value).unwrap();
        encoded.as_object_mut().unwrap().remove("request_id");
        value.request_id = digest_value(&encoded).unwrap();
        assert!(value.validate().is_err());
    }

    #[test]
    fn exact_proposal_cannot_substitute_the_observation_basis() {
        let mut value = request();
        value.proposal_input["observation"] = serde_json::json!(digest('9'));
        assert!(value.seal().is_err());
    }

    #[test]
    fn refusal_is_not_a_program_counter_variant() {
        assert!(serde_json::from_str::<AgProgramCounterV1>("\"refused\"").is_err());
    }

    #[test]
    fn refusal_preserves_exact_basis_and_rejects_substitution() {
        let request = request();
        let outcome = serde_json::json!({
            "key": {
                "campaign": request.campaign_id.clone(),
                "occurrence": request.occurrence_id.clone(),
            },
            "at_state_digest": digest('7'),
            "code": "stale_observation",
            "evidence": null,
        });
        let parsed = parse_ag_refusal(
            outcome.clone(),
            &request.campaign_id,
            &request.occurrence_id,
        )
        .unwrap();
        assert_eq!(parsed.exact_outcome, outcome);
        assert!(parse_ag_refusal(
            parsed.exact_outcome,
            &request.campaign_id,
            "00000000-0000-4000-8000-000000000099",
        )
        .is_err());
    }

    #[test]
    fn parser_rejects_wrong_occurrence_and_preserves_closed_pc() {
        let request = request();
        let snapshot = serde_json::json!({
            "prior_state_digest": digest('4'),
            "state_digest": digest('5'),
            "state": {
                "proposal_recorded": {
                    "meta": {
                        "key": {"campaign": request.campaign_id, "occurrence": request.occurrence_id},
                        "program": digest('2'), "residuals": [], "budget": {}, "used_human_decisions": []
                    }
                }
            }
        });
        let parsed = parse_ag_snapshot(
            snapshot.clone(),
            &request.campaign_id,
            &request.occurrence_id,
        )
        .unwrap();
        assert_eq!(parsed.program_counter, AgProgramCounterV1::ProposalRecorded);
        assert!(parse_ag_snapshot(
            snapshot,
            &request.campaign_id,
            "00000000-0000-4000-8000-000000000002"
        )
        .is_err());
    }

    #[test]
    fn adapter_rejects_arbitrary_executable() {
        assert!(AgLoopCtlPortV1::new(
            "sh",
            "ag.sqlite",
            "observe",
            "nightshift-observation-resolver/v1",
            "profile.json",
        )
        .is_err());
    }

    /// Explicit stable-contract check against a real canonical AG database.
    /// Ignored by default because the executable/database are external inputs.
    #[test]
    #[ignore = "set NIGHTSHIFT_TEST_AG_LOOPCTL, NIGHTSHIFT_TEST_AG_DB, NIGHTSHIFT_TEST_AG_OBSERVATION_RESOLVER, and NIGHTSHIFT_TEST_AG_RUNTIME_PROFILE"]
    fn real_ag_loopctl_status_contract() {
        let program = std::env::var_os("NIGHTSHIFT_TEST_AG_LOOPCTL").unwrap();
        let database = std::env::var_os("NIGHTSHIFT_TEST_AG_DB").unwrap();
        let resolver = std::env::var_os("NIGHTSHIFT_TEST_AG_OBSERVATION_RESOLVER").unwrap();
        let profile = std::env::var_os("NIGHTSHIFT_TEST_AG_RUNTIME_PROFILE").unwrap();
        let mut port = AgLoopCtlPortV1::new(
            program,
            database,
            resolver,
            "nightshift-observation-resolver/v1",
            profile,
        )
        .unwrap();
        let value = port
            .status(&digest('a'), "00000000-0000-4000-8000-000000000001")
            .unwrap();
        assert_eq!(value.program_counter, AgProgramCounterV1::ProposalRecorded);
        assert!(value.docket_attempt_id.is_none());
        assert!(value.settlement_id.is_none());
    }

    /// Opens a disposable real AG database and crosses only the canonical
    /// init/record-proposal seam. No standing, authorization, or dispatch
    /// command is available to this adapter.
    #[test]
    #[ignore = "set NIGHTSHIFT_TEST_AG_LOOPCTL, NIGHTSHIFT_TEST_AG_OBSERVATION_RESOLVER, and NIGHTSHIFT_TEST_AG_RUNTIME_PROFILE"]
    fn real_ag_loopctl_open_occurrence_contract() {
        let program = std::env::var_os("NIGHTSHIFT_TEST_AG_LOOPCTL").unwrap();
        let resolver = std::env::var_os("NIGHTSHIFT_TEST_AG_OBSERVATION_RESOLVER").unwrap();
        let profile = std::env::var_os("NIGHTSHIFT_TEST_AG_RUNTIME_PROFILE").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut port = AgLoopCtlPortV1::new(
            program,
            directory.path().join("ag.sqlite"),
            resolver,
            "nightshift-observation-resolver/v1",
            profile,
        )
        .unwrap();
        let request = request();
        let value = port.open_occurrence(&request).unwrap();
        assert_eq!(value.campaign_id, request.campaign_id);
        assert_eq!(value.occurrence_id, request.occurrence_id);
        assert_eq!(value.program_counter, AgProgramCounterV1::ProposalRecorded);
        assert!(value.docket_attempt_id.is_none());
        assert!(value.settlement_id.is_none());
    }
}
