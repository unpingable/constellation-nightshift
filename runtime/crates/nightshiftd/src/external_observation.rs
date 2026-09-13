//! Authenticated custody for non-NQ application/world observation candidates.
//!
//! The first closed adapter is Maude's local-Compose workflow.  The record
//! preserves exact execution evidence and PlanNode bindings, but deliberately
//! does not implement NQ admission, Nightshift currentness, standing,
//! authorization, or settlement.  It is source material for a future explicit
//! observation-cycle input, not an alternate observation cycle.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub const LOCAL_COMPOSE_OBSERVATION_SCHEMA_V1: &str = "maude.local-compose-world-observation/v1";
pub const LOCAL_COMPOSE_CLAIM_SCHEMA_V1: &str = "maude.local-compose-world-claim/v1";
pub const EXTERNAL_OBSERVATION_HANDOFF_SCHEMA_V1: &str =
    "nightshift.external_observation_handoff.v1";
pub const EXTERNAL_OBSERVATION_CUSTODY_SCHEMA_V1: &str =
    "nightshift.external_observation_custody_provenance.v1";
pub const EXTERNAL_OBSERVATION_EXPORT_SCHEMA_V1: &str = "nightshift.external_observation_export.v1";
pub const HMAC_AUTH_SCHEMA_V1: &str = "maude.hmac_sha256.v1";

const EXECUTOR_EVIDENCE_SCHEMA_V1: &str = "maude.local-compose.executor-evidence/v1";
const WORK_SCHEMA_V1: &str = "maude.local-compose-workflow/v1";
const EVIDENCE_DOMAIN: &str = "maude.local-compose.executor-evidence/v1";
const HANDOFF_AUTH_DOMAIN: &[u8] = b"nightshift-external-observation-handoff/v1\0";
const MAX_CREDENTIAL_BYTES: usize = 32;

const REQUIRED_NONCLAIMS: [&str; 4] = [
    "candidate is not Nightshift currentness",
    "Docket settlement is not world-state freshness",
    "producer authentication is not standing or authorization",
    "observation candidate cannot authorize or execute work",
];

pub(crate) fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a non-empty token"));
    }
    Ok(())
}

pub(crate) fn require_digest(name: &str, value: &str) -> Result<(), String> {
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

pub(crate) fn semantic_id<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "identity preimage is not an object".to_owned())?;
    object.remove(field);
    object.remove("authentication");
    let bytes = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub(crate) fn authentication_preimage<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "authentication preimage is not an object".to_owned())?
        .remove("authentication");
    serde_jcs::to_vec(&value).map_err(|error| error.to_string())
}

pub(crate) fn hash_domain(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ag-ng\0digest\0v1\0");
    hasher.update((domain.len() as u128).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((payload.len() as u128).to_be_bytes());
    hasher.update(payload);
    format!("sha256:{:x}", hasher.finalize())
}

fn hmac_sha256(key: &[u8], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut material = [0_u8; BLOCK];
    if key.len() > BLOCK {
        material[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        material[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= material[index];
        outer_pad[index] ^= material[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(domain);
    inner.update(payload);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

pub(crate) fn hmac_text(key: &[u8], domain: &[u8], payload: &[u8]) -> String {
    let mut text = "hmac-sha256:".to_owned();
    for byte in hmac_sha256(key, domain, payload) {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

pub(crate) fn read_protected_key(path: &Path) -> Result<[u8; MAX_CREDENTIAL_BYTES], String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot open external-observation credential: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect external-observation credential: {error}"))?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err("external-observation credential must be a protected regular file".into());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("external-observation credential is owned by another principal".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read external-observation credential: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "external-observation credential must contain exactly 32 bytes".into())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalComposeActionV1 {
    Qualify,
    Teardown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorOutcomeV1 {
    Success,
    Failure,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldClaimStatusV1 {
    Satisfied,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalComposeClaimKindV1 {
    FrontDoorReachable,
    CacheMissThenHit,
    SingleCacheFailureSurvived,
    CacheTopologyRestored,
    CampaignResourcesAbsent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalComposeWorldClaimV1 {
    pub schema: String,
    pub claim_id: String,
    pub kind: LocalComposeClaimKindV1,
    pub status: WorldClaimStatusV1,
    pub plan_node_id: String,
    pub compiled_output_identity: String,
    pub evidence_paths: Vec<String>,
}

impl LocalComposeWorldClaimV1 {
    fn validate(&self) -> Result<(), String> {
        if self.schema != LOCAL_COMPOSE_CLAIM_SCHEMA_V1 {
            return Err("unsupported local-Compose world-claim schema".into());
        }
        require_digest("claim_id", &self.claim_id)?;
        require_token("plan_node_id", &self.plan_node_id)?;
        require_digest("compiled_output_identity", &self.compiled_output_identity)?;
        if self.evidence_paths.is_empty()
            || self.evidence_paths.iter().any(|path| {
                !path.starts_with("/evidence/") || path.chars().any(char::is_whitespace)
            })
        {
            return Err("claim evidence paths must be exact /evidence JSON pointers".into());
        }
        if self.claim_id != semantic_id(self, "claim_id")? {
            return Err("claim identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalComposeWorldObservationV1 {
    pub schema: String,
    pub observation_id: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub action: LocalComposeActionV1,
    pub plan_document_digest: String,
    pub compilation_id: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub proposal_id: String,
    pub exact_work_id: String,
    pub issuance_id: String,
    pub attempt_id: String,
    pub settlement_id: String,
    pub subject_digest: String,
    pub scope_digest: String,
    pub executor_evidence_receipt: String,
    pub executor_evidence_bytes: u64,
    pub observed_at_unix_ms: i64,
    pub outcome: ExecutorOutcomeV1,
    pub source_evidence: Value,
    pub claims: Vec<LocalComposeWorldClaimV1>,
    pub nonclaims: Vec<String>,
}

impl LocalComposeWorldObservationV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != LOCAL_COMPOSE_OBSERVATION_SCHEMA_V1 {
            return Err("unsupported local-Compose world-observation schema".into());
        }
        if self.adapter_id != "maude.local-compose-observation-adapter"
            || self.adapter_version != "1"
        {
            return Err("unsupported local-Compose observation adapter identity".into());
        }
        for (name, value) in [
            ("observation_id", &self.observation_id),
            ("plan_document_digest", &self.plan_document_digest),
            ("compilation_id", &self.compilation_id),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("exact_work_id", &self.exact_work_id),
            ("issuance_id", &self.issuance_id),
            ("attempt_id", &self.attempt_id),
            ("settlement_id", &self.settlement_id),
            ("subject_digest", &self.subject_digest),
            ("scope_digest", &self.scope_digest),
            ("executor_evidence_receipt", &self.executor_evidence_receipt),
        ] {
            require_digest(name, value)?;
        }
        require_token("occurrence_id", &self.occurrence_id)?;
        if uuid::Uuid::parse_str(&self.occurrence_id)
            .map(|value| value.to_string())
            .ok()
            .as_deref()
            != Some(self.occurrence_id.as_str())
        {
            return Err("occurrence_id must be a canonical UUID".into());
        }
        if self.executor_evidence_bytes == 0 || self.executor_evidence_bytes > 16 * 1024 * 1024 {
            return Err("executor evidence length is invalid".into());
        }
        if self.observed_at_unix_ms < 0 {
            return Err("executor observation time is invalid".into());
        }
        if self.nonclaims != REQUIRED_NONCLAIMS.map(str::to_owned) {
            return Err("external observation nonclaims are not the exact v1 set".into());
        }
        self.validate_source_evidence()?;
        self.validate_claims()?;
        if self.observation_id != semantic_id(self, "observation_id")? {
            return Err("external observation identity mismatch".into());
        }
        Ok(())
    }

    fn validate_source_evidence(&self) -> Result<(), String> {
        let source = self
            .source_evidence
            .as_object()
            .ok_or_else(|| "executor source evidence is not an object".to_owned())?;
        let exact_fields = [
            "dispatch",
            "docket_outcome",
            "evidence",
            "evidence_schema",
            "observed_at_unix_ms",
            "outcome",
        ];
        if source.len() != exact_fields.len()
            || exact_fields
                .iter()
                .any(|field| !source.contains_key(*field))
        {
            return Err("executor source evidence has unknown or missing fields".into());
        }
        if source.get("evidence_schema").and_then(Value::as_str)
            != Some(EXECUTOR_EVIDENCE_SCHEMA_V1)
        {
            return Err("unsupported executor evidence schema".into());
        }
        if source.get("observed_at_unix_ms").and_then(Value::as_i64)
            != Some(self.observed_at_unix_ms)
            || source.get("outcome")
                != Some(&serde_json::to_value(self.outcome).map_err(|error| error.to_string())?)
        {
            return Err("executor evidence observation facts are substituted".into());
        }
        let dispatch = source
            .get("dispatch")
            .and_then(Value::as_object)
            .ok_or_else(|| "executor dispatch is not an object".to_owned())?;
        let dispatch_fields = [
            "attempt",
            "marker",
            "scope",
            "subject",
            "work",
            "work_schema",
        ];
        if dispatch.len() != dispatch_fields.len()
            || dispatch_fields
                .iter()
                .any(|field| !dispatch.contains_key(*field))
        {
            return Err("executor dispatch has unknown or missing fields".into());
        }
        if dispatch.get("attempt").and_then(Value::as_str) != Some(self.attempt_id.as_str())
            || dispatch.get("subject").and_then(Value::as_str) != Some(self.subject_digest.as_str())
            || dispatch.get("scope").and_then(Value::as_str) != Some(self.scope_digest.as_str())
            || dispatch.get("work").and_then(Value::as_str) != Some(self.exact_work_id.as_str())
            || dispatch.get("work_schema").and_then(Value::as_str) != Some(WORK_SCHEMA_V1)
        {
            return Err("executor dispatch is not bound to observation identity".into());
        }
        let docket = source
            .get("docket_outcome")
            .and_then(Value::as_object)
            .ok_or_else(|| "Docket outcome is not an object".to_owned())?;
        let docket_fields = ["attempt", "marker", "outcome", "receipt"];
        if docket.len() != docket_fields.len()
            || docket_fields
                .iter()
                .any(|field| !docket.contains_key(*field))
        {
            return Err("Docket outcome has unknown or missing fields".into());
        }
        if docket.get("attempt").and_then(Value::as_str) != Some(self.attempt_id.as_str())
            || docket.get("marker") != dispatch.get("marker")
            || docket.get("receipt").and_then(Value::as_str)
                != Some(self.executor_evidence_receipt.as_str())
            || docket.get("outcome")
                != Some(&serde_json::to_value(self.outcome).map_err(|error| error.to_string())?)
        {
            return Err("Docket outcome is not bound to observation identity".into());
        }
        let mut preimage = self.source_evidence.clone();
        preimage
            .as_object_mut()
            .expect("checked above")
            .remove("docket_outcome");
        let bytes = serde_jcs::to_vec(&preimage).map_err(|error| error.to_string())?;
        if hash_domain(EVIDENCE_DOMAIN, &bytes) != self.executor_evidence_receipt {
            return Err("executor evidence receipt mismatch".into());
        }
        let source_bytes = serde_jcs::to_vec(&self.source_evidence)
            .map_err(|error| error.to_string())?
            .len();
        if u64::try_from(source_bytes).map_err(|_| "executor evidence too large")?
            != self.executor_evidence_bytes
        {
            return Err("executor evidence byte length mismatch".into());
        }
        if self.outcome == ExecutorOutcomeV1::Success {
            self.validate_success_evidence()?;
        }
        Ok(())
    }

    fn validate_success_evidence(&self) -> Result<(), String> {
        match self.action {
            LocalComposeActionV1::Qualify => {
                if self
                    .source_evidence
                    .pointer("/evidence/health/status")
                    .and_then(Value::as_u64)
                    != Some(200)
                    || self.source_evidence.pointer("/evidence/restored_nodes")
                        != Some(&serde_json::json!(["cache-a", "cache-b"]))
                {
                    return Err("successful qualify evidence contradicts health/topology".into());
                }
                let sequence = self
                    .source_evidence
                    .pointer("/evidence/cache_sequence")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "successful qualify evidence lacks cache sequence".to_owned())?;
                let expected = [
                    ("MISS", "cache-a"),
                    ("MISS", "cache-b"),
                    ("HIT", "cache-a"),
                    ("HIT", "cache-b"),
                ];
                if sequence.len() != expected.len()
                    || sequence.iter().zip(expected).any(|(item, (cache, node))| {
                        item.get("cache").and_then(Value::as_str) != Some(cache)
                            || item.get("cache_node").and_then(Value::as_str) != Some(node)
                    })
                {
                    return Err("successful qualify evidence contradicts cache sequence".into());
                }
                let failure_requests = self
                    .source_evidence
                    .pointer("/evidence/failure_requests")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        "successful qualify evidence lacks failure requests".to_owned()
                    })?;
                if failure_requests.is_empty()
                    || failure_requests.iter().any(|item| {
                        item.get("status").and_then(Value::as_u64) != Some(200)
                            || item.get("cache_node").and_then(Value::as_str) != Some("cache-b")
                    })
                {
                    return Err("successful qualify evidence contradicts failover".into());
                }
            }
            LocalComposeActionV1::Teardown => {
                if self
                    .source_evidence
                    .pointer("/evidence/campaign_containers_running")
                    .and_then(Value::as_u64)
                    != Some(0)
                    || self
                        .source_evidence
                        .pointer("/evidence/campaign_networks_remaining")
                        .and_then(Value::as_u64)
                        .is_some_and(|value| value != 0)
                {
                    return Err("successful teardown evidence contradicts resource absence".into());
                }
            }
        }
        Ok(())
    }

    fn validate_claims(&self) -> Result<(), String> {
        let expected: &[(LocalComposeClaimKindV1, &str, &[&str])] = match self.action {
            LocalComposeActionV1::Qualify => &[
                (
                    LocalComposeClaimKindV1::FrontDoorReachable,
                    "pn_health",
                    &["/evidence/health"],
                ),
                (
                    LocalComposeClaimKindV1::CacheMissThenHit,
                    "pn_cache_behavior",
                    &["/evidence/cache_sequence"],
                ),
                (
                    LocalComposeClaimKindV1::SingleCacheFailureSurvived,
                    "pn_continued",
                    &["/evidence/failure_requests"],
                ),
                (
                    LocalComposeClaimKindV1::CacheTopologyRestored,
                    "pn_restore",
                    &["/evidence/restored_nodes", "/evidence/restored_health"],
                ),
            ],
            LocalComposeActionV1::Teardown => &[(
                LocalComposeClaimKindV1::CampaignResourcesAbsent,
                "pn_teardown",
                if self
                    .source_evidence
                    .pointer("/evidence/campaign_networks_remaining")
                    .is_some()
                {
                    &[
                        "/evidence/campaign_containers_running",
                        "/evidence/campaign_networks_remaining",
                    ][..]
                } else {
                    &["/evidence/campaign_containers_running"][..]
                },
            )],
        };
        if self.claims.len() != expected.len() {
            return Err("external observation claim set is incomplete".into());
        }
        let expected_status = if self.outcome == ExecutorOutcomeV1::Success {
            WorldClaimStatusV1::Satisfied
        } else {
            WorldClaimStatusV1::Unknown
        };
        for (claim, (kind, node, paths)) in self.claims.iter().zip(expected.iter()) {
            claim.validate()?;
            if claim.kind != *kind
                || claim.plan_node_id != *node
                || claim.status != expected_status
                || claim.evidence_paths
                    != paths
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>()
                || claim
                    .evidence_paths
                    .iter()
                    .any(|path| self.source_evidence.pointer(path).is_none())
            {
                return Err("external observation claim projection mismatch".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HmacAuthenticationV1 {
    pub schema: String,
    pub key_id: String,
    pub tag: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationHandoffV1 {
    pub schema: String,
    pub handoff_id: String,
    pub producer_principal_id: String,
    pub producer_key_id: String,
    pub target_runtime_id: String,
    pub observation: LocalComposeWorldObservationV1,
    pub created_at: DateTime<Utc>,
    pub authentication: HmacAuthenticationV1,
}

impl ExternalObservationHandoffV1 {
    pub fn validate_untrusted(&self) -> Result<(), String> {
        if self.schema != EXTERNAL_OBSERVATION_HANDOFF_SCHEMA_V1 {
            return Err("unsupported external-observation handoff schema".into());
        }
        require_digest("handoff_id", &self.handoff_id)?;
        require_token("producer_principal_id", &self.producer_principal_id)?;
        require_token("producer_key_id", &self.producer_key_id)?;
        require_token("target_runtime_id", &self.target_runtime_id)?;
        if self.authentication.schema != HMAC_AUTH_SCHEMA_V1
            || self.authentication.key_id != self.producer_key_id
            || !self.authentication.tag.starts_with("hmac-sha256:")
        {
            return Err("external-observation authentication is malformed".into());
        }
        require_digest("handoff_id", &self.handoff_id)?;
        self.observation.validate()?;
        if self.handoff_id != semantic_id(self, "handoff_id")? {
            return Err("external-observation handoff identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedExternalObservationHandoffV1 {
    handoff: ExternalObservationHandoffV1,
}

impl VerifiedExternalObservationHandoffV1 {
    pub(crate) fn handoff(&self) -> &ExternalObservationHandoffV1 {
        &self.handoff
    }
}

#[derive(Debug)]
pub struct ExternalObservationVerifierV1 {
    expected_principal_id: String,
    expected_key_id: String,
    expected_runtime_id: String,
    producer_key: [u8; MAX_CREDENTIAL_BYTES],
}

impl ExternalObservationVerifierV1 {
    pub fn from_key_file(
        expected_principal_id: String,
        expected_key_id: String,
        expected_runtime_id: String,
        key_path: &Path,
    ) -> Result<Self, String> {
        require_token("expected producer principal", &expected_principal_id)?;
        require_token("expected producer key", &expected_key_id)?;
        require_token("expected Nightshift runtime", &expected_runtime_id)?;
        Ok(Self {
            expected_principal_id,
            expected_key_id,
            expected_runtime_id,
            producer_key: read_protected_key(key_path)?,
        })
    }

    pub fn verify(
        &self,
        handoff: &ExternalObservationHandoffV1,
    ) -> Result<VerifiedExternalObservationHandoffV1, String> {
        handoff.validate_untrusted()?;
        if handoff.producer_principal_id != self.expected_principal_id
            || handoff.producer_key_id != self.expected_key_id
        {
            return Err("external-observation producer identity mismatch".into());
        }
        if handoff.target_runtime_id != self.expected_runtime_id {
            return Err("external-observation target runtime mismatch".into());
        }
        let expected = hmac_text(
            &self.producer_key,
            HANDOFF_AUTH_DOMAIN,
            &authentication_preimage(handoff)?,
        );
        if !constant_time_eq(expected.as_bytes(), handoff.authentication.tag.as_bytes()) {
            return Err("external-observation authentication failed".into());
        }
        Ok(VerifiedExternalObservationHandoffV1 {
            handoff: handoff.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(principal: &str, key_id: &str, runtime: &str, key: [u8; 32]) -> Self {
        Self {
            expected_principal_id: principal.into(),
            expected_key_id: key_id.into(),
            expected_runtime_id: runtime.into(),
            producer_key: key,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationCustodyProvenanceV1 {
    pub schema: String,
    pub custody_id: String,
    pub handoff_id: String,
    pub observation_id: String,
    pub producer_principal_id: String,
    pub producer_key_id: String,
    pub target_runtime_id: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub exact_work_id: String,
    pub attempt_id: String,
    pub settlement_id: String,
    pub executor_evidence_receipt: String,
    pub received_at: DateTime<Utc>,
}

impl ExternalObservationCustodyProvenanceV1 {
    pub(crate) fn mint(
        verified: &VerifiedExternalObservationHandoffV1,
        received_at: DateTime<Utc>,
    ) -> Result<Self, String> {
        let handoff = verified.handoff();
        let observation = &handoff.observation;
        let mut value = Self {
            schema: EXTERNAL_OBSERVATION_CUSTODY_SCHEMA_V1.into(),
            custody_id: String::new(),
            handoff_id: handoff.handoff_id.clone(),
            observation_id: observation.observation_id.clone(),
            producer_principal_id: handoff.producer_principal_id.clone(),
            producer_key_id: handoff.producer_key_id.clone(),
            target_runtime_id: handoff.target_runtime_id.clone(),
            campaign_id: observation.campaign_id.clone(),
            occurrence_id: observation.occurrence_id.clone(),
            exact_work_id: observation.exact_work_id.clone(),
            attempt_id: observation.attempt_id.clone(),
            settlement_id: observation.settlement_id.clone(),
            executor_evidence_receipt: observation.executor_evidence_receipt.clone(),
            received_at,
        };
        value.custody_id = semantic_id(&value, "custody_id")?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EXTERNAL_OBSERVATION_CUSTODY_SCHEMA_V1 {
            return Err("unsupported external-observation custody schema".into());
        }
        for (name, value) in [
            ("custody_id", &self.custody_id),
            ("handoff_id", &self.handoff_id),
            ("observation_id", &self.observation_id),
            ("campaign_id", &self.campaign_id),
            ("exact_work_id", &self.exact_work_id),
            ("attempt_id", &self.attempt_id),
            ("settlement_id", &self.settlement_id),
            ("executor_evidence_receipt", &self.executor_evidence_receipt),
        ] {
            require_digest(name, value)?;
        }
        require_token("occurrence_id", &self.occurrence_id)?;
        require_token("producer_principal_id", &self.producer_principal_id)?;
        require_token("producer_key_id", &self.producer_key_id)?;
        require_token("target_runtime_id", &self.target_runtime_id)?;
        if self.custody_id != semantic_id(self, "custody_id")? {
            return Err("external-observation custody identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAgeV1 {
    FreshAtEvaluation,
    StaleAtEvaluation,
    NotYetObserved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationExportMatchV1 {
    pub observation: LocalComposeWorldObservationV1,
    pub custody: ExternalObservationCustodyProvenanceV1,
    pub evaluated_at_unix_ms: i64,
    pub evidence_ttl_ms: u64,
    pub evidence_age: EvidenceAgeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservationExportV1 {
    pub schema: String,
    pub query: ExternalObservationQueryV1,
    pub matches: Vec<ExternalObservationExportMatchV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalObservationQueryV1 {
    Observation {
        observation_id: String,
    },
    GovernedOccurrence {
        campaign_id: String,
        occurrence_id: String,
    },
    Attempt {
        attempt_id: String,
    },
}

impl ExternalObservationQueryV1 {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Observation { observation_id } => {
                require_digest("observation_id", observation_id)
            }
            Self::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } => {
                require_digest("campaign_id", campaign_id)?;
                require_token("occurrence_id", occurrence_id)
            }
            Self::Attempt { attempt_id } => require_digest("attempt_id", attempt_id),
        }
    }
}

pub fn evidence_age(observed_at: i64, evaluated_at: i64, ttl_ms: u64) -> EvidenceAgeV1 {
    if evaluated_at < observed_at {
        EvidenceAgeV1::NotYetObserved
    } else if u64::try_from(evaluated_at - observed_at)
        .map(|age| age <= ttl_ms)
        .unwrap_or(false)
    {
        EvidenceAgeV1::FreshAtEvaluation
    } else {
        EvidenceAgeV1::StaleAtEvaluation
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::canonical_store::{CanonicalStore, CanonicalStoreError};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn digest(label: &str) -> String {
        format!("sha256:{:x}", Sha256::digest(label.as_bytes()))
    }

    pub(crate) fn signed_handoff(
        key: &[u8; 32],
        created_at: &str,
        occurrence: &str,
    ) -> ExternalObservationHandoffV1 {
        let attempt = digest("attempt");
        let marker = digest("marker");
        let source_without_outcome = serde_json::json!({
            "dispatch": {
                "attempt": attempt,
                "marker": marker,
                "scope": digest("scope"),
                "subject": digest("subject"),
                "work": digest("work"),
                "work_schema": WORK_SCHEMA_V1,
            },
            "evidence": {
                "health": {"status": 200},
                "cache_sequence": [
                    {"cache":"MISS","cache_node":"cache-a"},
                    {"cache":"MISS","cache_node":"cache-b"},
                    {"cache":"HIT","cache_node":"cache-a"},
                    {"cache":"HIT","cache_node":"cache-b"}
                ],
                "failure_requests": [{"status":200,"cache_node":"cache-b"}],
                "restored_nodes": ["cache-a", "cache-b"],
                "restored_health": {"status": 200}
            },
            "evidence_schema": EXECUTOR_EVIDENCE_SCHEMA_V1,
            "observed_at_unix_ms": 1000,
            "outcome": "success"
        });
        let evidence_receipt = hash_domain(
            EVIDENCE_DOMAIN,
            &serde_jcs::to_vec(&source_without_outcome).unwrap(),
        );
        let mut source = source_without_outcome;
        source.as_object_mut().unwrap().insert(
            "docket_outcome".into(),
            serde_json::json!({
                "attempt": attempt,
                "marker": marker,
                "outcome": "success",
                "receipt": evidence_receipt,
            }),
        );
        let mut claims = Vec::new();
        for (kind, node, paths) in [
            (
                LocalComposeClaimKindV1::FrontDoorReachable,
                "pn_health",
                vec!["/evidence/health"],
            ),
            (
                LocalComposeClaimKindV1::CacheMissThenHit,
                "pn_cache_behavior",
                vec!["/evidence/cache_sequence"],
            ),
            (
                LocalComposeClaimKindV1::SingleCacheFailureSurvived,
                "pn_continued",
                vec!["/evidence/failure_requests"],
            ),
            (
                LocalComposeClaimKindV1::CacheTopologyRestored,
                "pn_restore",
                vec!["/evidence/restored_nodes", "/evidence/restored_health"],
            ),
        ] {
            let mut claim = LocalComposeWorldClaimV1 {
                schema: LOCAL_COMPOSE_CLAIM_SCHEMA_V1.into(),
                claim_id: String::new(),
                kind,
                status: WorldClaimStatusV1::Satisfied,
                plan_node_id: node.into(),
                compiled_output_identity: digest(node),
                evidence_paths: paths.into_iter().map(str::to_owned).collect(),
            };
            claim.claim_id = semantic_id(&claim, "claim_id").unwrap();
            claims.push(claim);
        }
        let mut observation = LocalComposeWorldObservationV1 {
            schema: LOCAL_COMPOSE_OBSERVATION_SCHEMA_V1.into(),
            observation_id: String::new(),
            adapter_id: "maude.local-compose-observation-adapter".into(),
            adapter_version: "1".into(),
            action: LocalComposeActionV1::Qualify,
            plan_document_digest: digest("plan"),
            compilation_id: digest("compilation"),
            campaign_id: digest("campaign"),
            occurrence_id: occurrence.into(),
            proposal_id: digest("proposal"),
            exact_work_id: digest("work"),
            issuance_id: digest("issuance"),
            attempt_id: digest("attempt"),
            settlement_id: digest("settlement"),
            subject_digest: digest("subject"),
            scope_digest: digest("scope"),
            executor_evidence_receipt: evidence_receipt,
            executor_evidence_bytes: u64::try_from(serde_jcs::to_vec(&source).unwrap().len())
                .unwrap(),
            observed_at_unix_ms: 1000,
            outcome: ExecutorOutcomeV1::Success,
            source_evidence: source,
            claims,
            nonclaims: REQUIRED_NONCLAIMS.map(str::to_owned).into(),
        };
        observation.observation_id = semantic_id(&observation, "observation_id").unwrap();
        let mut handoff = ExternalObservationHandoffV1 {
            schema: EXTERNAL_OBSERVATION_HANDOFF_SCHEMA_V1.into(),
            handoff_id: String::new(),
            producer_principal_id: "maude-observer:local".into(),
            producer_key_id: "maude-observer-key:one".into(),
            target_runtime_id: "nightshift:local".into(),
            observation,
            created_at: DateTime::parse_from_rfc3339(created_at)
                .unwrap()
                .with_timezone(&Utc),
            authentication: HmacAuthenticationV1 {
                schema: HMAC_AUTH_SCHEMA_V1.into(),
                key_id: "maude-observer-key:one".into(),
                tag: String::new(),
            },
        };
        handoff.handoff_id = semantic_id(&handoff, "handoff_id").unwrap();
        handoff.authentication.tag = hmac_text(
            key,
            HANDOFF_AUTH_DOMAIN,
            &authentication_preimage(&handoff).unwrap(),
        );
        handoff
    }

    pub(crate) fn reseal_handoff(handoff: &mut ExternalObservationHandoffV1, key: &[u8; 32]) {
        let mut evidence_preimage = handoff.observation.source_evidence.clone();
        evidence_preimage
            .as_object_mut()
            .unwrap()
            .remove("docket_outcome");
        let receipt = hash_domain(
            EVIDENCE_DOMAIN,
            &serde_jcs::to_vec(&evidence_preimage).unwrap(),
        );
        handoff.observation.executor_evidence_receipt = receipt.clone();
        handoff.observation.source_evidence["docket_outcome"]["receipt"] =
            serde_json::json!(receipt);
        handoff.observation.executor_evidence_bytes = u64::try_from(
            serde_jcs::to_vec(&handoff.observation.source_evidence)
                .unwrap()
                .len(),
        )
        .unwrap();
        handoff.observation.observation_id =
            semantic_id(&handoff.observation, "observation_id").unwrap();
        handoff.handoff_id = semantic_id(handoff, "handoff_id").unwrap();
        handoff.authentication.tag = hmac_text(
            key,
            HANDOFF_AUTH_DOMAIN,
            &authentication_preimage(handoff).unwrap(),
        );
    }

    #[test]
    fn evidence_age_is_not_currentness_and_has_closed_boundaries() {
        assert_eq!(evidence_age(100, 99, 5), EvidenceAgeV1::NotYetObserved);
        assert_eq!(evidence_age(100, 105, 5), EvidenceAgeV1::FreshAtEvaluation);
        assert_eq!(evidence_age(100, 106, 5), EvidenceAgeV1::StaleAtEvaluation);
    }

    #[test]
    fn public_types_contain_no_authority_capability() {
        let source = include_str!("external_observation.rs");
        for forbidden in [
            concat!("pub ", "authorization:"),
            concat!("pub ", "spend:"),
            concat!("pub ", "standing:"),
            concat!("pub ", "capability:"),
            concat!("pub ", "currentness:"),
        ] {
            assert!(!source.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn authenticated_candidate_survives_restart_without_becoming_cycle_currentness() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        let key = [7_u8; 32];
        let handoff = signed_handoff(
            &key,
            "1970-01-01T00:00:02Z",
            "00000000-0000-4000-8000-000000000000",
        );
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let verified = verifier.verify(&handoff).unwrap();
        let first_received = DateTime::parse_from_rfc3339("1970-01-01T00:00:03Z")
            .unwrap()
            .with_timezone(&Utc);
        let first = CanonicalStore::open(&database)
            .unwrap()
            .record_external_observation(&verified, first_received)
            .unwrap();
        let mut reopened = CanonicalStore::open(&database).unwrap();
        let replay = reopened
            .record_external_observation(
                &verified,
                DateTime::parse_from_rfc3339("1970-01-01T00:00:09Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();
        assert_eq!(replay, first);
        assert!(reopened.list_cycles().unwrap().is_empty());
        let export = reopened
            .export_external_observation(
                ExternalObservationQueryV1::Attempt {
                    attempt_id: digest("attempt"),
                },
                1_005,
                5,
            )
            .unwrap();
        assert_eq!(export.matches.len(), 1);
        assert_eq!(
            export.matches[0].evidence_age,
            EvidenceAgeV1::FreshAtEvaluation
        );
        let stale = reopened
            .export_external_observation(
                ExternalObservationQueryV1::Observation {
                    observation_id: handoff.observation.observation_id,
                },
                1_006,
                5,
            )
            .unwrap();
        assert_eq!(
            stale.matches[0].evidence_age,
            EvidenceAgeV1::StaleAtEvaluation
        );
    }

    #[test]
    fn wrong_key_runtime_and_source_substitution_refuse_before_persistence() {
        let key = [7_u8; 32];
        let handoff = signed_handoff(
            &key,
            "1970-01-01T00:00:02Z",
            "00000000-0000-4000-8000-000000000000",
        );
        let wrong_key = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            [8_u8; 32],
        );
        assert!(wrong_key.verify(&handoff).is_err());
        let wrong_runtime = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:other",
            key,
        );
        assert!(wrong_runtime.verify(&handoff).is_err());
        let mut substituted = handoff;
        substituted.observation.source_evidence["evidence"]["health"]["status"] =
            serde_json::json!(503);
        substituted.observation.observation_id =
            semantic_id(&substituted.observation, "observation_id").unwrap();
        substituted.handoff_id = semantic_id(&substituted, "handoff_id").unwrap();
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        assert!(verifier.verify(&substituted).is_err());
    }

    #[test]
    fn authenticated_but_semantically_contradictory_success_evidence_refuses() {
        let key = [7_u8; 32];
        let mut handoff = signed_handoff(
            &key,
            "1970-01-01T00:00:02Z",
            "00000000-0000-4000-8000-000000000000",
        );
        handoff.observation.source_evidence["evidence"]["health"]["status"] =
            serde_json::json!(503);
        reseal_handoff(&mut handoff, &key);

        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        assert_eq!(
            verifier.verify(&handoff).unwrap_err(),
            "successful qualify evidence contradicts health/topology"
        );
    }

    #[test]
    fn conflicting_valid_handoff_for_same_attempt_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        let key = [7_u8; 32];
        let first = signed_handoff(
            &key,
            "1970-01-01T00:00:02Z",
            "00000000-0000-4000-8000-000000000000",
        );
        let second = signed_handoff(
            &key,
            "1970-01-01T00:00:03Z",
            "00000000-0000-4000-8000-000000000001",
        );
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let first = verifier.verify(&first).unwrap();
        let second = verifier.verify(&second).unwrap();
        let mut store = CanonicalStore::open(&database).unwrap();
        let received = DateTime::parse_from_rfc3339("1970-01-01T00:00:04Z")
            .unwrap()
            .with_timezone(&Utc);
        store.record_external_observation(&first, received).unwrap();
        assert!(matches!(
            store.record_external_observation(&second, received),
            Err(CanonicalStoreError::ExternalObservationConflict(_))
        ));
    }

    #[test]
    fn concurrent_conflicting_candidates_accept_at_most_one() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        CanonicalStore::open(&database).unwrap();
        let key = [7_u8; 32];
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let candidates = [
            signed_handoff(
                &key,
                "1970-01-01T00:00:02Z",
                "00000000-0000-4000-8000-000000000000",
            ),
            signed_handoff(
                &key,
                "1970-01-01T00:00:03Z",
                "00000000-0000-4000-8000-000000000001",
            ),
        ]
        .map(|handoff| verifier.verify(&handoff).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let stores = [
            CanonicalStore::open(&database).unwrap(),
            CanonicalStore::open(&database).unwrap(),
        ];
        let handles = candidates
            .into_iter()
            .zip(stores)
            .map(|(candidate, mut store)| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.record_external_observation(
                        &candidate,
                        DateTime::parse_from_rfc3339("1970-01-01T00:00:04Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    )
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(CanonicalStoreError::ExternalObservationConflict(_))
                ))
                .count(),
            1
        );
    }
}
