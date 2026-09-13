//! Authenticated custody for Maude authoring-context handoffs.
//!
//! Custody answers who delivered an exact, session-bound assertion to this
//! Nightshift deployment. It is deliberately separate from authoring lineage
//! and is not accepted by currentness, standing, admissibility, AG spend, or
//! Docket APIs. Authentication establishes custody, never permission.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::authoring_context::{
    AuthoringContextProvenanceV1, AuthoringContextQueryV1, MaudeAuthoringContextInputV1,
};

pub const SESSION_CUSTODY_SCHEMA_V1: &str = "maude.supervised_session_custody.v1";
pub const HANDOFF_SCHEMA_V1: &str = "nightshift.maude_authoring_context_handoff.v1";
pub const HMAC_AUTH_SCHEMA_V1: &str = "maude.hmac_sha256.v1";
pub const CUSTODY_PROVENANCE_SCHEMA_V1: &str = "nightshift.authoring_context_custody_provenance.v1";
pub const CUSTODY_EXPORT_SCHEMA_V1: &str = "nightshift.authoring_context_custody_export.v1";

const SESSION_AUTH_DOMAIN: &[u8] = b"maude-supervised-session-custody/v1\0";
const HANDOFF_AUTH_DOMAIN: &[u8] = b"nightshift-authoring-context-handoff/v1\0";
const MAX_CREDENTIAL_BYTES: usize = 32;

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

fn require_hmac(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("hmac-sha256:") else {
        return Err(format!("{name} must use hmac-sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must use hmac-sha256:<64 lowercase hex>"));
    }
    Ok(())
}

fn sha256_id(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn semantic_id<T: Serialize>(value: &T, id_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "custody identity preimage is not an object".to_owned())?;
    object.remove(id_field);
    object.remove("authentication");
    let bytes = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(sha256_id(&bytes))
}

fn authentication_preimage<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "custody authentication preimage is not an object".to_owned())?
        .remove("authentication");
    serde_jcs::to_vec(&value).map_err(|error| error.to_string())
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
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn hmac_text(key: &[u8], domain: &[u8], payload: &[u8]) -> String {
    let bytes = hmac_sha256(key, domain, payload);
    let mut text = String::with_capacity("hmac-sha256:".len() + 64);
    text.push_str("hmac-sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HmacAuthenticationV1 {
    pub schema: String,
    pub key_id: String,
    pub tag: String,
}

impl HmacAuthenticationV1 {
    fn validate(&self, expected_key_id: &str) -> Result<(), String> {
        if self.schema != HMAC_AUTH_SCHEMA_V1 {
            return Err("unsupported Maude custody authentication schema".into());
        }
        require_token("custody authentication key_id", &self.key_id)?;
        if self.key_id != expected_key_id {
            return Err("custody authentication key identity mismatch".into());
        }
        require_hmac("custody authentication tag", &self.tag)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaudeSessionCustodyV1 {
    pub schema: String,
    pub session_record_id: String,
    pub session_issuer_principal_id: String,
    pub session_issuer_key_id: String,
    pub maude_session_id: String,
    pub maude_plan_ref: String,
    pub source_plan_bytes: u64,
    pub recorded_at: DateTime<Utc>,
    pub authentication: HmacAuthenticationV1,
}

impl MaudeSessionCustodyV1 {
    pub fn validate_untrusted(&self) -> Result<(), String> {
        if self.schema != SESSION_CUSTODY_SCHEMA_V1 {
            return Err("unsupported Maude supervised-session custody schema".into());
        }
        require_digest("session_record_id", &self.session_record_id)?;
        require_token(
            "session_issuer_principal_id",
            &self.session_issuer_principal_id,
        )?;
        require_token("session_issuer_key_id", &self.session_issuer_key_id)?;
        require_token("maude_session_id", &self.maude_session_id)?;
        require_digest("maude_plan_ref", &self.maude_plan_ref)?;
        if self.source_plan_bytes == 0 || self.source_plan_bytes > 1024 * 1024 {
            return Err("session custody source plan length is invalid".into());
        }
        self.authentication.validate(&self.session_issuer_key_id)?;
        if semantic_id(self, "session_record_id")? != self.session_record_id {
            return Err("session_record_id does not bind the exact session custody facts".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaudeAuthoringContextHandoffV1 {
    pub schema: String,
    pub handoff_id: String,
    pub producer_principal_id: String,
    pub producer_key_id: String,
    pub target_runtime_id: String,
    /// The sealed base cycle request before this handoff is attached.
    pub target_request_id: String,
    pub session_custody: MaudeSessionCustodyV1,
    pub authoring_context: MaudeAuthoringContextInputV1,
    pub created_at: DateTime<Utc>,
    pub authentication: HmacAuthenticationV1,
}

impl MaudeAuthoringContextHandoffV1 {
    pub fn validate_untrusted(&self) -> Result<(), String> {
        if self.schema != HANDOFF_SCHEMA_V1 {
            return Err("unsupported Maude authoring-context handoff schema".into());
        }
        require_digest("handoff_id", &self.handoff_id)?;
        require_token("producer_principal_id", &self.producer_principal_id)?;
        require_token("producer_key_id", &self.producer_key_id)?;
        require_token("target_runtime_id", &self.target_runtime_id)?;
        require_digest("target_request_id", &self.target_request_id)?;
        self.session_custody.validate_untrusted()?;
        self.authoring_context.validate()?;
        self.authentication.validate(&self.producer_key_id)?;
        if self.session_custody.session_issuer_key_id == self.producer_key_id {
            return Err(
                "session issuer and handoff producer must use distinct key identities".into(),
            );
        }
        if self.session_custody.maude_session_id != self.authoring_context.session_id
            || self.session_custody.maude_plan_ref != self.authoring_context.plan_ref
            || self.session_custody.source_plan_bytes
                != u64::try_from(self.authoring_context.plan_text.len())
                    .map_err(|_| "Maude plan length does not fit u64".to_owned())?
        {
            return Err("handoff does not bind its exact supervised session and plan".into());
        }
        if semantic_id(self, "handoff_id")? != self.handoff_id {
            return Err("handoff_id does not bind the exact handoff facts".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedMaudeHandoffV1 {
    handoff: MaudeAuthoringContextHandoffV1,
}

impl VerifiedMaudeHandoffV1 {
    pub(crate) fn handoff(&self) -> &MaudeAuthoringContextHandoffV1 {
        &self.handoff
    }
}

#[derive(Debug)]
pub struct MaudeCustodyVerifierV1 {
    expected_principal_id: String,
    expected_key_id: String,
    expected_session_issuer_principal_id: String,
    expected_session_issuer_key_id: String,
    expected_runtime_id: String,
    producer_key: [u8; MAX_CREDENTIAL_BYTES],
    session_issuer_key: [u8; MAX_CREDENTIAL_BYTES],
}

impl MaudeCustodyVerifierV1 {
    pub fn from_key_file(
        expected_principal_id: String,
        expected_key_id: String,
        expected_session_issuer_principal_id: String,
        expected_session_issuer_key_id: String,
        expected_runtime_id: String,
        producer_key_path: &Path,
        session_issuer_key_path: &Path,
    ) -> Result<Self, String> {
        require_token("expected producer principal", &expected_principal_id)?;
        require_token("expected producer key", &expected_key_id)?;
        require_token(
            "expected Maude session issuer principal",
            &expected_session_issuer_principal_id,
        )?;
        require_token(
            "expected Maude session issuer key",
            &expected_session_issuer_key_id,
        )?;
        require_token("expected Nightshift runtime", &expected_runtime_id)?;
        let producer_key = read_protected_key_path(producer_key_path)?;
        let session_issuer_key = read_protected_key_path(session_issuer_key_path)?;
        if expected_key_id == expected_session_issuer_key_id || producer_key == session_issuer_key {
            return Err(
                "Maude handoff producer and session issuer credentials must be distinct".into(),
            );
        }
        Ok(Self {
            expected_principal_id,
            expected_key_id,
            expected_session_issuer_principal_id,
            expected_session_issuer_key_id,
            expected_runtime_id,
            producer_key,
            session_issuer_key,
        })
    }

    pub fn verify(
        &self,
        handoff: &MaudeAuthoringContextHandoffV1,
        expected_target_request_id: &str,
    ) -> Result<VerifiedMaudeHandoffV1, String> {
        handoff.validate_untrusted()?;
        if handoff.producer_principal_id != self.expected_principal_id
            || handoff.producer_key_id != self.expected_key_id
        {
            return Err(
                "Maude handoff producer identity is not configured for this ingress".into(),
            );
        }
        if handoff.session_custody.session_issuer_principal_id
            != self.expected_session_issuer_principal_id
            || handoff.session_custody.session_issuer_key_id != self.expected_session_issuer_key_id
        {
            return Err(
                "Maude supervised-session issuer is not configured for this ingress".into(),
            );
        }
        if handoff.target_runtime_id != self.expected_runtime_id {
            return Err("Maude handoff targets a different Nightshift runtime".into());
        }
        if handoff.target_request_id != expected_target_request_id {
            return Err("Maude handoff targets a different canonical cycle request".into());
        }
        verify_authentication(
            &self.session_issuer_key,
            SESSION_AUTH_DOMAIN,
            &handoff.session_custody,
            &handoff.session_custody.authentication,
        )?;
        verify_authentication(
            &self.producer_key,
            HANDOFF_AUTH_DOMAIN,
            handoff,
            &handoff.authentication,
        )?;
        Ok(VerifiedMaudeHandoffV1 {
            handoff: handoff.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        expected_principal_id: &str,
        expected_key_id: &str,
        expected_session_issuer_principal_id: &str,
        expected_session_issuer_key_id: &str,
        expected_runtime_id: &str,
        producer_key: [u8; 32],
        session_issuer_key: [u8; 32],
    ) -> Self {
        Self {
            expected_principal_id: expected_principal_id.into(),
            expected_key_id: expected_key_id.into(),
            expected_session_issuer_principal_id: expected_session_issuer_principal_id.into(),
            expected_session_issuer_key_id: expected_session_issuer_key_id.into(),
            expected_runtime_id: expected_runtime_id.into(),
            producer_key,
            session_issuer_key,
        }
    }
}

fn read_protected_key_path(path: &Path) -> Result<[u8; MAX_CREDENTIAL_BYTES], String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("open Maude custody credential {}: {error}", path.display()))?;
    read_protected_key(file)
}

fn read_protected_key(file: File) -> Result<[u8; MAX_CREDENTIAL_BYTES], String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect Maude custody credential: {error}"))?;
    if !metadata.is_file() {
        return Err("Maude custody credential is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "Maude custody credential must not be accessible by group or others".into(),
            );
        }
    }
    let mut bytes = Vec::with_capacity(MAX_CREDENTIAL_BYTES + 1);
    file.take((MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read Maude custody credential: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "Maude custody credential must contain exactly 32 raw bytes".into())
}

fn verify_authentication<T: Serialize>(
    key: &[u8],
    domain: &[u8],
    value: &T,
    authentication: &HmacAuthenticationV1,
) -> Result<(), String> {
    let preimage = authentication_preimage(value)?;
    let expected = hmac_text(key, domain, &preimage);
    if !constant_time_eq(expected.as_bytes(), authentication.tag.as_bytes()) {
        return Err("Maude custody authentication failed".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringContextCustodyProvenanceV1 {
    pub schema: String,
    pub custody_id: String,
    pub handoff_id: String,
    pub session_record_id: String,
    pub authoring_context_provenance_id: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub proposal_id: String,
    pub exact_work_id: String,
    pub producer_principal_id: String,
    pub producer_key_id: String,
    pub session_issuer_principal_id: String,
    pub session_issuer_key_id: String,
    pub target_runtime_id: String,
    pub target_request_id: String,
    pub maude_session_id: String,
    pub maude_plan_ref: String,
    pub authentication_method: String,
    /// Caller-sealed cycle evaluation-time evidence. This is not a claim about
    /// the receiver's physical wall clock.
    pub recorded_at: DateTime<Utc>,
}

impl AuthoringContextCustodyProvenanceV1 {
    pub(crate) fn mint(
        verified: &VerifiedMaudeHandoffV1,
        authoring: &AuthoringContextProvenanceV1,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, String> {
        let handoff = verified.handoff();
        let mut record = Self {
            schema: CUSTODY_PROVENANCE_SCHEMA_V1.into(),
            custody_id: String::new(),
            handoff_id: handoff.handoff_id.clone(),
            session_record_id: handoff.session_custody.session_record_id.clone(),
            authoring_context_provenance_id: authoring.provenance_id.clone(),
            campaign_id: authoring.campaign_id.clone(),
            occurrence_id: authoring.occurrence_id.clone(),
            proposal_id: authoring.proposal_id.clone(),
            exact_work_id: authoring.exact_work_id.clone(),
            producer_principal_id: handoff.producer_principal_id.clone(),
            producer_key_id: handoff.producer_key_id.clone(),
            session_issuer_principal_id: handoff
                .session_custody
                .session_issuer_principal_id
                .clone(),
            session_issuer_key_id: handoff.session_custody.session_issuer_key_id.clone(),
            target_runtime_id: handoff.target_runtime_id.clone(),
            target_request_id: handoff.target_request_id.clone(),
            maude_session_id: handoff.authoring_context.session_id.clone(),
            maude_plan_ref: handoff.authoring_context.plan_ref.clone(),
            authentication_method: HMAC_AUTH_SCHEMA_V1.into(),
            recorded_at,
        };
        record.custody_id = semantic_id(&record, "custody_id")?;
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CUSTODY_PROVENANCE_SCHEMA_V1 {
            return Err("unsupported authoring-context custody provenance schema".into());
        }
        for (name, value) in [
            ("custody_id", &self.custody_id),
            ("handoff_id", &self.handoff_id),
            ("session_record_id", &self.session_record_id),
            (
                "authoring_context_provenance_id",
                &self.authoring_context_provenance_id,
            ),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("exact_work_id", &self.exact_work_id),
            ("target_request_id", &self.target_request_id),
            ("maude_plan_ref", &self.maude_plan_ref),
        ] {
            require_digest(name, value)?;
        }
        uuid::Uuid::parse_str(&self.occurrence_id)
            .map_err(|_| "custody occurrence_id must be a UUID".to_owned())?;
        for (name, value) in [
            ("producer_principal_id", &self.producer_principal_id),
            ("producer_key_id", &self.producer_key_id),
            (
                "session_issuer_principal_id",
                &self.session_issuer_principal_id,
            ),
            ("session_issuer_key_id", &self.session_issuer_key_id),
            ("target_runtime_id", &self.target_runtime_id),
            ("maude_session_id", &self.maude_session_id),
        ] {
            require_token(name, value)?;
        }
        if self.authentication_method != HMAC_AUTH_SCHEMA_V1 {
            return Err("unsupported custody authentication method".into());
        }
        if semantic_id(self, "custody_id")? != self.custody_id {
            return Err("custody_id does not bind the exact custody provenance".into());
        }
        Ok(())
    }

    pub fn validate_for_authoring(
        &self,
        authoring: &AuthoringContextProvenanceV1,
    ) -> Result<(), String> {
        self.validate()?;
        if self.authoring_context_provenance_id != authoring.provenance_id
            || self.campaign_id != authoring.campaign_id
            || self.occurrence_id != authoring.occurrence_id
            || self.proposal_id != authoring.proposal_id
            || self.exact_work_id != authoring.exact_work_id
            || self.maude_session_id != authoring.maude_session_id
            || self.maude_plan_ref != authoring.maude_plan_ref
        {
            return Err("custody provenance does not bind the exact authoring lineage".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringContextCustodyExportV1 {
    pub schema: String,
    pub query: AuthoringContextQueryV1,
    pub matches: Vec<AuthoringContextCustodyProvenanceV1>,
}

impl AuthoringContextCustodyExportV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CUSTODY_EXPORT_SCHEMA_V1 {
            return Err("unsupported authoring-context custody export schema".into());
        }
        self.query.validate()?;
        for record in &self.matches {
            record.validate()?;
            let bound = match &self.query {
                AuthoringContextQueryV1::GovernedOccurrence {
                    campaign_id,
                    occurrence_id,
                } => record.campaign_id == *campaign_id && record.occurrence_id == *occurrence_id,
                AuthoringContextQueryV1::Proposal { proposal_id } => {
                    record.proposal_id == *proposal_id
                }
                AuthoringContextQueryV1::MaudeContext {
                    plan_ref,
                    session_id,
                } => record.maude_plan_ref == *plan_ref && record.maude_session_id == *session_id,
            };
            if !bound {
                return Err("authoring custody export contains a substituted match".into());
            }
        }
        Ok(())
    }
}

// Crate-confined signers exist only for deterministic Nightshift tests. The
// production signer lives at the Maude session boundary; no public Nightshift
// API can mint producer custody evidence.
#[cfg(test)]
pub(crate) fn sign_session_for_test(
    key: &[u8; 32],
    issuer_principal: &str,
    issuer_key_id: &str,
    session: &str,
    plan_ref: &str,
    source_plan_bytes: u64,
    recorded_at: DateTime<Utc>,
) -> MaudeSessionCustodyV1 {
    let mut value = MaudeSessionCustodyV1 {
        schema: SESSION_CUSTODY_SCHEMA_V1.into(),
        session_record_id: String::new(),
        session_issuer_principal_id: issuer_principal.into(),
        session_issuer_key_id: issuer_key_id.into(),
        maude_session_id: session.into(),
        maude_plan_ref: plan_ref.into(),
        source_plan_bytes,
        recorded_at,
        authentication: HmacAuthenticationV1 {
            schema: HMAC_AUTH_SCHEMA_V1.into(),
            key_id: issuer_key_id.into(),
            tag: String::new(),
        },
    };
    value.session_record_id = semantic_id(&value, "session_record_id").unwrap();
    value.authentication.tag = hmac_text(
        key,
        SESSION_AUTH_DOMAIN,
        &authentication_preimage(&value).unwrap(),
    );
    value
}

#[cfg(test)]
pub(crate) struct TestHandoffInput<'a> {
    pub(crate) principal: &'a str,
    pub(crate) key_id: &'a str,
    pub(crate) runtime_id: &'a str,
    pub(crate) target_request_id: &'a str,
    pub(crate) session_custody: MaudeSessionCustodyV1,
    pub(crate) authoring_context: MaudeAuthoringContextInputV1,
    pub(crate) created_at: DateTime<Utc>,
}

#[cfg(test)]
pub(crate) fn sign_handoff_for_test(
    key: &[u8; 32],
    input: TestHandoffInput<'_>,
) -> MaudeAuthoringContextHandoffV1 {
    let mut value = MaudeAuthoringContextHandoffV1 {
        schema: HANDOFF_SCHEMA_V1.into(),
        handoff_id: String::new(),
        producer_principal_id: input.principal.into(),
        producer_key_id: input.key_id.into(),
        target_runtime_id: input.runtime_id.into(),
        target_request_id: input.target_request_id.into(),
        session_custody: input.session_custody,
        authoring_context: input.authoring_context,
        created_at: input.created_at,
        authentication: HmacAuthenticationV1 {
            schema: HMAC_AUTH_SCHEMA_V1.into(),
            key_id: input.key_id.into(),
            tag: String::new(),
        },
    };
    value.handoff_id = semantic_id(&value, "handoff_id").unwrap();
    value.authentication.tag = hmac_text(
        key,
        HANDOFF_AUTH_DOMAIN,
        &authentication_preimage(&value).unwrap(),
    );
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (MaudeAuthoringContextHandoffV1, MaudeCustodyVerifierV1) {
        let producer_key = [7_u8; 32];
        let session_issuer_key = [3_u8; 32];
        let plan = "line one\r\nline two\r\n";
        let plan_ref = sha256_id(plan.as_bytes());
        let time = DateTime::parse_from_rfc3339("2026-08-21T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let session = sign_session_for_test(
            &session_issuer_key,
            "maude:supervisor",
            "maude-session-key:primary",
            "sess_0123456789ab",
            &plan_ref,
            plan.len() as u64,
            time,
        );
        let handoff = sign_handoff_for_test(
            &producer_key,
            TestHandoffInput {
                principal: "maude-handoff:local",
                key_id: "maude-handoff-key:primary",
                runtime_id: "nightshift:local-c1",
                target_request_id: &sha256_id(b"request"),
                session_custody: session,
                authoring_context: MaudeAuthoringContextInputV1 {
                    schema: crate::authoring_context::AUTHORING_CONTEXT_INPUT_SCHEMA_V1.into(),
                    plan_ref,
                    session_id: "sess_0123456789ab".into(),
                    plan_text: plan.into(),
                },
                created_at: time,
            },
        );
        let verifier = MaudeCustodyVerifierV1 {
            expected_principal_id: "maude-handoff:local".into(),
            expected_key_id: "maude-handoff-key:primary".into(),
            expected_session_issuer_principal_id: "maude:supervisor".into(),
            expected_session_issuer_key_id: "maude-session-key:primary".into(),
            expected_runtime_id: "nightshift:local-c1".into(),
            producer_key,
            session_issuer_key,
        };
        (handoff, verifier)
    }

    #[test]
    fn exact_authenticated_handoff_preserves_crlf_bytes() {
        let (handoff, verifier) = fixture();
        verifier
            .verify(&handoff, &handoff.target_request_id)
            .unwrap();
        assert!(handoff
            .authoring_context
            .plan_text
            .as_bytes()
            .windows(2)
            .any(|window| window == b"\r\n"));
    }

    #[test]
    fn wrong_principal_key_runtime_and_target_refuse() {
        let (handoff, mut verifier) = fixture();
        verifier.expected_principal_id = "maude:other".into();
        assert!(verifier
            .verify(&handoff, &handoff.target_request_id)
            .is_err());
        verifier.expected_principal_id = handoff.producer_principal_id.clone();
        verifier.expected_key_id = "maude-key:other".into();
        assert!(verifier
            .verify(&handoff, &handoff.target_request_id)
            .is_err());
        verifier.expected_key_id = handoff.producer_key_id.clone();
        verifier.expected_session_issuer_principal_id = "maude:other-supervisor".into();
        assert!(verifier
            .verify(&handoff, &handoff.target_request_id)
            .is_err());
        verifier.expected_session_issuer_principal_id =
            handoff.session_custody.session_issuer_principal_id.clone();
        verifier.expected_runtime_id = "nightshift:other".into();
        assert!(verifier
            .verify(&handoff, &handoff.target_request_id)
            .is_err());
        verifier.expected_runtime_id = handoff.target_runtime_id.clone();
        assert!(verifier.verify(&handoff, &sha256_id(b"other")).is_err());
    }

    #[test]
    fn recomputed_ids_cannot_hide_authenticated_substitution() {
        let (mut handoff, verifier) = fixture();
        handoff.authoring_context.plan_text = "substituted\r\n".into();
        handoff.authoring_context.plan_ref =
            sha256_id(handoff.authoring_context.plan_text.as_bytes());
        handoff.session_custody.maude_plan_ref = handoff.authoring_context.plan_ref.clone();
        handoff.session_custody.source_plan_bytes =
            handoff.authoring_context.plan_text.len() as u64;
        handoff.session_custody.session_record_id =
            semantic_id(&handoff.session_custody, "session_record_id").unwrap();
        handoff.handoff_id = semantic_id(&handoff, "handoff_id").unwrap();
        assert!(verifier
            .verify(&handoff, &handoff.target_request_id)
            .is_err());
    }

    #[test]
    fn wrong_credential_fails_authentication() {
        let (handoff, mut verifier) = fixture();
        verifier.producer_key = [9_u8; 32];
        assert!(verifier
            .verify(&handoff, &handoff.target_request_id)
            .is_err());
        let (handoff, mut verifier) = fixture();
        verifier.session_issuer_key = [9_u8; 32];
        assert!(verifier
            .verify(&handoff, &handoff.target_request_id)
            .is_err());
    }

    #[test]
    fn deployment_refuses_one_credential_for_both_custody_roles() {
        let directory = tempfile::tempdir().unwrap();
        let producer = directory.path().join("producer.key");
        let session = directory.path().join("session.key");
        std::fs::write(&producer, [5_u8; 32]).unwrap();
        std::fs::write(&session, [5_u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&producer, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(MaudeCustodyVerifierV1::from_key_file(
            "maude-handoff:local".into(),
            "maude-handoff-key:primary".into(),
            "maude:supervisor".into(),
            "maude-session-key:primary".into(),
            "nightshift:local-c1".into(),
            &producer,
            &session,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn deployment_refuses_group_readable_credentials() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let producer = directory.path().join("producer.key");
        let session = directory.path().join("session.key");
        std::fs::write(&producer, [5_u8; 32]).unwrap();
        std::fs::write(&session, [7_u8; 32]).unwrap();
        std::fs::set_permissions(&producer, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(MaudeCustodyVerifierV1::from_key_file(
            "maude-handoff:local".into(),
            "maude-handoff-key:primary".into(),
            "maude:supervisor".into(),
            "maude-session-key:primary".into(),
            "nightshift:local-c1".into(),
            &producer,
            &session,
        )
        .is_err());
    }

    #[test]
    fn maude_python_wire_vector_verifies_byte_exactly() {
        let wire = r#"{"authentication":{"key_id":"maude-handoff-key:primary","schema":"maude.hmac_sha256.v1","tag":"hmac-sha256:5a37c617f13a81b5e569a72e5c599bfc884664de39ae34b0b3cd42bc1ed90357"},"authoring_context":{"plan_ref":"sha256:6612d9c94c2da8d2544e1188348fc7baf717ffff1bacde51929a166404a41ffc","plan_text":"line one\r\nline two\r\n","schema":"nightshift.maude_authoring_context_input.v1","session_id":"sess_0123456789ab"},"created_at":"2026-08-21T12:00:00Z","handoff_id":"sha256:387b71673128eeee403d27142232f878b4f451a41b2beb1f59261140d2bbb221","producer_key_id":"maude-handoff-key:primary","producer_principal_id":"maude-handoff:local","schema":"nightshift.maude_authoring_context_handoff.v1","session_custody":{"authentication":{"key_id":"maude-session-key:primary","schema":"maude.hmac_sha256.v1","tag":"hmac-sha256:2c14c5b929956ec1eb217cf72691bbae304eccd49d7f4b8c8647488dd2fd1032"},"maude_plan_ref":"sha256:6612d9c94c2da8d2544e1188348fc7baf717ffff1bacde51929a166404a41ffc","maude_session_id":"sess_0123456789ab","recorded_at":"2026-08-21T12:00:00Z","schema":"maude.supervised_session_custody.v1","session_issuer_key_id":"maude-session-key:primary","session_issuer_principal_id":"maude:supervisor","session_record_id":"sha256:a154c2de74b92e7a637eefeb1f0914dcd45150cdcd1668bdfb705189fa865864","source_plan_bytes":20},"target_request_id":"sha256:1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047","target_runtime_id":"nightshift:local-c1"}"#;
        let handoff: MaudeAuthoringContextHandoffV1 = serde_json::from_str(wire).unwrap();
        let verifier = MaudeCustodyVerifierV1::for_test(
            "maude-handoff:local",
            "maude-handoff-key:primary",
            "maude:supervisor",
            "maude-session-key:primary",
            "nightshift:local-c1",
            [7_u8; 32],
            [3_u8; 32],
        );
        verifier
            .verify(&handoff, &handoff.target_request_id)
            .unwrap();
        assert_eq!(handoff.authoring_context.plan_text.len(), 20);
    }
}
