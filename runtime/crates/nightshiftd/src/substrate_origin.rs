//! Verification-only substrate-origin contract for NQ V3 acquisitions.
//!
//! This module verifies an independently signed, profile-bounded coordinate
//! that NQ committed before provider invocation. The software-key profile
//! proves key possession only. The Linode metadata profile proves only its
//! logical provider-instance proposition under separately qualified helper
//! locality and routing assumptions. Neither claims bare-metal or installation
//! identity.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::Path;

use chrono::DateTime;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::continuity_authority::{
    ContinuityAcquisitionBasisV1, ContinuityAcquisitionCarrierV1, ContinuityAuthorityVerifierV1,
    ContinuityRelationV1,
};

pub const COORDINATE_SCHEMA_V1: &str = "nq.substrate_coordinate.v1";
pub const ORIGIN_BASIS_SCHEMA_V1: &str = "nq.substrate_origin_acquisition_basis.v1";
pub const ATTESTATION_SCHEMA_V1: &str = "nq.substrate_origin_attestation.v1";
pub const SIGNED_ATTESTATION_SCHEMA_V1: &str = "nq.signed_substrate_origin_attestation.v1";
pub const ORIGIN_INTENT_SCHEMA_V1: &str = "nq.substrate_origin_acquisition_intent.v1";
pub const REQUIREMENT_SCHEMA_V1: &str = "nightshift.substrate_origin_requirement.v1";
pub const APPLICABILITY_SCHEMA_V1: &str = "nightshift.substrate_origin_applicability.v1";

const MAX_PUBLIC_KEY_BYTES: u64 = 512;
const ATTESTATION_NONCLAIMS: [&str; 5] = [
    "origin attestation proves possession of the pinned attester key for this exact acquisition basis",
    "origin attestation does not establish bare-metal physical identity",
    "origin attestation does not establish subject continuity or predecessor history",
    "origin attestation does not establish evidence truth, currentness, standing, or authority",
    "attester key custody and runtime co-location remain deployment qualifications",
];
pub const LINODE_INSTANCE_METADATA_PROFILE_V1: &str = "linode_instance_metadata_v1";
pub const LINODE_METADATA_NAMESPACE_V1: &str = "akamai_linode";
pub const LINODE_METADATA_INSTANCE_ENDPOINT_V1: &str = "http://169.254.169.254/v1/instance";
pub const LINODE_METADATA_EVIDENCE_SCHEMA_V1: &str = "nq.linode_instance_metadata_evidence.v1";
const LINODE_METADATA_NONCLAIMS: [&str; 6] = [
    "origin attestation proves the pinned helper reported an exact response under the closed Linode metadata profile for this acquisition basis",
    "Linode metadata is instance-local but is not a provider-signed portable identity document",
    "the qualified coordinate identifies one logical Linode instance, not physical host placement",
    "host UUID is supplemental evidence and is not part of the qualified coordinate",
    "origin attestation does not establish installation identity, evidence truth, currentness, standing, or authority",
    "helper isolation, metadata routing, and runtime co-location remain deployment qualifications",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateCoordinateKindV1 {
    AttesterKey,
    LinodeInstance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateOriginEvidenceMethodV1 {
    Ed25519AcquisitionChallenge,
    LinodeInstanceMetadataV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateCoordinateV1 {
    pub schema: String,
    pub kind: SubstrateCoordinateKindV1,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attester_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attester_public_key_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linode_instance_id_sha256: Option<String>,
    pub evidence_method: SubstrateOriginEvidenceMethodV1,
    pub coordinate_ref: String,
}

impl SubstrateCoordinateV1 {
    fn for_key(namespace: &str, key_id: &str, key: &VerifyingKey) -> Result<Self, String> {
        require_token("coordinate namespace", namespace)?;
        require_token("attester key id", key_id)?;
        let mut value = Self {
            schema: COORDINATE_SCHEMA_V1.into(),
            kind: SubstrateCoordinateKindV1::AttesterKey,
            namespace: namespace.into(),
            attester_key_id: Some(key_id.into()),
            attester_public_key_sha256: Some(format!(
                "sha256:{:x}",
                Sha256::digest(key.as_bytes())
            )),
            linode_instance_id_sha256: None,
            evidence_method: SubstrateOriginEvidenceMethodV1::Ed25519AcquisitionChallenge,
            coordinate_ref: String::new(),
        };
        value.coordinate_ref = value.computed_ref()?;
        value.validate()?;
        Ok(value)
    }

    fn for_linode_instance_digest(instance_id_sha256: &str) -> Result<Self, String> {
        require_digest("Linode instance id digest", instance_id_sha256)?;
        let mut value = Self {
            schema: COORDINATE_SCHEMA_V1.into(),
            kind: SubstrateCoordinateKindV1::LinodeInstance,
            namespace: LINODE_METADATA_NAMESPACE_V1.into(),
            attester_key_id: None,
            attester_public_key_sha256: None,
            linode_instance_id_sha256: Some(instance_id_sha256.into()),
            evidence_method: SubstrateOriginEvidenceMethodV1::LinodeInstanceMetadataV1,
            coordinate_ref: String::new(),
        };
        value.coordinate_ref = value.computed_ref()?;
        value.validate()?;
        Ok(value)
    }

    fn computed_ref(&self) -> Result<String, String> {
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .ok_or_else(|| "substrate coordinate is not an object".to_owned())?
            .remove("coordinate_ref");
        let prefix = match self.kind {
            SubstrateCoordinateKindV1::AttesterKey => "substrate:attester-key:v1",
            SubstrateCoordinateKindV1::LinodeInstance => "substrate:linode-instance:v1",
        };
        Ok(format!("{prefix}:{:x}", Sha256::digest(jcs(&value)?)))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != COORDINATE_SCHEMA_V1 {
            return Err("unsupported substrate coordinate schema".into());
        }
        require_token("coordinate namespace", &self.namespace)?;
        match self.kind {
            SubstrateCoordinateKindV1::AttesterKey => {
                if self.evidence_method
                    != SubstrateOriginEvidenceMethodV1::Ed25519AcquisitionChallenge
                    || self.linode_instance_id_sha256.is_some()
                {
                    return Err("substrate coordinate profile mismatch".into());
                }
                require_token(
                    "attester key id",
                    self.attester_key_id
                        .as_deref()
                        .ok_or_else(|| "attester coordinate fields are absent".to_owned())?,
                )?;
                require_digest(
                    "attester public key digest",
                    self.attester_public_key_sha256
                        .as_deref()
                        .ok_or_else(|| "attester coordinate fields are absent".to_owned())?,
                )?;
            }
            SubstrateCoordinateKindV1::LinodeInstance => {
                if self.namespace != LINODE_METADATA_NAMESPACE_V1
                    || self.evidence_method
                        != SubstrateOriginEvidenceMethodV1::LinodeInstanceMetadataV1
                    || self.attester_key_id.is_some()
                    || self.attester_public_key_sha256.is_some()
                {
                    return Err("substrate coordinate profile mismatch".into());
                }
                require_digest(
                    "Linode instance id digest",
                    self.linode_instance_id_sha256
                        .as_deref()
                        .ok_or_else(|| "Linode instance coordinate is absent".to_owned())?,
                )?;
            }
        }
        if self.coordinate_ref != self.computed_ref()? {
            return Err("substrate coordinate identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinodeInstanceMetadataEvidenceV1 {
    pub schema: String,
    pub profile_id: String,
    pub endpoint: String,
    pub instance_id_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_uuid_sha256: Option<String>,
    pub canonical_response_sha256: String,
}

impl LinodeInstanceMetadataEvidenceV1 {
    fn validate(&self) -> Result<(), String> {
        if self.schema != LINODE_METADATA_EVIDENCE_SCHEMA_V1
            || self.profile_id != LINODE_INSTANCE_METADATA_PROFILE_V1
            || self.endpoint != LINODE_METADATA_INSTANCE_ENDPOINT_V1
        {
            return Err("unsupported Linode metadata profile evidence".into());
        }
        require_digest("Linode instance id digest", &self.instance_id_sha256)?;
        if let Some(value) = &self.host_uuid_sha256 {
            require_digest("Linode host UUID digest", value)?;
        }
        require_digest(
            "Linode canonical metadata response digest",
            &self.canonical_response_sha256,
        )
    }

    fn coordinate(&self) -> Result<SubstrateCoordinateV1, String> {
        self.validate()?;
        SubstrateCoordinateV1::for_linode_instance_digest(&self.instance_id_sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginAcquisitionBasisV1 {
    pub schema: String,
    pub acquisition_id: String,
    pub watcher_instance_id: String,
    pub watcher_config_digest: String,
    pub subject_ref: String,
    pub expected_coordinate: SubstrateCoordinateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity: Option<ContinuityAcquisitionBasisV1>,
}

impl SubstrateOriginAcquisitionBasisV1 {
    fn digest(&self) -> Result<String, String> {
        self.validate()?;
        Ok(format!("{:x}", Sha256::digest(jcs(self)?)))
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != ORIGIN_BASIS_SCHEMA_V1 {
            return Err("unsupported substrate-origin basis schema".into());
        }
        require_token("origin acquisition id", &self.acquisition_id)?;
        require_token("origin watcher instance", &self.watcher_instance_id)?;
        require_token("origin subject", &self.subject_ref)?;
        require_hex_digest("origin watcher config digest", &self.watcher_config_digest)?;
        self.expected_coordinate.validate()?;
        if let Some(continuity) = &self.continuity {
            if continuity.acquisition_id != self.acquisition_id
                || continuity.watcher_instance_id != self.watcher_instance_id
                || continuity.watcher_config_digest != self.watcher_config_digest
                || continuity.edge.subject_ref != self.subject_ref
                || continuity.edge.successor_ref != self.expected_coordinate.coordinate_ref
            {
                return Err("continuity basis substitutes substrate-origin basis".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginAttestationV1 {
    pub schema: String,
    pub attestation_occurrence_ref: String,
    pub issuer_id: String,
    pub key_id: String,
    pub acquisition_id: String,
    pub acquisition_basis_digest: String,
    pub coordinate: SubstrateCoordinateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linode_metadata: Option<LinodeInstanceMetadataEvidenceV1>,
    pub attested_at: String,
    pub replay_identity: String,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSubstrateOriginAttestationV1 {
    pub schema: String,
    pub payload: SubstrateOriginAttestationV1,
    pub payload_digest: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginAcquisitionIntentV1 {
    pub schema: String,
    pub intent_id: String,
    pub basis: SubstrateOriginAcquisitionBasisV1,
    pub basis_digest: String,
    pub attestation: SignedSubstrateOriginAttestationV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity_carrier: Option<ContinuityAcquisitionCarrierV1>,
    pub intake_id: String,
    pub attempt_id: String,
    pub run_id: String,
    pub request: serde_json::Value,
    pub provider: serde_json::Value,
    pub origin_carrier: String,
    pub checkpoint_contract_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateOriginAcquisitionPhaseV1 {
    ProviderInvocationStarted,
    ProviderIntakeCompleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginAcquisitionProofV1 {
    pub intent: SubstrateOriginAcquisitionIntentV1,
    pub intent_digest: String,
    pub phases: Vec<SubstrateOriginAcquisitionPhaseV1>,
}

impl SubstrateOriginAcquisitionProofV1 {
    pub(crate) fn validate_shape(&self) -> Result<(), String> {
        let intent = &self.intent;
        if intent.schema != ORIGIN_INTENT_SCHEMA_V1
            || intent.basis.schema != ORIGIN_BASIS_SCHEMA_V1
            || self.phases
                != [
                    SubstrateOriginAcquisitionPhaseV1::ProviderInvocationStarted,
                    SubstrateOriginAcquisitionPhaseV1::ProviderIntakeCompleted,
                ]
        {
            return Err("unsupported or incomplete NQ substrate-origin acquisition".into());
        }
        intent.basis.validate()?;
        for (name, value) in [
            ("origin intent id", intent.intent_id.as_str()),
            ("origin intake id", intent.intake_id.as_str()),
            ("origin attempt id", intent.attempt_id.as_str()),
            ("origin run id", intent.run_id.as_str()),
            ("origin carrier", intent.origin_carrier.as_str()),
        ] {
            require_token(name, value)?;
        }
        require_digest("origin intent id", &intent.intent_id)?;
        require_digest("origin intent digest", &self.intent_digest)?;
        require_hex_digest("origin basis digest", &intent.basis_digest)?;
        require_digest(
            "origin checkpoint contract digest",
            &intent.checkpoint_contract_digest,
        )?;
        if intent.basis_digest != intent.basis.digest()?
            || intent.intake_id != intent.basis.acquisition_id
            || intent.attestation.payload.acquisition_id != intent.intake_id
            || intent.attestation.payload.acquisition_basis_digest != intent.basis_digest
            || intent
                .request
                .pointer("/instance_id")
                .and_then(serde_json::Value::as_str)
                != Some(&intent.basis.watcher_instance_id)
            || intent
                .request
                .pointer("/binding/subject")
                .and_then(serde_json::Value::as_str)
                != Some(&intent.basis.subject_ref)
            || !intent.provider.is_object()
        {
            return Err("NQ origin intent substitutes its exact acquisition basis".into());
        }
        match (&intent.basis.continuity, &intent.continuity_carrier) {
            (None, None) => {}
            (Some(basis), Some(carrier))
                if carrier
                    .authority
                    .payload
                    .authority_occurrence_ref
                    .to_string()
                    == basis.authority_occurrence_ref
                    && carrier.authority.payload_digest == basis.authority_digest
                    && carrier.commitment.payload.acquisition_id == intent.intake_id => {}
            _ => return Err("NQ origin intent continuity carrier mismatch".into()),
        }
        let mut identity = serde_json::to_value(intent).map_err(|error| error.to_string())?;
        identity
            .as_object_mut()
            .ok_or_else(|| "origin intent is not an object".to_owned())?
            .remove("intent_id");
        if intent.intent_id != format!("sha256:{:x}", Sha256::digest(jcs(&identity)?))
            || self.intent_digest != format!("sha256:{:x}", Sha256::digest(jcs(intent)?))
        {
            return Err("NQ substrate-origin intent identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginRequirementV1 {
    pub schema: String,
    pub profile_id: String,
    pub subject_ref: String,
    /// Exact coordinate permitted to establish the first V3 origin history.
    /// Omitted after cutover so a replacement attester key requires an exact
    /// predecessor plus Standing continuity authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_coordinate_ref: Option<String>,
    pub expected_issuer_id: String,
    pub expected_key_id: String,
    pub expected_namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_linode_instance_id_sha256: Option<String>,
}

impl SubstrateOriginRequirementV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != REQUIREMENT_SCHEMA_V1 {
            return Err("unsupported substrate-origin requirement schema".into());
        }
        for (name, value) in [
            ("origin profile", self.profile_id.as_str()),
            ("origin subject", self.subject_ref.as_str()),
            ("origin issuer", self.expected_issuer_id.as_str()),
            ("origin key id", self.expected_key_id.as_str()),
            ("origin namespace", self.expected_namespace.as_str()),
        ] {
            require_token(name, value)?;
        }
        let coordinate_prefix = if let Some(value) = &self.expected_linode_instance_id_sha256 {
            if self.profile_id != LINODE_INSTANCE_METADATA_PROFILE_V1
                || self.expected_namespace != LINODE_METADATA_NAMESPACE_V1
            {
                return Err("Linode metadata origin requirement profile mismatch".into());
            }
            require_digest("expected Linode instance id digest", value)?;
            "substrate:linode-instance:v1:"
        } else {
            if self.profile_id == LINODE_INSTANCE_METADATA_PROFILE_V1 {
                return Err(
                    "Linode metadata origin requirement lacks an exact instance id digest".into(),
                );
            }
            "substrate:attester-key:v1:"
        };
        if self.bootstrap_coordinate_ref.as_ref().is_some_and(|value| {
            !value.starts_with(coordinate_prefix) || value.chars().any(char::is_whitespace)
        }) {
            return Err("bootstrap coordinate uses an unsupported coordinate kind".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateOriginApplicabilityStatusV1 {
    Applicable,
    Refused,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateOriginApplicabilityReasonV1 {
    BootstrapOriginEstablished,
    StableExactOrigin,
    AuthorizedExactTransition,
    SubjectMismatch,
    IntakeMismatch,
    PredecessorHistoryAbsent,
    PredecessorHistoryMismatch,
    OriginMismatch,
    ContinuityAuthorityMissing,
    ContinuityAuthorityUnexpected,
    ContinuityEdgeMismatch,
    OriginProofInvalid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateOriginApplicabilityV1 {
    pub schema: String,
    pub applicability_id: String,
    pub status: SubstrateOriginApplicabilityStatusV1,
    pub reason: SubstrateOriginApplicabilityReasonV1,
    pub profile_id: String,
    pub diagnostic_artifact_id: String,
    pub subject_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_applicability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_coordinate_ref: Option<String>,
    pub observed_coordinate_ref: String,
    pub attestation_occurrence_ref: String,
    pub acquisition_id: String,
    pub provider_intake_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_occurrence_ref: Option<String>,
}

impl SubstrateOriginApplicabilityV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        requirement: &SubstrateOriginRequirementV1,
        proof: &SubstrateOriginAcquisitionProofV1,
        diagnostic_artifact_id: &str,
        provider_intake_ref: &str,
        predecessor: Option<&SubstrateOriginApplicabilityV1>,
        status: SubstrateOriginApplicabilityStatusV1,
        reason: SubstrateOriginApplicabilityReasonV1,
    ) -> Result<Self, String> {
        let authority_occurrence_ref = proof.intent.continuity_carrier.as_ref().map(|carrier| {
            carrier
                .authority
                .payload
                .authority_occurrence_ref
                .to_string()
        });
        let mut value = Self {
            schema: APPLICABILITY_SCHEMA_V1.into(),
            applicability_id: String::new(),
            status,
            reason,
            profile_id: requirement.profile_id.clone(),
            diagnostic_artifact_id: diagnostic_artifact_id.into(),
            subject_ref: requirement.subject_ref.clone(),
            predecessor_applicability_id: predecessor.map(|value| value.applicability_id.clone()),
            predecessor_coordinate_ref: predecessor
                .map(|value| value.observed_coordinate_ref.clone()),
            observed_coordinate_ref: proof
                .intent
                .basis
                .expected_coordinate
                .coordinate_ref
                .clone(),
            attestation_occurrence_ref: proof
                .intent
                .attestation
                .payload
                .attestation_occurrence_ref
                .clone(),
            acquisition_id: proof.intent.basis.acquisition_id.clone(),
            provider_intake_ref: provider_intake_ref.into(),
            authority_occurrence_ref,
        };
        value.applicability_id = object_id(&value, "applicability_id")?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != APPLICABILITY_SCHEMA_V1 {
            return Err("unsupported substrate-origin applicability schema".into());
        }
        require_digest("origin applicability id", &self.applicability_id)?;
        require_digest("origin diagnostic artifact", &self.diagnostic_artifact_id)?;
        for (name, value) in [
            ("origin profile", self.profile_id.as_str()),
            ("origin subject", self.subject_ref.as_str()),
            ("observed coordinate", self.observed_coordinate_ref.as_str()),
            (
                "origin attestation occurrence",
                self.attestation_occurrence_ref.as_str(),
            ),
            ("origin acquisition", self.acquisition_id.as_str()),
            ("origin provider intake", self.provider_intake_ref.as_str()),
        ] {
            require_token(name, value)?;
        }
        if let Some(value) = &self.predecessor_applicability_id {
            require_digest("predecessor applicability", value)?;
        }
        if self.predecessor_applicability_id.is_some() != self.predecessor_coordinate_ref.is_some()
        {
            return Err("origin predecessor identity and coordinate must be paired".into());
        }
        if self.applicability_id != object_id(self, "applicability_id")? {
            return Err("substrate-origin applicability identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SubstrateOriginVerifierV1 {
    requirement: SubstrateOriginRequirementV1,
    key: VerifyingKey,
}

impl SubstrateOriginVerifierV1 {
    pub fn from_public_key_hex(
        requirement: SubstrateOriginRequirementV1,
        public_key_hex: &str,
    ) -> Result<Self, String> {
        requirement.validate()?;
        let bytes: [u8; 32] = hex::decode(public_key_hex.trim())
            .map_err(|_| "origin public key is not hexadecimal".to_owned())?
            .try_into()
            .map_err(|_| "origin public key is not 32 bytes".to_owned())?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| "origin public key is invalid".to_owned())?;
        let verifier = Self { requirement, key };
        if let Some(bootstrap) = &verifier.requirement.bootstrap_coordinate_ref {
            if verifier.expected_coordinate()?.coordinate_ref != *bootstrap {
                return Err("bootstrap coordinate does not match pinned origin key".into());
            }
        }
        Ok(verifier)
    }

    pub fn from_public_key_file(
        requirement: SubstrateOriginRequirementV1,
        path: &Path,
    ) -> Result<Self, String> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .map_err(|error| format!("open origin public key: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("inspect origin public key: {error}"))?;
        if !metadata.is_file() || metadata.len() > MAX_PUBLIC_KEY_BYTES {
            return Err("origin public key must be a bounded regular file".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_PUBLIC_KEY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read origin public key: {error}"))?;
        if bytes.len() as u64 > MAX_PUBLIC_KEY_BYTES {
            return Err("origin public key exceeds size bound".into());
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| "origin public key is not UTF-8".to_owned())?;
        Self::from_public_key_hex(requirement, text)
    }

    pub fn requirement(&self) -> &SubstrateOriginRequirementV1 {
        &self.requirement
    }

    pub fn expected_coordinate(&self) -> Result<SubstrateCoordinateV1, String> {
        match &self.requirement.expected_linode_instance_id_sha256 {
            Some(instance_id) => SubstrateCoordinateV1::for_linode_instance_digest(instance_id),
            None => SubstrateCoordinateV1::for_key(
                &self.requirement.expected_namespace,
                &self.requirement.expected_key_id,
                &self.key,
            ),
        }
    }

    fn verify_attestation(
        &self,
        basis: &SubstrateOriginAcquisitionBasisV1,
        signed: &SignedSubstrateOriginAttestationV1,
    ) -> Result<(), String> {
        if signed.schema != SIGNED_ATTESTATION_SCHEMA_V1
            || signed.payload.schema != ATTESTATION_SCHEMA_V1
            || signed.payload.issuer_id != self.requirement.expected_issuer_id
            || signed.payload.key_id != self.requirement.expected_key_id
            || signed.payload.coordinate != self.expected_coordinate()?
            || signed.payload.coordinate != basis.expected_coordinate
            || signed.payload.acquisition_id != basis.acquisition_id
            || signed.payload.acquisition_basis_digest != basis.digest()?
            || signed.payload.nonclaims != expected_nonclaims(&signed.payload.coordinate)
            || !profile_evidence_matches(&signed.payload)?
        {
            return Err("substrate-origin attestation binding mismatch".into());
        }
        require_token(
            "origin attestation occurrence",
            &signed.payload.attestation_occurrence_ref,
        )?;
        require_token("origin replay identity", &signed.payload.replay_identity)?;
        require_hex_digest("origin attestation payload digest", &signed.payload_digest)?;
        DateTime::parse_from_rfc3339(&signed.payload.attested_at)
            .map_err(|_| "origin attested_at is not RFC3339".to_owned())?;
        let payload = jcs(&signed.payload)?;
        if signed.payload_digest != format!("{:x}", Sha256::digest(&payload)) {
            return Err("origin attestation payload digest mismatch".into());
        }
        let signature: [u8; 64] = hex::decode(&signed.signature)
            .map_err(|_| "origin signature is not hexadecimal".to_owned())?
            .try_into()
            .map_err(|_| "origin signature is not 64 bytes".to_owned())?;
        let mut preimage =
            Vec::with_capacity(SIGNED_ATTESTATION_SCHEMA_V1.len() + 1 + payload.len());
        preimage.extend_from_slice(SIGNED_ATTESTATION_SCHEMA_V1.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&payload);
        self.key
            .verify(&preimage, &Signature::from_bytes(&signature))
            .map_err(|_| "origin Ed25519 verification failed".to_owned())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        proof: &SubstrateOriginAcquisitionProofV1,
        diagnostic_artifact_id: &str,
        diagnostic_subject_ref: &str,
        diagnostic_provider_intake_ref: &str,
        predecessor: Option<&SubstrateOriginApplicabilityV1>,
        continuity_verifier: Option<&ContinuityAuthorityVerifierV1>,
    ) -> Result<SubstrateOriginApplicabilityV1, String> {
        proof.validate_shape()?;
        self.verify_attestation(&proof.intent.basis, &proof.intent.attestation)?;
        let verdict = |status, reason| {
            SubstrateOriginApplicabilityV1::new(
                &self.requirement,
                proof,
                diagnostic_artifact_id,
                diagnostic_provider_intake_ref,
                predecessor,
                status,
                reason,
            )
        };
        if diagnostic_subject_ref != self.requirement.subject_ref
            || proof.intent.basis.subject_ref != self.requirement.subject_ref
        {
            return verdict(
                SubstrateOriginApplicabilityStatusV1::Refused,
                SubstrateOriginApplicabilityReasonV1::SubjectMismatch,
            );
        }
        if proof.intent.intake_id != diagnostic_provider_intake_ref {
            return verdict(
                SubstrateOriginApplicabilityStatusV1::Refused,
                SubstrateOriginApplicabilityReasonV1::IntakeMismatch,
            );
        }
        let observed = &proof.intent.basis.expected_coordinate.coordinate_ref;
        match predecessor {
            None if self.requirement.bootstrap_coordinate_ref.as_deref()
                == Some(observed.as_str()) =>
            {
                if proof.intent.basis.continuity.is_some()
                    || proof.intent.continuity_carrier.is_some()
                {
                    verdict(
                        SubstrateOriginApplicabilityStatusV1::Refused,
                        SubstrateOriginApplicabilityReasonV1::ContinuityAuthorityUnexpected,
                    )
                } else {
                    verdict(
                        SubstrateOriginApplicabilityStatusV1::Applicable,
                        SubstrateOriginApplicabilityReasonV1::BootstrapOriginEstablished,
                    )
                }
            }
            None => verdict(
                SubstrateOriginApplicabilityStatusV1::Unresolved,
                SubstrateOriginApplicabilityReasonV1::PredecessorHistoryAbsent,
            ),
            Some(previous) if &previous.observed_coordinate_ref == observed => {
                if proof.intent.basis.continuity.is_some()
                    || proof.intent.continuity_carrier.is_some()
                {
                    verdict(
                        SubstrateOriginApplicabilityStatusV1::Refused,
                        SubstrateOriginApplicabilityReasonV1::ContinuityAuthorityUnexpected,
                    )
                } else {
                    verdict(
                        SubstrateOriginApplicabilityStatusV1::Applicable,
                        SubstrateOriginApplicabilityReasonV1::StableExactOrigin,
                    )
                }
            }
            Some(previous) => {
                let (Some(basis), Some(carrier), Some(continuity_verifier)) = (
                    proof.intent.basis.continuity.as_ref(),
                    proof.intent.continuity_carrier.as_ref(),
                    continuity_verifier,
                ) else {
                    return verdict(
                        SubstrateOriginApplicabilityStatusV1::Refused,
                        SubstrateOriginApplicabilityReasonV1::ContinuityAuthorityMissing,
                    );
                };
                continuity_verifier.verify_embedded_carrier(carrier, basis)?;
                if basis.edge.subject_ref != self.requirement.subject_ref
                    || basis.edge.relation != ContinuityRelationV1::SubstrateIncarnation
                    || basis.edge.predecessor_ref != previous.observed_coordinate_ref
                    || &basis.edge.successor_ref != observed
                {
                    verdict(
                        SubstrateOriginApplicabilityStatusV1::Refused,
                        SubstrateOriginApplicabilityReasonV1::ContinuityEdgeMismatch,
                    )
                } else {
                    verdict(
                        SubstrateOriginApplicabilityStatusV1::Applicable,
                        SubstrateOriginApplicabilityReasonV1::AuthorizedExactTransition,
                    )
                }
            }
        }
    }
}

fn expected_nonclaims(coordinate: &SubstrateCoordinateV1) -> Vec<String> {
    match coordinate.kind {
        SubstrateCoordinateKindV1::AttesterKey => ATTESTATION_NONCLAIMS.map(str::to_owned).to_vec(),
        SubstrateCoordinateKindV1::LinodeInstance => {
            LINODE_METADATA_NONCLAIMS.map(str::to_owned).to_vec()
        }
    }
}

fn profile_evidence_matches(payload: &SubstrateOriginAttestationV1) -> Result<bool, String> {
    match payload.coordinate.kind {
        SubstrateCoordinateKindV1::AttesterKey => Ok(payload.linode_metadata.is_none()),
        SubstrateCoordinateKindV1::LinodeInstance => {
            let Some(evidence) = &payload.linode_metadata else {
                return Ok(false);
            };
            Ok(evidence.coordinate()? == payload.coordinate)
        }
    }
}

fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a bounded non-whitespace token"));
    }
    Ok(())
}

fn require_hex_digest(name: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be lowercase SHA-256 hex"));
    }
    Ok(())
}

fn require_digest(name: &str, value: &str) -> Result<(), String> {
    let Some(value) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    };
    require_hex_digest(name, value)
}

fn object_id<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity preimage is not an object".to_owned())?
        .remove(field);
    Ok(format!("sha256:{:x}", Sha256::digest(jcs(&value)?)))
}

fn jcs<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn verifier_and_key() -> (SubstrateOriginVerifierV1, SigningKey) {
        let key = SigningKey::from_bytes(&[19; 32]);
        let base = SubstrateOriginRequirementV1 {
            schema: REQUIREMENT_SCHEMA_V1.into(),
            profile_id: "origin-profile:test".into(),
            subject_ref: "observer:test-office".into(),
            bootstrap_coordinate_ref: None,
            expected_issuer_id: "origin-attester:test".into(),
            expected_key_id: "origin-key:test".into(),
            expected_namespace: "test.local".into(),
            expected_linode_instance_id_sha256: None,
        };
        let provisional = SubstrateOriginVerifierV1::from_public_key_hex(
            base.clone(),
            &hex::encode(key.verifying_key().as_bytes()),
        )
        .expect("provisional verifier");
        let requirement = SubstrateOriginRequirementV1 {
            bootstrap_coordinate_ref: Some(
                provisional
                    .expected_coordinate()
                    .expect("coordinate")
                    .coordinate_ref,
            ),
            ..base
        };
        (
            SubstrateOriginVerifierV1::from_public_key_hex(
                requirement,
                &hex::encode(key.verifying_key().as_bytes()),
            )
            .expect("verifier"),
            key,
        )
    }

    fn proof(
        verifier: &SubstrateOriginVerifierV1,
        key: &SigningKey,
        acquisition_id: &str,
    ) -> SubstrateOriginAcquisitionProofV1 {
        let basis = SubstrateOriginAcquisitionBasisV1 {
            schema: ORIGIN_BASIS_SCHEMA_V1.into(),
            acquisition_id: acquisition_id.into(),
            watcher_instance_id: "watcher:test".into(),
            watcher_config_digest: "a".repeat(64),
            subject_ref: "observer:test-office".into(),
            expected_coordinate: verifier.expected_coordinate().expect("coordinate"),
            continuity: None,
        };
        let payload = SubstrateOriginAttestationV1 {
            schema: ATTESTATION_SCHEMA_V1.into(),
            attestation_occurrence_ref: format!("attestation:{acquisition_id}"),
            issuer_id: "origin-attester:test".into(),
            key_id: "origin-key:test".into(),
            acquisition_id: acquisition_id.into(),
            acquisition_basis_digest: basis.digest().expect("basis digest"),
            coordinate: basis.expected_coordinate.clone(),
            linode_metadata: None,
            attested_at: "2026-08-24T12:00:00Z".into(),
            replay_identity: format!("replay:{acquisition_id}"),
            nonclaims: ATTESTATION_NONCLAIMS.map(str::to_owned).to_vec(),
        };
        let payload_bytes = jcs(&payload).expect("payload bytes");
        let mut preimage = Vec::new();
        preimage.extend_from_slice(SIGNED_ATTESTATION_SCHEMA_V1.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&payload_bytes);
        let attestation = SignedSubstrateOriginAttestationV1 {
            schema: SIGNED_ATTESTATION_SCHEMA_V1.into(),
            payload,
            payload_digest: format!("{:x}", Sha256::digest(&payload_bytes)),
            signature: hex::encode(key.sign(&preimage).to_bytes()),
        };
        let mut intent = SubstrateOriginAcquisitionIntentV1 {
            schema: ORIGIN_INTENT_SCHEMA_V1.into(),
            intent_id: String::new(),
            basis: basis.clone(),
            basis_digest: basis.digest().expect("basis digest"),
            attestation,
            continuity_carrier: None,
            intake_id: acquisition_id.into(),
            attempt_id: format!("attempt:{acquisition_id}"),
            run_id: format!("run:{acquisition_id}"),
            request: serde_json::json!({
                "instance_id": "watcher:test",
                "binding": {"subject": "observer:test-office"}
            }),
            provider: serde_json::json!({"kind": "test-provider"}),
            origin_carrier: "local_test".into(),
            checkpoint_contract_digest: format!("sha256:{}", "b".repeat(64)),
        };
        let mut identity = serde_json::to_value(&intent).expect("intent value");
        identity
            .as_object_mut()
            .expect("intent object")
            .remove("intent_id");
        intent.intent_id = format!("sha256:{:x}", Sha256::digest(jcs(&identity).unwrap()));
        SubstrateOriginAcquisitionProofV1 {
            intent_digest: format!("sha256:{:x}", Sha256::digest(jcs(&intent).unwrap())),
            intent,
            phases: vec![
                SubstrateOriginAcquisitionPhaseV1::ProviderInvocationStarted,
                SubstrateOriginAcquisitionPhaseV1::ProviderIntakeCompleted,
            ],
        }
    }

    fn verifier_for_key(key: &SigningKey, bootstrap: bool) -> SubstrateOriginVerifierV1 {
        let base = SubstrateOriginRequirementV1 {
            schema: REQUIREMENT_SCHEMA_V1.into(),
            profile_id: "origin-profile:test".into(),
            subject_ref: "observer:test-office".into(),
            bootstrap_coordinate_ref: None,
            expected_issuer_id: "origin-attester:test".into(),
            expected_key_id: "origin-key:test".into(),
            expected_namespace: "test.local".into(),
            expected_linode_instance_id_sha256: None,
        };
        let provisional = SubstrateOriginVerifierV1::from_public_key_hex(
            base.clone(),
            &hex::encode(key.verifying_key().as_bytes()),
        )
        .unwrap();
        let requirement = SubstrateOriginRequirementV1 {
            bootstrap_coordinate_ref: bootstrap
                .then(|| provisional.expected_coordinate().unwrap().coordinate_ref),
            ..base
        };
        SubstrateOriginVerifierV1::from_public_key_hex(
            requirement,
            &hex::encode(key.verifying_key().as_bytes()),
        )
        .unwrap()
    }

    fn linode_verifier(key: &SigningKey, instance_digest: &str) -> SubstrateOriginVerifierV1 {
        let base = SubstrateOriginRequirementV1 {
            schema: REQUIREMENT_SCHEMA_V1.into(),
            profile_id: LINODE_INSTANCE_METADATA_PROFILE_V1.into(),
            subject_ref: "observer:test-office".into(),
            bootstrap_coordinate_ref: None,
            expected_issuer_id: "origin-attester:test".into(),
            expected_key_id: "origin-key:test".into(),
            expected_namespace: LINODE_METADATA_NAMESPACE_V1.into(),
            expected_linode_instance_id_sha256: Some(instance_digest.into()),
        };
        let provisional = SubstrateOriginVerifierV1::from_public_key_hex(
            base.clone(),
            &hex::encode(key.verifying_key().as_bytes()),
        )
        .unwrap();
        SubstrateOriginVerifierV1::from_public_key_hex(
            SubstrateOriginRequirementV1 {
                bootstrap_coordinate_ref: Some(
                    provisional.expected_coordinate().unwrap().coordinate_ref,
                ),
                ..base
            },
            &hex::encode(key.verifying_key().as_bytes()),
        )
        .unwrap()
    }

    fn linode_proof(
        verifier: &SubstrateOriginVerifierV1,
        key: &SigningKey,
        acquisition_id: &str,
        instance_digest: &str,
    ) -> SubstrateOriginAcquisitionProofV1 {
        let mut value = proof(verifier, key, acquisition_id);
        value.intent.attestation.payload.linode_metadata = Some(LinodeInstanceMetadataEvidenceV1 {
            schema: LINODE_METADATA_EVIDENCE_SCHEMA_V1.into(),
            profile_id: LINODE_INSTANCE_METADATA_PROFILE_V1.into(),
            endpoint: LINODE_METADATA_INSTANCE_ENDPOINT_V1.into(),
            instance_id_sha256: instance_digest.into(),
            host_uuid_sha256: Some(format!("sha256:{}", "2".repeat(64))),
            canonical_response_sha256: format!("sha256:{}", "3".repeat(64)),
        });
        value.intent.attestation.payload.nonclaims =
            LINODE_METADATA_NONCLAIMS.map(str::to_owned).to_vec();
        reseal_origin_proof(&mut value, key);
        value
    }

    fn reseal_origin_proof(proof: &mut SubstrateOriginAcquisitionProofV1, key: &SigningKey) {
        proof.intent.basis_digest = proof.intent.basis.digest().unwrap();
        proof.intent.attestation.payload.acquisition_basis_digest =
            proof.intent.basis_digest.clone();
        proof.intent.attestation.payload.coordinate =
            proof.intent.basis.expected_coordinate.clone();
        let payload_bytes = jcs(&proof.intent.attestation.payload).unwrap();
        proof.intent.attestation.payload_digest = format!("{:x}", Sha256::digest(&payload_bytes));
        let mut preimage = Vec::new();
        preimage.extend_from_slice(SIGNED_ATTESTATION_SCHEMA_V1.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&payload_bytes);
        proof.intent.attestation.signature = hex::encode(key.sign(&preimage).to_bytes());
        proof.intent.intent_id.clear();
        let mut identity = serde_json::to_value(&proof.intent).unwrap();
        identity.as_object_mut().unwrap().remove("intent_id");
        proof.intent.intent_id = format!("sha256:{:x}", Sha256::digest(jcs(&identity).unwrap()));
        proof.intent_digest = format!("sha256:{:x}", Sha256::digest(jcs(&proof.intent).unwrap()));
    }

    #[test]
    fn bootstrap_then_stable_origin_builds_exact_append_only_chain() {
        let (verifier, key) = verifier_and_key();
        let first_proof = proof(&verifier, &key, "intake:first");
        let first = verifier
            .evaluate(
                &first_proof,
                &format!("sha256:{}", "c".repeat(64)),
                "observer:test-office",
                "intake:first",
                None,
                None,
            )
            .expect("bootstrap verdict");
        assert_eq!(
            first.status,
            SubstrateOriginApplicabilityStatusV1::Applicable
        );
        assert_eq!(
            first.reason,
            SubstrateOriginApplicabilityReasonV1::BootstrapOriginEstablished
        );

        let second_proof = proof(&verifier, &key, "intake:second");
        let second = verifier
            .evaluate(
                &second_proof,
                &format!("sha256:{}", "d".repeat(64)),
                "observer:test-office",
                "intake:second",
                Some(&first),
                None,
            )
            .expect("stable verdict");
        assert_eq!(
            second.status,
            SubstrateOriginApplicabilityStatusV1::Applicable
        );
        assert_eq!(
            second.predecessor_applicability_id,
            Some(first.applicability_id)
        );
        assert_eq!(
            second.observed_coordinate_ref,
            first.observed_coordinate_ref
        );
    }

    #[test]
    fn attestation_substitution_and_asserted_names_do_not_establish_origin() {
        let (verifier, key) = verifier_and_key();
        let mut named_proof = proof(&verifier, &key, "intake:hostile");
        named_proof.intent.provider["hostname"] = serde_json::json!("p2.example");
        assert!(
            named_proof.validate_shape().is_err(),
            "intent resealing is mandatory"
        );

        let mut proof = proof(&verifier, &key, "intake:hostile-origin");
        proof.intent.attestation.payload.coordinate.coordinate_ref =
            "substrate:attester-key:v1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .into();
        assert!(verifier
            .evaluate(
                &proof,
                &format!("sha256:{}", "e".repeat(64)),
                "observer:test-office",
                "intake:hostile-origin",
                None,
                None,
            )
            .is_err());
    }

    #[test]
    fn exact_p1_to_p2_authority_and_origin_are_both_required() {
        let (p1_verifier, p1_key) = verifier_and_key();
        let first_proof = proof(&p1_verifier, &p1_key, "intake:p1");
        let first = p1_verifier
            .evaluate(
                &first_proof,
                &format!("sha256:{}", "1".repeat(64)),
                "observer:test-office",
                "intake:p1",
                None,
                None,
            )
            .unwrap();

        let p2_key = SigningKey::from_bytes(&[29; 32]);
        let p2_verifier = verifier_for_key(&p2_key, false);
        let p2_coordinate = p2_verifier.expected_coordinate().unwrap().coordinate_ref;
        let mut continuity = crate::continuity_authority::tests::proof();
        continuity
            .intent
            .carrier
            .authority
            .payload
            .edge
            .predecessor_ref = first.observed_coordinate_ref.clone();
        continuity
            .intent
            .carrier
            .authority
            .payload
            .edge
            .successor_ref = p2_coordinate.clone();
        crate::continuity_authority::tests::resign_authority(&mut continuity);
        continuity.intent.basis.acquisition_id = "intake:p2".into();
        continuity.intent.basis.watcher_instance_id = "watcher:test".into();
        continuity.intent.basis.watcher_config_digest = "a".repeat(64);
        continuity.intent.basis.edge = continuity.intent.carrier.authority.payload.edge.clone();
        continuity.intent.basis.authority_digest =
            continuity.intent.carrier.authority.payload_digest.clone();
        continuity.intent.basis_digest = format!(
            "{:x}",
            Sha256::digest(jcs(&continuity.intent.basis).unwrap())
        );
        continuity.intent.carrier.commitment.payload.acquisition_id = "intake:p2".into();
        continuity
            .intent
            .carrier
            .commitment
            .payload
            .acquisition_basis_digest = continuity.intent.basis_digest.clone();
        continuity
            .intent
            .carrier
            .commitment
            .payload
            .authority_payload_digest = continuity.intent.carrier.authority.payload_digest.clone();
        crate::continuity_authority::tests::resign_commitment(&mut continuity);
        crate::continuity_authority::tests::reseal_intent(&mut continuity);

        let mut second_proof = proof(&p2_verifier, &p2_key, "intake:p2");
        second_proof.intent.basis.continuity = Some(continuity.intent.basis.clone());
        second_proof.intent.continuity_carrier = Some(continuity.intent.carrier.clone());
        reseal_origin_proof(&mut second_proof, &p2_key);
        let second = p2_verifier
            .evaluate(
                &second_proof,
                &format!("sha256:{}", "2".repeat(64)),
                "observer:test-office",
                "intake:p2",
                Some(&first),
                Some(&crate::continuity_authority::tests::verifier()),
            )
            .expect("exact authority plus exact P2 origin applies");
        assert_eq!(
            second.reason,
            SubstrateOriginApplicabilityReasonV1::AuthorizedExactTransition
        );
        assert_eq!(
            second.predecessor_applicability_id,
            Some(first.applicability_id.clone())
        );
        assert_eq!(second.observed_coordinate_ref, p2_coordinate);

        let mut wrong_origin = second_proof;
        wrong_origin.intent.basis.expected_coordinate.coordinate_ref =
            "substrate:attester-key:v1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .into();
        assert!(p2_verifier
            .evaluate(
                &wrong_origin,
                &format!("sha256:{}", "3".repeat(64)),
                "observer:test-office",
                "intake:p2",
                Some(&first),
                Some(&crate::continuity_authority::tests::verifier()),
            )
            .is_err());
    }

    #[test]
    fn linode_logical_instance_profile_applies_and_refuses_profile_or_instance_substitution() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let instance_digest = format!("sha256:{}", "1".repeat(64));
        let verifier = linode_verifier(&key, &instance_digest);
        let proof = linode_proof(&verifier, &key, "intake:linode", &instance_digest);
        let verdict = verifier
            .evaluate(
                &proof,
                &format!("sha256:{}", "4".repeat(64)),
                "observer:test-office",
                "intake:linode",
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            verdict.reason,
            SubstrateOriginApplicabilityReasonV1::BootstrapOriginEstablished
        );
        assert!(verdict
            .observed_coordinate_ref
            .starts_with("substrate:linode-instance:v1:"));

        let software_verifier = verifier_for_key(&key, true);
        assert!(software_verifier
            .evaluate(
                &proof,
                &format!("sha256:{}", "4".repeat(64)),
                "observer:test-office",
                "intake:linode",
                None,
                None,
            )
            .is_err());

        let mut substituted = proof;
        substituted
            .intent
            .attestation
            .payload
            .linode_metadata
            .as_mut()
            .unwrap()
            .instance_id_sha256 = format!("sha256:{}", "9".repeat(64));
        reseal_origin_proof(&mut substituted, &key);
        assert!(verifier
            .evaluate(
                &substituted,
                &format!("sha256:{}", "4".repeat(64)),
                "observer:test-office",
                "intake:linode",
                None,
                None,
            )
            .is_err());

        let missing_coordinate = SubstrateOriginRequirementV1 {
            schema: REQUIREMENT_SCHEMA_V1.into(),
            profile_id: LINODE_INSTANCE_METADATA_PROFILE_V1.into(),
            subject_ref: "observer:test-office".into(),
            bootstrap_coordinate_ref: None,
            expected_issuer_id: "origin-attester:test".into(),
            expected_key_id: "origin-key:test".into(),
            expected_namespace: LINODE_METADATA_NAMESPACE_V1.into(),
            expected_linode_instance_id_sha256: None,
        };
        assert!(missing_coordinate.validate().is_err());
    }
}
