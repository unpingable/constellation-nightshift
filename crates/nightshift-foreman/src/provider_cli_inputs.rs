//! Bounded typed sealing of operator-authored inputs, not admission or authority.
use anyhow::Result;
use nightshift_foreman::{
    ExecutionAvailabilityPolicyV1, ExecutionProfileV2, ForemanAdmissionV1,
    ForemanExecutionAvailabilityRequirementV1,
};
use nightshiftd::packet::NightshiftPacketV1;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    packet: NightshiftPacketV1,
    admission: ForemanAdmissionV1,
    profile: ExecutionProfileV2,
    policy: ExecutionAvailabilityPolicyV1,
    requirement: ForemanExecutionAvailabilityRequirementV1,
}

pub fn seal(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut value: Inputs = serde_json::from_slice(bytes)?;
    value.packet.seal()?;
    value.admission.packet_digest = value.packet.packet_digest.clone();
    value.admission.seal()?;
    value.profile.packet_digest = value.packet.packet_digest.clone();
    value.profile.admission_digest = value.admission.admission_digest.clone();
    value.profile.seal()?;
    value.policy.seal()?;
    value.requirement.packet_digest = value.packet.packet_digest.clone();
    value.requirement.admission_digest = value.admission.admission_digest.clone();
    value.requirement.profile_digest = value.profile.profile_digest.clone();
    value.requirement.run_id = value.admission.run_id.clone();
    value.requirement.policy_id = value.policy.policy_id.clone();
    value.requirement.policy_digest = value.policy.policy_digest.clone();
    value.requirement.seal()?;
    Ok(serde_jcs::to_vec(&value)?)
}
