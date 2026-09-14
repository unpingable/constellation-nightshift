//! Select one desired local check using the canonical recurrence-slot identity.
//! Selection does not acquire evidence, reserve execution, or grant permission.

use crate::canonical_store::{RecurrenceSlotV1, RecurrenceTriggerV1, SlotTimingV1};
use chrono::{DateTime, Duration, Timelike as _, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const POLICY_SCHEMA: &str = "nightshift.saved-check-schedule-policy/v1";
pub const SELECTION_SCHEMA: &str = "nightshift.saved-check-selection/v1";
pub const REQUEST_SCHEMA: &str = "nightshift.saved-check-due-request/v1";

/// Immutable operator selection policy; source identity is not a source timestamp.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckScheduleV1 {
    pub schema: String,
    pub policy_id: String,
    pub configuration_version: String,
    pub definition_reference: String,
    pub definition_digest: String,
    pub source_identity: String,
    pub subject_id: String,
    pub scope_id: String,
    pub scheduler_clock_id: String,
    pub epoch: DateTime<Utc>,
    pub interval_seconds: u64,
    pub admissible_delay_seconds: u64,
}

/// Stable request shared by all selections of the same policy and slot.
/// There is deliberately no source observation time or execution credential.
#[derive(Clone, Debug, Serialize)]
pub struct SavedCheckDueRequestV1 {
    pub schema: &'static str,
    pub policy_digest: String,
    pub slot: RecurrenceSlotV1,
    pub evaluation_id: String,
    pub definition_reference: String,
    pub definition_digest: String,
    pub source_identity: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    NotDue,
    Missed,
    Due,
}

#[derive(Debug, Serialize)]
pub struct SavedCheckSelectionV1 {
    pub schema: &'static str,
    pub selection: Selection,
    pub policy_digest: String,
    /// A missed slot remains inspectable, but is not a runnable request.
    pub slot: Option<RecurrenceSlotV1>,
    pub request: Option<SavedCheckDueRequestV1>,
    pub authority: &'static str,
    pub observation_created: bool,
}

fn digest(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn token(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("{name} must be 1..256 visible ASCII bytes"));
    }
    Ok(())
}

impl SavedCheckScheduleV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != POLICY_SCHEMA {
            return Err("unsupported saved-check schedule schema".into());
        }
        for (name, value) in [
            ("policy_id", &self.policy_id),
            ("configuration_version", &self.configuration_version),
            ("definition_reference", &self.definition_reference),
            ("source_identity", &self.source_identity),
            ("subject_id", &self.subject_id),
            ("scope_id", &self.scope_id),
            ("scheduler_clock_id", &self.scheduler_clock_id),
        ] {
            token(name, value)?;
        }
        let hash = self.definition_digest.strip_prefix("sha256:").unwrap_or("");
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("definition_digest must be an exact lowercase SHA-256 identity".into());
        }
        // A bounded, nonoverlapping window prevents a current tick from issuing
        // a burst of historical work. Missed slots require separate intervention.
        if !(1..=86_400).contains(&self.interval_seconds)
            || self.admissible_delay_seconds >= self.interval_seconds
            || self.epoch.nanosecond() != 0
        {
            return Err(
                "require whole-second epoch, interval 1..86400 and delay < interval".into(),
            );
        }
        Ok(())
    }

    pub fn select(
        &self,
        scheduler_clock_id: &str,
        at: DateTime<Utc>,
    ) -> Result<SavedCheckSelectionV1, String> {
        self.validate()?;
        if scheduler_clock_id != self.scheduler_clock_id {
            return Err("scheduler clock does not match policy".into());
        }
        let policy_digest = digest(self)?;
        let mut result = SavedCheckSelectionV1 {
            schema: SELECTION_SCHEMA,
            selection: Selection::NotDue,
            policy_digest: policy_digest.clone(),
            slot: None,
            request: None,
            authority: "none",
            observation_created: false,
        };
        if at < self.epoch {
            return Ok(result);
        }
        let interval = i64::try_from(self.interval_seconds).map_err(|_| "interval overflow")?;
        let occurrence = at.signed_duration_since(self.epoch).num_seconds() / interval;
        let offset = occurrence
            .checked_mul(interval)
            .ok_or("slot offset overflow")?;
        let due = self
            .epoch
            .checked_add_signed(Duration::try_seconds(offset).ok_or("slot duration overflow")?)
            .ok_or("slot date overflow")?;
        let delay = i64::try_from(self.admissible_delay_seconds).map_err(|_| "delay overflow")?;
        let latest = due
            .checked_add_signed(Duration::try_seconds(delay).ok_or("deadline duration overflow")?)
            .ok_or("deadline date overflow")?;
        let slot = RecurrenceSlotV1::new(
            self.policy_id.clone(),
            // All operator policy fields affect identity, not just its label.
            policy_digest.clone(),
            self.subject_id.clone(),
            self.scope_id.clone(),
            self.scheduler_clock_id.clone(),
            due,
            latest,
            u64::try_from(occurrence).map_err(|_| "negative occurrence")?,
            RecurrenceTriggerV1::Scheduled,
            None,
        )
        .map_err(|error| error.to_string())?;
        let timing = slot
            .timing_at(scheduler_clock_id, at)
            .map_err(|error| error.to_string())?;
        result.slot = Some(slot.clone());
        if timing == SlotTimingV1::Missed {
            result.selection = Selection::Missed;
            return Ok(result);
        }
        result.selection = Selection::Due;
        result.request = Some(SavedCheckDueRequestV1 {
            schema: REQUEST_SCHEMA,
            policy_digest,
            evaluation_id: digest(&(REQUEST_SCHEMA, slot.slot_id.as_str()))?,
            slot,
            definition_reference: self.definition_reference.clone(),
            definition_digest: self.definition_digest.clone(),
            source_identity: self.source_identity.clone(),
        });
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }
    fn policy() -> SavedCheckScheduleV1 {
        SavedCheckScheduleV1 {
            schema: POLICY_SCHEMA.into(),
            policy_id: "local-capacity".into(),
            configuration_version: "1".into(),
            definition_reference: "capacity".into(),
            definition_digest: format!("sha256:{}", "a".repeat(64)),
            source_identity: "local-sqlite".into(),
            subject_id: "queue".into(),
            scope_id: "local-check".into(),
            scheduler_clock_id: "operator-clock".into(),
            epoch: time("2026-09-14T12:00:00Z"),
            interval_seconds: 60,
            admissible_delay_seconds: 10,
        }
    }

    #[test]
    fn due_selection_reuses_canonical_slot_and_replays_exact_request() {
        let policy = policy();
        let first = policy.select("operator-clock", policy.epoch).unwrap();
        let late = policy
            .select("operator-clock", policy.epoch + Duration::seconds(10))
            .unwrap();
        assert_eq!(first.selection, Selection::Due);
        first.slot.as_ref().unwrap().validate().unwrap();
        assert_eq!(
            serde_jcs::to_vec(&first.request).unwrap(),
            serde_jcs::to_vec(&late.request).unwrap()
        );
        assert_eq!(
            first.slot.unwrap().configuration_version,
            first.policy_digest
        );
    }

    #[test]
    fn before_epoch_and_missed_are_not_requests_and_do_not_catch_up() {
        let policy = policy();
        let before = policy
            .select("operator-clock", policy.epoch - Duration::seconds(1))
            .unwrap();
        assert_eq!(before.selection, Selection::NotDue);
        assert!(before.request.is_none());
        let missed = policy
            .select("operator-clock", policy.epoch + Duration::seconds(11))
            .unwrap();
        assert_eq!(missed.selection, Selection::Missed);
        assert!(missed.request.is_none());
        assert_eq!(missed.slot.unwrap().occurrence, 0);
        let next = policy
            .select("operator-clock", policy.epoch + Duration::seconds(600))
            .unwrap();
        assert_eq!(next.request.unwrap().slot.occurrence, 10);
    }

    #[test]
    fn clock_and_material_changes_do_not_share_an_occurrence() {
        let mut policy = policy();
        assert!(policy.select("another-clock", policy.epoch).is_err());
        let original = policy
            .select("operator-clock", policy.epoch)
            .unwrap()
            .request
            .unwrap();
        policy.source_identity = "different-source".into();
        let changed = policy
            .select("operator-clock", policy.epoch)
            .unwrap()
            .request
            .unwrap();
        assert_ne!(original.evaluation_id, changed.evaluation_id);
        assert_ne!(original.slot.slot_id, changed.slot.slot_id);
    }

    #[test]
    fn malformed_contract_and_unbounded_values_refuse_without_panicking() {
        for change in 0..7 {
            let mut policy = policy();
            match change {
                0 => policy.interval_seconds = u64::MAX,
                1 => policy.admissible_delay_seconds = u64::MAX,
                2 => policy.definition_digest = "sha256:not-a-digest".into(),
                3 => policy.source_identity = String::new(),
                4 => policy.schema = "unsupported".into(),
                5 => policy.subject_id = "x".repeat(257),
                _ => policy.interval_seconds = 0,
            }
            assert!(policy.select("operator-clock", policy.epoch).is_err());
        }
        let mut boundary = policy();
        boundary.epoch = DateTime::<Utc>::MAX_UTC.with_nanosecond(0).unwrap();
        assert!(boundary.select("operator-clock", boundary.epoch).is_err());
    }
}
