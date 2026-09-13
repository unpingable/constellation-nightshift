//! Read-only Nightshift → AG observation-evidence translator.
//!
//! This module implements the producer side of AG's frozen
//! `ag.governed-loop.observation-resolution/v2` contract. It answers one
//! exact question about one already-persisted observation:
//!
//! > Is the cited historical observation unique, internally valid, bound to
//! > the requesting subject, still inside its actionable evidence window, and
//! > still the latest qualified observation in its domain lineage — and if
//! > so, what is its semantic decision basis?
//!
//! `Current` means exactly:
//!
//! - the cited observation resolves uniquely (zero matches is `Absent`, an
//!   ambiguous caller-supplied identity is `Contradictory`);
//! - the persisted record passes the canonical store's own revalidation and
//!   the resolver's subject cross-bindings;
//! - its support is not explicitly `Contradictory`;
//! - it is bound to the requesting AG subject through the cycle's exact
//!   typed intent (the only persisted Nightshift-subject ↔ AG-subject-digest
//!   binding);
//! - `now < evaluated_at + configured TTL` (equality is stale);
//! - no strictly later qualified observation exists in the same frozen
//!   family `(policy_id, configuration_version, subject_id, scope_id,
//!   scheduler_clock_id)` under logical slot order.
//!
//! `Current` does **not** mean workflow allowed, condition clean, delivery
//! qualified, catalog admitted, standing granted, work authorized, or that
//! the world was re-observed at resolution time. This translator revalidates
//! cited historical evidence; it never manufactures new evidence and never
//! evaluates workflow policy. Workflow preconditions are AG catalog policy,
//! judged by AG at `decide` and `authorize`.
//!
//! Freshness rule: the only persisted wall-clock evidence instant is the
//! posture's `evaluated_at`. Support expiry ticks live on the evidence
//! authority's opaque receiver clock and have no wall-clock interpretation
//! in Nightshift, so they cannot be translated into AG's unix-ms freshness
//! window. `fresh_until_unix_ms = evaluated_at + default_ttl_ms`, with the
//! TTL bounded by deployment configuration.
//!
//! Non-`Current` responses for `Absent`/`Contradictory` carry a fixed
//! empty-evidence sentinel basis (`condition.unresolved` +
//! `delivery.failed`): AG's v2 contract requires a well-formed basis whose
//! digest equals `normalized_preconditions` on every response, and AG never
//! consumes the basis of a non-`Current` resolution. `Stale`/`Superseded`
//! responses carry the honest normalized basis of the cited record.

use std::collections::BTreeSet;

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::canonical_store::{
    CanonicalStore, CanonicalStoreError, ObservationCycleV1, ObservationFamilyKeyV1,
    ObservationOrderKeyV1,
};
use crate::currentness::SupportStandingV1;
use crate::decision_basis::{
    normalization_rule_v1, normalize_posture, DecisionBasisV1, CONDITION_UNRESOLVED_ATOM_V1,
    DECISION_BASIS_SCHEMA_V1, DELIVERY_FAILED_ATOM_V1,
};

/// Exact AG observation-request wire schema consumed by this resolver.
pub const AG_OBSERVATION_REQUEST_SCHEMA_V1: &str = "ag.governed-loop.observation-request/v1";
/// Exact AG observation-resolution wire schema produced by this resolver.
pub const AG_OBSERVATION_RESOLUTION_SCHEMA_V2: &str = "ag.governed-loop.observation-resolution/v2";

const CURRENTNESS_DIGEST_DOMAIN_V1: &[u8] = b"nightshift.observation-currentness.v1\0";

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

fn currentness_digest(parts: &[&[u8]]) -> String {
    let mut payload = CURRENTNESS_DIGEST_DOMAIN_V1.to_vec();
    for part in parts {
        payload.extend_from_slice(part);
        payload.push(0);
    }
    format!("sha256:{:x}", Sha256::digest(&payload))
}

/// The frozen empty-evidence sentinel basis for `Absent`/`Contradictory`
/// responses. No posture exists to normalize; the atoms state only that no
/// condition was resolved and no delivery occurred.
fn no_evidence_basis() -> DecisionBasisV1 {
    DecisionBasisV1 {
        schema: DECISION_BASIS_SCHEMA_V1.into(),
        rule: normalization_rule_v1(),
        atoms: BTreeSet::from([
            CONDITION_UNRESOLVED_ATOM_V1.to_owned(),
            DELIVERY_FAILED_ATOM_V1.to_owned(),
        ]),
    }
}

/// One exact AG observation request. `key` is echoed verbatim; the resolver
/// derives all semantic information from persisted Nightshift records and
/// never accepts caller-supplied lineage.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgObservationRequestV1 {
    /// Exact request schema.
    pub schema: String,
    /// Occurrence key, echoed verbatim into the response.
    pub key: serde_json::Value,
    /// Exact cited observation identity.
    pub observation: String,
    /// Exact AG subject digest the request claims.
    pub subject: String,
    /// AG's consequence-time clock reading; the resolution instant.
    pub now_unix_ms: u64,
}

impl AgObservationRequestV1 {
    /// Strict syntactic validation of the wire request.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != AG_OBSERVATION_REQUEST_SCHEMA_V1 {
            return Err(format!(
                "unsupported observation request schema {}",
                self.schema
            ));
        }
        if !self.key.is_object() {
            return Err("key must be an exact occurrence-key object".into());
        }
        require_digest("observation", &self.observation)?;
        require_digest("subject", &self.subject)?;
        Ok(())
    }
}

/// Mirror of AG's closed observation-status vocabulary (snake_case wire).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgObservationStatusV1 {
    /// Unique, valid, subject-bound, fresh, latest-in-lineage evidence.
    Current,
    /// The cited evidence is beyond its actionable freshness window.
    Stale,
    /// A strictly later qualified observation exists in the same family.
    Superseded,
    /// The citation is ambiguous or the persisted evidence is contradictory.
    Contradictory,
    /// No persisted observation carries the cited identity.
    Absent,
}

/// The frozen `ag.governed-loop.observation-resolution/v2` response.
#[derive(Clone, Debug, Serialize)]
pub struct AgObservationResolutionV2 {
    /// Exact response schema.
    pub schema: String,
    /// Verbatim echo of the request occurrence key.
    pub key: serde_json::Value,
    /// Verbatim echo of the cited observation identity.
    pub observation: String,
    /// Deterministic currentness witness over the exact persisted record.
    pub currentness: String,
    /// Canonical digest of `basis` (AG independently recomputes it).
    pub normalized_preconditions: String,
    /// Semantic decision basis produced by WO-3 normalization.
    pub basis: DecisionBasisV1,
    /// Configured identity of this resolver; deployment identity only.
    pub resolver_id: String,
    /// Verbatim echo of the request subject digest.
    pub subject: String,
    /// Evidence-health status.
    pub status: AgObservationStatusV1,
    /// The resolution instant (the request's `now`).
    pub resolved_at_unix_ms: u64,
    /// Exclusive freshness deadline.
    pub fresh_until_unix_ms: u64,
}

/// Resolver configuration. The resolver identity is deployment identity, not
/// authorization; it must be explicitly configured and nonempty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationResolverConfigV1 {
    /// Exact identity AG is configured to expect.
    pub resolver_id: String,
    /// Bounded evidence window: `fresh_until = evaluated_at + default_ttl_ms`.
    pub default_ttl_ms: u64,
}

impl ObservationResolverConfigV1 {
    /// Configuration validation; an empty identity is a startup error.
    pub fn validate(&self) -> Result<(), String> {
        if self.resolver_id.trim().is_empty() {
            return Err("resolver_id must be explicitly configured and nonempty".into());
        }
        if self.default_ttl_ms == 0 {
            return Err("default_ttl_ms must be a positive bounded window".into());
        }
        Ok(())
    }
}

/// Process-level failures. These are never encoded as evidence statuses:
/// database corruption, IO failure, and malformed requests exit non-zero.
#[derive(Debug, thiserror::Error)]
pub enum ObservationResolverError {
    /// The wire request is malformed.
    #[error("invalid observation request: {0}")]
    Request(String),
    /// The canonical store could not be read.
    #[error("canonical store error: {0}")]
    Store(#[from] CanonicalStoreError),
    /// The resolver is misconfigured.
    #[error("invalid resolver configuration: {0}")]
    Configuration(String),
}

struct Classification {
    status: AgObservationStatusV1,
    basis: DecisionBasisV1,
    currentness: String,
    fresh_until_unix_ms: u64,
}

fn negative(
    request: &AgObservationRequestV1,
    config: &ObservationResolverConfigV1,
    status: AgObservationStatusV1,
) -> AgObservationResolutionV2 {
    let basis = no_evidence_basis();
    let normalized_preconditions = basis
        .digest()
        .expect("the sentinel basis is a valid v1 basis");
    AgObservationResolutionV2 {
        schema: AG_OBSERVATION_RESOLUTION_SCHEMA_V2.into(),
        key: request.key.clone(),
        observation: request.observation.clone(),
        currentness: currentness_digest(&[
            request.observation.as_bytes(),
            status_name(status).as_bytes(),
        ]),
        normalized_preconditions,
        basis,
        resolver_id: config.resolver_id.clone(),
        subject: request.subject.clone(),
        status,
        resolved_at_unix_ms: request.now_unix_ms,
        fresh_until_unix_ms: request.now_unix_ms + config.default_ttl_ms,
    }
}

fn status_name(status: AgObservationStatusV1) -> &'static str {
    match status {
        AgObservationStatusV1::Current => "current",
        AgObservationStatusV1::Stale => "stale",
        AgObservationStatusV1::Superseded => "superseded",
        AgObservationStatusV1::Contradictory => "contradictory",
        AgObservationStatusV1::Absent => "absent",
    }
}

/// Classify the cited observation, preserving the frozen precedence:
/// authenticity (`Contradictory`) first, then freshness (`Stale`), then
/// lineage (`Superseded`). `Stale` deliberately precedes `Superseded` so the
/// refusal reason stays precise when both hold.
fn classify(
    store: &CanonicalStore,
    request: &AgObservationRequestV1,
    config: &ObservationResolverConfigV1,
) -> Result<Classification, ObservationResolverError> {
    let matches = match store.find_cycles_by_observation_id(&request.observation) {
        Ok(matches) => matches,
        // A persisted record that fails the store's own revalidation is
        // contradictory stored evidence, not a process failure.
        Err(CanonicalStoreError::Invalid(_)) => {
            return Ok(Classification {
                status: AgObservationStatusV1::Contradictory,
                basis: no_evidence_basis(),
                currentness: String::new(),
                fresh_until_unix_ms: 0,
            });
        }
        Err(error) => return Err(ObservationResolverError::Store(error)),
    };
    let sentinel = |status: AgObservationStatusV1| Classification {
        status,
        basis: no_evidence_basis(),
        currentness: String::new(),
        fresh_until_unix_ms: 0,
    };
    let [cycle] = matches.as_slice() else {
        return Ok(sentinel(if matches.is_empty() {
            AgObservationStatusV1::Absent
        } else {
            // Ambiguous caller-supplied identity fails closed: never choose
            // first, newest, or by write order.
            AgObservationStatusV1::Contradictory
        }));
    };
    let Some(record) = &cycle.observation else {
        return Ok(sentinel(AgObservationStatusV1::Contradictory));
    };
    if record
        .external_evidence
        .as_ref()
        .is_some_and(|composition| {
            store
                .validate_external_composition_source(composition)
                .is_err()
        })
    {
        return Ok(sentinel(AgObservationStatusV1::Contradictory));
    }
    if record
        .decision_external_evidence
        .as_ref()
        .is_some_and(|composition| {
            store
                .validate_decision_composition_source(composition)
                .is_err()
        })
    {
        return Ok(sentinel(AgObservationStatusV1::Contradictory));
    }
    // Explicit subject cross-bindings over the persisted record. The store
    // has already re-run cycle/observation validation; these tie the slot,
    // support, and posture subjects to one exact Nightshift subject.
    if record.support.subject_id != cycle.slot.subject_id
        || record.posture.policy.subject.id != cycle.slot.subject_id
        || record.observation_id != request.observation
    {
        return Ok(sentinel(AgObservationStatusV1::Contradictory));
    }
    // Only an explicitly contradictory support state is contradictory
    // evidence health. Other non-Current standings never alter the basis.
    if record.support.standing == SupportStandingV1::Contradictory {
        return Ok(sentinel(AgObservationStatusV1::Contradictory));
    }
    // AG subject binding. The cycle's exact typed intent is the only
    // persisted Nightshift-subject ↔ AG-subject-digest binding; an
    // observation never prepared for AG has no verifiable AG subject, and a
    // request naming a different digest contradicts the persisted binding.
    let Some(intent) = &cycle.intent else {
        return Ok(sentinel(AgObservationStatusV1::Contradictory));
    };
    if intent.subject_id != cycle.slot.subject_id || intent.subject_digest != request.subject {
        return Ok(sentinel(AgObservationStatusV1::Contradictory));
    }
    // Freshness from the persisted posture instant plus the configured
    // bounded window. Support expiry ticks are opaque receiver-clock values
    // and cannot be translated into AG's unix-ms window.
    let basis = normalize_posture(&record.posture);
    let evaluated_ms = DateTime::parse_from_rfc3339(&record.posture.evaluated_at)
        .ok()
        .and_then(|instant| u64::try_from(instant.timestamp_millis()).ok());
    let Some(evaluated_ms) = evaluated_ms else {
        return Ok(sentinel(AgObservationStatusV1::Contradictory));
    };
    let posture_fresh_until = evaluated_ms
        .checked_add(config.default_ttl_ms)
        .ok_or_else(|| {
            ObservationResolverError::Configuration(
                "resolver freshness horizon overflows Unix milliseconds".into(),
            )
        })?;
    // A composed observation is current only inside both independent
    // horizons: the ordinary Nightshift posture window and the
    // deployment-owned application-evidence profile window. Receipt time and
    // the UI's display-age arithmetic never participate.
    let evidence_horizon = record
        .external_evidence
        .as_ref()
        .map(|composition| composition.fresh_until_unix_ms)
        .or_else(|| {
            record
                .decision_external_evidence
                .as_ref()
                .map(|composition| composition.fresh_until_unix_ms)
        });
    let fresh_until_unix_ms = evidence_horizon.map_or(posture_fresh_until, |horizon| {
        posture_fresh_until.min(horizon)
    });
    let composition_id = record
        .external_evidence
        .as_ref()
        .map(|composition| composition.composition_id.as_bytes())
        .or_else(|| {
            record
                .decision_external_evidence
                .as_ref()
                .map(|composition| composition.composition_id.as_bytes())
        });
    let currentness = composition_id.map_or_else(
        || {
            currentness_digest(&[
                record.observation_id.as_bytes(),
                record.support.support_id.as_bytes(),
                record.posture.posture_id.as_bytes(),
            ])
        },
        |composition_id| {
            currentness_digest(&[
                record.observation_id.as_bytes(),
                record.support.support_id.as_bytes(),
                record.posture.posture_id.as_bytes(),
                composition_id,
            ])
        },
    );
    if request.now_unix_ms >= fresh_until_unix_ms {
        return Ok(Classification {
            status: AgObservationStatusV1::Stale,
            basis,
            currentness,
            fresh_until_unix_ms,
        });
    }
    // Domain-scoped supersession under logical slot order. A later qualified
    // observation supersedes even when its own support is weak; `Missed` and
    // unrecovered cycles never qualify. Write/completion order is never used.
    let family = ObservationFamilyKeyV1::of_slot(&cycle.slot);
    let latest = match store.latest_qualified_observation_in_family(&family) {
        Ok(latest) => latest,
        Err(CanonicalStoreError::Invalid(_)) => {
            return Ok(sentinel(AgObservationStatusV1::Contradictory));
        }
        Err(error) => return Err(ObservationResolverError::Store(error)),
    };
    let superseded = latest.as_ref().is_some_and(|latest: &ObservationCycleV1| {
        ObservationOrderKeyV1::of_slot(&latest.slot) > ObservationOrderKeyV1::of_slot(&cycle.slot)
    });
    Ok(Classification {
        status: if superseded {
            AgObservationStatusV1::Superseded
        } else {
            AgObservationStatusV1::Current
        },
        basis,
        currentness,
        fresh_until_unix_ms,
    })
}

/// Resolve one exact AG observation request against the read-only canonical
/// store. Evidence-health answers are returned as statuses; only malformed
/// requests, misconfiguration, and store IO failures are process errors.
pub fn resolve_observation(
    store: &CanonicalStore,
    request: &AgObservationRequestV1,
    config: &ObservationResolverConfigV1,
) -> Result<AgObservationResolutionV2, ObservationResolverError> {
    config
        .validate()
        .map_err(ObservationResolverError::Configuration)?;
    request
        .validate()
        .map_err(ObservationResolverError::Request)?;
    if matches!(request.now_unix_ms, u64::MAX) {
        return Err(ObservationResolverError::Request(
            "now_unix_ms leaves no representable freshness window".into(),
        ));
    }
    let classification = classify(store, request, config)?;
    if classification.status == AgObservationStatusV1::Absent
        || classification.status == AgObservationStatusV1::Contradictory
    {
        return Ok(negative(request, config, classification.status));
    }
    let normalized_preconditions = classification
        .basis
        .digest()
        .expect("normalized posture is a valid v1 basis");
    Ok(AgObservationResolutionV2 {
        schema: AG_OBSERVATION_RESOLUTION_SCHEMA_V2.into(),
        key: request.key.clone(),
        observation: request.observation.clone(),
        currentness: classification.currentness,
        normalized_preconditions,
        basis: classification.basis,
        resolver_id: config.resolver_id.clone(),
        subject: request.subject.clone(),
        status: classification.status,
        resolved_at_unix_ms: request.now_unix_ms,
        fresh_until_unix_ms: classification.fresh_until_unix_ms,
    })
}
