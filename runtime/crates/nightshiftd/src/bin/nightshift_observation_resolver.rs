//! Read-only Nightshift observation resolver for AG's frozen
//! `ag.governed-loop.observation-resolution/v2` boundary.
//!
//! One-shot process contract: read one exact AG observation request from
//! stdin, write exactly one canonical resolution JSON document to stdout,
//! exit 0. Malformed requests, misconfiguration, and store IO failures exit
//! non-zero with a diagnostic on stderr; they are never encoded as evidence
//! statuses. This binary opens the canonical store strictly read-only and
//! has no cycle-mutation, lease, AG, Docket, or executor surface.

use std::io::Read as _;
use std::path::PathBuf;

use anyhow::{bail, Context as _};
use clap::Parser;

use nightshiftd::canonical_store::AgOccurrenceReferenceV1;
use nightshiftd::canonical_store::CanonicalStore;
use nightshiftd::observation_resolver::{
    resolve_observation, AgObservationRequestV1, ObservationResolverConfigV1,
};
use nightshiftd::repository_qualification::{
    QualificationApplicabilityOutcomeV1, QualificationApplicabilityProfileV1,
    QualificationReceiptStoreV1,
};
use nightshiftd::reservation_qualification::{
    ReservationApplicabilityOutcomeV1, ReservationApplicabilityProfileV1,
    ReservationRealizationStoreV1,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(
    name = "nightshift-observation-resolver",
    version,
    about = "Read-only Nightshift observation-evidence resolver for AG"
)]
struct Arguments {
    /// Canonical Nightshift store, opened strictly read-only.
    #[arg(long)]
    store: PathBuf,
    /// Exact resolver identity AG is configured to expect.
    #[arg(long)]
    resolver_id: String,
    /// Bounded evidence window: fresh_until = evaluated_at + this TTL.
    #[arg(long)]
    default_ttl_ms: u64,
    /// Exact Q3 applicability/source/receipt binding. When present, `store`
    /// is the repository-qualification receipt store and generic resolution
    /// is disabled.
    #[arg(long)]
    repository_qualification_binding: Option<PathBuf>,
    /// Exact reservation realization/source binding. Mutually exclusive with
    /// the V1 repository-qualification binding.
    #[arg(long)]
    reservation_qualification_binding: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryQualificationResolverBindingV0 {
    schema: String,
    applicability: QualificationApplicabilityProfileV1,
    source: AgOccurrenceReferenceV1,
    receipt_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationQualificationResolverBindingV1 {
    schema: String,
    applicability: ReservationApplicabilityProfileV1,
    source: AgOccurrenceReferenceV1,
}
fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("read observation request from stdin")?;
    let request: AgObservationRequestV1 =
        serde_json::from_str(&input).context("parse observation request")?;
    request.validate().map_err(anyhow::Error::msg)?;
    if arguments.repository_qualification_binding.is_some()
        && arguments.reservation_qualification_binding.is_some()
    {
        bail!("qualification resolver bindings are mutually exclusive");
    }
    let body = if let Some(binding_path) = arguments.reservation_qualification_binding {
        let binding_bytes = std::fs::read(&binding_path)
            .with_context(|| format!("read {}", binding_path.display()))?;
        let binding: ReservationQualificationResolverBindingV1 =
            serde_json::from_slice(&binding_bytes).context("parse reservation binding")?;
        if serde_jcs::to_vec(&binding).context("canonicalize reservation binding")? != binding_bytes
        {
            bail!("reservation qualification binding must be exact canonical JSON");
        }
        if binding.schema != "nightshift.repository-qualification-reservation-resolver-binding/v1"
            || binding.applicability.resolver_id != arguments.resolver_id
        {
            bail!("reservation qualification resolver binding/identity mismatch");
        }
        let key = request
            .key
            .as_object()
            .context("AG occurrence key must be an object")?;
        if key.len() != 2 {
            bail!("AG occurrence key must contain exactly campaign and occurrence");
        }
        let target_campaign = key
            .get("campaign")
            .and_then(serde_json::Value::as_str)
            .context("AG occurrence key has no campaign")?;
        let target_occurrence = key
            .get("occurrence")
            .and_then(serde_json::Value::as_str)
            .context("AG occurrence key has no occurrence")?;
        let store = ReservationRealizationStoreV1::open_read_only(&arguments.store)
            .map_err(anyhow::Error::msg)
            .context("open reservation realization store read-only")?;
        match store
            .resolve_applicability(
                &binding.applicability,
                &binding.source,
                target_campaign,
                target_occurrence,
                &request.observation,
                &request.subject,
                request.now_unix_ms,
            )
            .map_err(anyhow::Error::msg)?
        {
            ReservationApplicabilityOutcomeV1::Observation(resolution) => {
                serde_jcs::to_vec(&resolution).context("canonicalize reservation resolution")?
            }
            ReservationApplicabilityOutcomeV1::RetainedOnly { .. }
            | ReservationApplicabilityOutcomeV1::Absent => {
                bail!("reservation has no unique current qualified realization")
            }
        }
    } else if let Some(binding_path) = arguments.repository_qualification_binding {
        let binding_bytes = std::fs::read(&binding_path)
            .with_context(|| format!("read {}", binding_path.display()))?;
        let binding: RepositoryQualificationResolverBindingV0 =
            serde_json::from_slice(&binding_bytes).context("parse qualification binding")?;
        if serde_jcs::to_vec(&binding).context("canonicalize qualification binding")?
            != binding_bytes
        {
            bail!("repository qualification binding must be exact canonical JSON");
        }
        if binding.schema != "nightshift.repository-qualification-resolver-binding/v0"
            || binding.applicability.resolver_id != arguments.resolver_id
        {
            bail!("repository qualification resolver binding/identity mismatch");
        }
        let key = request
            .key
            .as_object()
            .context("AG occurrence key must be an object")?;
        if key.len() != 2 {
            bail!("AG occurrence key must contain exactly campaign and occurrence");
        }
        let target_campaign = key
            .get("campaign")
            .and_then(serde_json::Value::as_str)
            .context("AG occurrence key has no campaign")?;
        let target_occurrence = key
            .get("occurrence")
            .and_then(serde_json::Value::as_str)
            .context("AG occurrence key has no occurrence")?;
        let store = QualificationReceiptStoreV1::open_read_only(&arguments.store)
            .map_err(anyhow::Error::msg)
            .context("open qualification receipt store read-only")?;
        match store
            .resolve_applicability(
                &binding.applicability,
                &binding.source,
                &binding.receipt_id,
                target_campaign,
                target_occurrence,
                &request.observation,
                &request.subject,
                request.now_unix_ms,
            )
            .map_err(anyhow::Error::msg)?
        {
            QualificationApplicabilityOutcomeV1::Observation(resolution) => {
                serde_jcs::to_vec(&resolution).context("canonicalize qualification resolution")?
            }
            QualificationApplicabilityOutcomeV1::RetainedOnly { .. } => {
                bail!("retained qualification status is not an AG-current observation")
            }
        }
    } else {
        let config = ObservationResolverConfigV1 {
            resolver_id: arguments.resolver_id,
            default_ttl_ms: arguments.default_ttl_ms,
        };
        let store = CanonicalStore::open_read_only(&arguments.store)
            .context("open canonical store read-only")?;
        let resolution = resolve_observation(&store, &request, &config)
            .map_err(anyhow::Error::new)
            .context("resolve observation")?;
        serde_jcs::to_vec(&resolution).context("canonicalize resolution")?
    };
    let body = String::from_utf8(body).context("resolution is UTF-8")?;
    if body.contains('\n') {
        bail!("canonical resolution must be a single JSON line");
    }
    println!("{body}");
    Ok(())
}
