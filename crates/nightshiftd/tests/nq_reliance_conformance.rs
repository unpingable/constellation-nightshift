//! Historical consumer conformance against archived NQ classic golden vectors.
//! No current parser fallback or fixture regeneration dependency is implied.
//!
//! The fixtures under `tests/fixtures/nq_reliance/` are `nq.reliance.receipt.v1`
//! documents **produced by NQ** — emitted by `nq-monitor reliance evaluate` over
//! NQ's own golden vectors. Night Shift verifies them independently here: no
//! shared library guarantees agreement, and none of NQ's evaluator is copied
//! into this repository.
//!
//! Two properties are under test:
//!
//! 1. Night Shift accepts what it should and **refuses what it should**,
//!    including receipts addressed to a different consumer.
//! 2. Every accepted receipt maps to a read-only posture that grants nothing.

use std::collections::BTreeMap;

use nightshiftd::nq_disposition::{
    derive_disposition, Disposition, NqRelianceReceiptDto, SourceState, EXPECTED_CONSUMER_PROFILE,
};

const NOW: &str = "2026-07-26T00:00:00Z";

fn fixtures() -> BTreeMap<String, Vec<u8>> {
    let dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nq_reliance");
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("fixture dir") {
        let p = entry.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) == Some("json") {
            let name = p.file_stem().unwrap().to_string_lossy().to_string();
            out.insert(name, std::fs::read(&p).unwrap());
        }
    }
    assert!(!out.is_empty(), "fixtures must exist");
    out
}

/// Receipts addressed to `nightshift-readonly`, and the posture each must yield.
fn expected_for_this_consumer() -> BTreeMap<&'static str, Disposition> {
    BTreeMap::from([
        (
            "valid_reliance_nightshift_readonly",
            Disposition::ContinueObserving,
        ),
        ("contradiction_retained", Disposition::HumanJudgmentRequired),
        ("premise_not_accepted", Disposition::HumanJudgmentRequired),
        (
            "residual_blocks_reliance",
            Disposition::HumanJudgmentRequired,
        ),
        (
            "custody_basis_not_accepted",
            Disposition::HumanJudgmentRequired,
        ),
        ("unauthorized_claim", Disposition::Stop),
        ("unauthorized_purpose", Disposition::Stop),
    ])
}

#[test]
fn nq_golden_vectors_addressed_to_this_consumer_map_to_the_expected_posture() {
    let fx = fixtures();
    for (name, expected) in expected_for_this_consumer() {
        let bytes = fx
            .get(name)
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        let dto = NqRelianceReceiptDto::parse_historical_checked(bytes, EXPECTED_CONSUMER_PROFILE)
            .unwrap_or_else(|e| panic!("{name} must parse: {e}"));
        let rec = derive_disposition(
            &SourceState::Fresh,
            Some(&dto),
            NOW,
            EXPECTED_CONSUMER_PROFILE,
        );
        assert_eq!(rec.disposition, expected, "{name}");
    }
}

#[test]
fn receipts_addressed_to_another_consumer_are_refused_not_reinterpreted() {
    let fx = fixtures();
    // These NQ vectors are real and valid — they are simply not ours.
    for name in [
        "valid_operational_health_reliance",
        "cannot_testify_is_not_authorization",
        "safe_to_merge_has_no_consumer",
        "recursive_self_witness_attempt",
        "stale_health_packet",
        "substituted_health_packet",
        "unknown_consumer",
    ] {
        let bytes = fx
            .get(name)
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        let err = NqRelianceReceiptDto::parse_historical_checked(bytes, EXPECTED_CONSUMER_PROFILE)
            .err()
            .unwrap_or_else(|| panic!("{name} is not addressed to this consumer and must refuse"));
        assert!(
            err.to_string().contains("consumer"),
            "{name}: refusal must name the consumer mismatch, got {err}"
        );
    }
}

#[test]
fn no_accepted_vector_yields_an_action_or_capability() {
    let fx = fixtures();
    for name in expected_for_this_consumer().keys() {
        let dto =
            NqRelianceReceiptDto::parse_historical_checked(&fx[*name], EXPECTED_CONSUMER_PROFILE).unwrap();
        let rec = derive_disposition(
            &SourceState::Fresh,
            Some(&dto),
            NOW,
            EXPECTED_CONSUMER_PROFILE,
        );
        let text = serde_json::to_string(&rec).unwrap();
        for forbidden in ["\"capability\"", "\"lease\"", "\"execute\"", "\"retry\""] {
            assert!(
                !text.contains(forbidden),
                "{name} must not carry {forbidden}"
            );
        }
        assert!(rec
            .does_not_establish
            .iter()
            .any(|d| d.contains("no action was executed or authorized")));
    }
}

#[test]
fn carried_facts_survive_every_accepted_vector() {
    let fx = fixtures();
    // The three vectors that carry premises, contradictions, and residuals.
    for (name, field) in [
        ("premise_not_accepted", "premises"),
        ("contradiction_retained", "retained_contradictions"),
        ("residual_blocks_reliance", "unresolved_residuals"),
    ] {
        let raw: serde_json::Value = serde_json::from_slice(&fx[name]).unwrap();
        let source_len = raw[field].as_array().map_or(0, Vec::len);
        let dto =
            NqRelianceReceiptDto::parse_historical_checked(&fx[name], EXPECTED_CONSUMER_PROFILE).unwrap();
        let rec = derive_disposition(
            &SourceState::Fresh,
            Some(&dto),
            NOW,
            EXPECTED_CONSUMER_PROFILE,
        );
        let carried = serde_json::to_value(rec.source.as_ref().unwrap()).unwrap();
        assert_eq!(
            carried[field].as_array().map_or(0, Vec::len),
            source_len,
            "{name}: {field} must survive the projection unchanged"
        );
    }
}

/// The no-response case is a Night Shift event with no NQ receipt behind it,
/// and there is deliberately no fixture for it — a fixture would be a
/// fabricated NQ document.
#[test]
fn the_no_response_case_has_no_nq_fixture_because_it_is_not_an_nq_document() {
    let fx = fixtures();
    for bytes in fx.values() {
        let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(v["schema"], "nq.reliance.receipt.v1");
    }
    let rec = derive_disposition(
        &SourceState::NoResponse {
            elapsed_seconds: 30,
            timeout_seconds: 30,
        },
        None,
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    assert_eq!(rec.disposition, Disposition::EvidenceUnavailable);
    assert!(rec.source.is_none());
}

// ---------------------------------------------------------------------------
// Continuity-gated consumer vectors (2026-07-26).
//
// NQ's supporting-evaluation vectors, mirrored byte-wise as always. The same
// consumer machinery reads them under the `nightshift-readonly-continuity`
// expectation — a *configured* expectation, never an ambient one; under the
// base expectation these receipts refuse unparsed.
// ---------------------------------------------------------------------------

const CONTINUITY_CONSUMER: &str = "nightshift-readonly-continuity";
const DOCKET_PRIMARY_SUBJECT: &str = "gwr:ref-continuity:v0:repo-0123456789abcdef0123456789abcdef\
     #refs/gwr/target@2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";

/// Receipts addressed to the continuity-gated consumer, and the posture each
/// must yield. No new mapping law: these arrive through NQ's closed decision
/// vocabulary exactly as the base vectors do.
fn expected_for_continuity_consumer() -> BTreeMap<&'static str, Disposition> {
    BTreeMap::from([
        (
            "continuity_gated_authorized",
            Disposition::ContinueObserving,
        ),
        (
            "continuity_support_missing",
            Disposition::HumanJudgmentRequired,
        ),
        (
            "continuity_support_lost",
            Disposition::HumanJudgmentRequired,
        ),
        (
            "continuity_support_stale",
            Disposition::WaitForFreshEvidence,
        ),
        (
            "docket_primary_continuity_gated_authorized",
            Disposition::ContinueObserving,
        ),
    ])
}

#[test]
fn continuity_vectors_map_to_the_expected_posture_under_the_continuity_expectation() {
    let fx = fixtures();
    for (name, expected) in expected_for_continuity_consumer() {
        let bytes = fx
            .get(name)
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        let dto = NqRelianceReceiptDto::parse_historical_checked(bytes, CONTINUITY_CONSUMER)
            .unwrap_or_else(|e| panic!("{name} must parse: {e}"));
        let rec = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_CONSUMER);
        assert_eq!(rec.disposition, expected, "{name}");
        assert_eq!(rec.expected_consumer_profile, CONTINUITY_CONSUMER, "{name}");
    }
}

#[test]
fn continuity_vectors_refuse_under_the_base_expectation() {
    let fx = fixtures();
    for name in expected_for_continuity_consumer().keys() {
        let err = NqRelianceReceiptDto::parse_historical_checked(&fx[*name], EXPECTED_CONSUMER_PROFILE)
            .err()
            .unwrap_or_else(|| panic!("{name} is not addressed to the base consumer"));
        assert!(
            err.to_string().contains("consumer"),
            "{name}: refusal must name the consumer mismatch, got {err}"
        );
    }
}

#[test]
fn the_authorized_continuity_vector_disclosure_survives_the_projection() {
    let fx = fixtures();
    let raw: serde_json::Value =
        serde_json::from_slice(&fx["continuity_gated_authorized"]).unwrap();
    let source_refs = raw["supporting_receipts"].as_array().unwrap();
    assert_eq!(source_refs.len(), 1, "the vector binds one supporting eval");

    let dto = NqRelianceReceiptDto::parse_historical_checked(
        &fx["continuity_gated_authorized"],
        CONTINUITY_CONSUMER,
    )
    .unwrap();
    let rec = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_CONSUMER);
    let carried = &rec.source.as_ref().unwrap().supporting_receipts;
    assert_eq!(carried.len(), 1);
    assert_eq!(carried[0].claim, source_refs[0]["claim"]);
    assert_eq!(carried[0].content_hash, source_refs[0]["content_hash"]);
    assert_eq!(carried[0].subject, source_refs[0]["subject"]);
}

#[test]
fn docket_primary_logical_subject_disclosure_survives_the_projection_unchanged() {
    let fx = fixtures();
    let raw: serde_json::Value =
        serde_json::from_slice(&fx["docket_primary_continuity_gated_authorized"]).unwrap();
    assert_eq!(raw["claim"], "docket_attempt_settled");
    assert_eq!(raw["decision"], "authorized_reliance");
    let raw_support = raw["supporting_receipts"]
        .as_array()
        .expect("NQ supporting disclosure");
    assert_eq!(raw_support.len(), 1);
    assert_eq!(raw_support[0]["claim"], "continuity_rely_eligible");
    assert_eq!(raw_support[0]["subject"], DOCKET_PRIMARY_SUBJECT);

    let dto = NqRelianceReceiptDto::parse_historical_checked(
        &fx["docket_primary_continuity_gated_authorized"],
        CONTINUITY_CONSUMER,
    )
    .unwrap();
    assert_eq!(dto.supporting_receipts[0].subject, DOCKET_PRIMARY_SUBJECT);

    let rec = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_CONSUMER);
    assert_eq!(rec.disposition, Disposition::ContinueObserving);
    let carried = rec.source.as_ref().expect("fresh NQ source binding");
    assert_eq!(carried.claim, "docket_attempt_settled");
    assert_eq!(
        carried.receipt_content_hash,
        raw["receipt_content_hash"].as_str().unwrap()
    );
    assert_eq!(carried.supporting_receipts.len(), 1);
    assert_eq!(
        carried.supporting_receipts[0].subject,
        DOCKET_PRIMARY_SUBJECT
    );
    assert_eq!(
        carried.supporting_receipts[0].subject,
        raw_support[0]["subject"].as_str().unwrap()
    );
}

#[test]
fn missing_support_refusal_stays_disclosure_free_and_distinct_from_no_response() {
    // The missing-support refusal binds nothing; its source binding must not
    // grow a supporting_receipts key (absent-when-empty, byte-compatible).
    let fx = fixtures();
    let dto =
        NqRelianceReceiptDto::parse_historical_checked(&fx["continuity_support_missing"], CONTINUITY_CONSUMER)
            .unwrap();
    let rec = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_CONSUMER);
    let json = serde_json::to_value(&rec).unwrap();
    assert!(json["source"].get("supporting_receipts").is_none());
    assert!(rec.source_state.is_nq_testimony());
    assert_eq!(rec.disposition, Disposition::HumanJudgmentRequired);
    assert!(rec.source.is_some());

    let silent = derive_disposition(
        &SourceState::NoResponse {
            elapsed_seconds: 30,
            timeout_seconds: 30,
        },
        None,
        NOW,
        CONTINUITY_CONSUMER,
    );
    assert!(!silent.source_state.is_nq_testimony());
    assert_eq!(silent.disposition, Disposition::EvidenceUnavailable);
    assert!(silent.source.is_none());
}
