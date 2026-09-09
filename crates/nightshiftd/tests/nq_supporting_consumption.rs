//! Supporting-evaluation consumption (2026-07-26 extension).
//!
//! NQ owns all supporting-evaluation law. What is under test here is only
//! Night Shift's side of the contract: disclosed supporting identities survive into the
//! source binding unmodified, the expected consumer profile is an explicit
//! parameter rather than an ambient assumption, and **missing support (NQ
//! testimony) never blurs into no response (Night Shift's own observation)**.

use nightshiftd::nq_disposition::{
    derive_disposition, Disposition, NqRelianceReceiptDto, SourceState, EXPECTED_CONSUMER_PROFILE,
    HISTORICAL_NQ_RELIANCE_RECEIPT_SCHEMA,
};

const NOW: &str = "2026-07-26T00:00:00Z";
const CONTINUITY_PROFILE: &str = "nightshift-readonly-continuity";

fn receipt_json(profile: &str, decision: &str, supporting: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema": HISTORICAL_NQ_RELIANCE_RECEIPT_SCHEMA,
        "decision_id": "sha256:dddd",
        "request_digest": "sha256:rrrr",
        "evidence_context_digest": "sha256:eeee",
        "consumer_profile_id": profile,
        "caller_binding": "configured",
        "caller_binding_disclosure":
            "consumer profile was selected from local configuration; this is not an \
             authenticated consumer identity",
        "purpose": "continue_observing",
        "claim": "docket_attempt_settled",
        "receipt_content_hash": "sha256:cccc",
        "underlying_status": "verified",
        "decision": decision,
        "premises": [],
        "coverage_limits": [],
        "unresolved_residuals": [],
        "retained_contradictions": [],
        "refusal_reasons": [],
        "establishes": [],
        "does_not_establish": ["this decision grants no execution authority"],
        "supporting_receipts": supporting,
        "policy_version": "v1",
        "generated_at": NOW
    })
}

fn supporting_ref() -> serde_json::Value {
    serde_json::json!([{
        "claim": "continuity_rely_eligible",
        "content_hash": "sha256:ssss",
        "status": "verified",
        "subject": "continuity-record:mem-1@2026-07-26T00:00:00Z"
    }])
}

// --- the DTO parses disclosure without judging it ---------------------------

#[test]
fn supporting_refs_parse_and_are_preserved_in_order() {
    let two = serde_json::json!([
        {"claim": "continuity_rely_eligible", "content_hash": "sha256:s1",
         "status": "verified", "subject": "a"},
        {"claim": "docket_attempt_settled", "content_hash": "sha256:s2",
         "status": "verified", "subject": "b"},
    ]);
    let v = receipt_json(CONTINUITY_PROFILE, "authorized_reliance", two);
    let dto =
        NqRelianceReceiptDto::parse_historical_checked(&serde_json::to_vec(&v).unwrap(), CONTINUITY_PROFILE)
            .unwrap();
    assert_eq!(dto.supporting_receipts.len(), 2);
    assert_eq!(dto.supporting_receipts[0].content_hash, "sha256:s1");
    assert_eq!(dto.supporting_receipts[1].content_hash, "sha256:s2");
}

#[test]
fn a_receipt_without_supporting_refs_still_parses() {
    // Pre-extension receipts have no supporting_receipts key at all.
    let mut v = receipt_json(
        EXPECTED_CONSUMER_PROFILE,
        "authorized_reliance",
        serde_json::json!([]),
    );
    v.as_object_mut().unwrap().remove("supporting_receipts");
    let dto = NqRelianceReceiptDto::parse_historical_checked(
        &serde_json::to_vec(&v).unwrap(),
        EXPECTED_CONSUMER_PROFILE,
    )
    .unwrap();
    assert!(dto.supporting_receipts.is_empty());
}

#[test]
fn an_unidentifiable_supporting_disclosure_is_malformed() {
    for broken in [
        serde_json::json!([{"claim": "", "content_hash": "sha256:s1", "status": "verified", "subject": "a"}]),
        serde_json::json!([{"claim": "c", "content_hash": "", "status": "verified", "subject": "a"}]),
    ] {
        let v = receipt_json(CONTINUITY_PROFILE, "authorized_reliance", broken);
        assert!(NqRelianceReceiptDto::parse_historical_checked(
            &serde_json::to_vec(&v).unwrap(),
            CONTINUITY_PROFILE
        )
        .is_err());
    }
}

// --- the expected profile is a parameter, not an assumption ------------------

#[test]
fn a_continuity_receipt_is_refused_under_the_base_expectation() {
    let v = receipt_json(CONTINUITY_PROFILE, "authorized_reliance", supporting_ref());
    let err = NqRelianceReceiptDto::parse_historical_checked(
        &serde_json::to_vec(&v).unwrap(),
        EXPECTED_CONSUMER_PROFILE,
    )
    .unwrap_err();
    assert!(err.to_string().contains(CONTINUITY_PROFILE));
}

#[test]
fn a_continuity_receipt_is_accepted_under_the_continuity_expectation() {
    let v = receipt_json(CONTINUITY_PROFILE, "authorized_reliance", supporting_ref());
    let dto =
        NqRelianceReceiptDto::parse_historical_checked(&serde_json::to_vec(&v).unwrap(), CONTINUITY_PROFILE)
            .unwrap();
    assert_eq!(dto.consumer_profile_id, CONTINUITY_PROFILE);
}

#[test]
fn a_base_receipt_is_refused_under_the_continuity_expectation() {
    let v = receipt_json(
        EXPECTED_CONSUMER_PROFILE,
        "authorized_reliance",
        serde_json::json!([]),
    );
    assert!(NqRelianceReceiptDto::parse_historical_checked(
        &serde_json::to_vec(&v).unwrap(),
        CONTINUITY_PROFILE
    )
    .is_err());
}

// --- disclosure survives into the disposition unmodified ---------------------

#[test]
fn supporting_identities_ride_the_source_binding_verbatim() {
    let v = receipt_json(CONTINUITY_PROFILE, "authorized_reliance", supporting_ref());
    let dto =
        NqRelianceReceiptDto::parse_historical_checked(&serde_json::to_vec(&v).unwrap(), CONTINUITY_PROFILE)
            .unwrap();
    let rec = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_PROFILE);
    let bound = &rec.source.as_ref().unwrap().supporting_receipts;
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].claim, "continuity_rely_eligible");
    assert_eq!(bound[0].content_hash, "sha256:ssss");
    assert_eq!(bound[0].status, "verified");
    assert_eq!(rec.expected_consumer_profile, CONTINUITY_PROFILE);
    assert_eq!(rec.disposition, Disposition::ContinueObserving);
}

#[test]
fn a_binding_without_supporting_refs_serializes_without_the_key() {
    let v = receipt_json(
        EXPECTED_CONSUMER_PROFILE,
        "authorized_reliance",
        serde_json::json!([]),
    );
    let dto = NqRelianceReceiptDto::parse_historical_checked(
        &serde_json::to_vec(&v).unwrap(),
        EXPECTED_CONSUMER_PROFILE,
    )
    .unwrap();
    let rec = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    let json = serde_json::to_value(&rec).unwrap();
    assert!(json["source"].get("supporting_receipts").is_none());
}

// --- the disposition names itself deterministically --------------------------

#[test]
fn disposition_id_is_deterministic_and_input_sensitive() {
    let v = receipt_json(CONTINUITY_PROFILE, "authorized_reliance", supporting_ref());
    let dto =
        NqRelianceReceiptDto::parse_historical_checked(&serde_json::to_vec(&v).unwrap(), CONTINUITY_PROFILE)
            .unwrap();
    let r1 = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_PROFILE);
    let r2 = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_PROFILE);
    assert!(r1.disposition_id.starts_with("sha256:"));
    assert_eq!(r1.disposition_id, r2.disposition_id);
    let r3 = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        "2026-07-26T00:00:01Z",
        CONTINUITY_PROFILE,
    );
    assert_ne!(r1.disposition_id, r3.disposition_id);
}

#[test]
fn disposition_id_matches_recomputation_over_the_emitted_record() {
    use sha2::{Digest, Sha256};
    let v = receipt_json(CONTINUITY_PROFILE, "authorized_reliance", supporting_ref());
    let dto =
        NqRelianceReceiptDto::parse_historical_checked(&serde_json::to_vec(&v).unwrap(), CONTINUITY_PROFILE)
            .unwrap();
    let rec = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_PROFILE);
    let mut probe = serde_json::to_value(&rec).unwrap();
    probe["disposition_id"] = serde_json::Value::String(String::new());
    let canonical = serde_jcs::to_string(&probe).unwrap();
    let expected = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
    assert_eq!(rec.disposition_id, expected);
}

// --- missing support is NQ testimony; no response is not -------------------

#[test]
fn missing_support_and_no_response_never_blur() {
    // NQ *decided* that coverage is insufficient (e.g. required supporting
    // claims absent). That is fresh NQ testimony carrying a refusal.
    let v = receipt_json(
        CONTINUITY_PROFILE,
        "coverage_insufficient",
        serde_json::json!([]),
    );
    let dto =
        NqRelianceReceiptDto::parse_historical_checked(&serde_json::to_vec(&v).unwrap(), CONTINUITY_PROFILE)
            .unwrap();
    let refused = derive_disposition(&SourceState::Fresh, Some(&dto), NOW, CONTINUITY_PROFILE);
    assert!(refused.source_state.is_nq_testimony());
    assert_eq!(refused.disposition, Disposition::HumanJudgmentRequired);
    assert!(refused.source.is_some());

    // NQ said *nothing*. That is Night Shift's own observation, no NQ voice.
    let silent = derive_disposition(
        &SourceState::NoResponse {
            elapsed_seconds: 30,
            timeout_seconds: 30,
        },
        None,
        NOW,
        CONTINUITY_PROFILE,
    );
    assert!(!silent.source_state.is_nq_testimony());
    assert_eq!(silent.disposition, Disposition::EvidenceUnavailable);
    assert!(silent.source.is_none());
    assert!(silent
        .does_not_establish
        .iter()
        .any(|s| s.contains("absence of a response is not evidence")));
}
