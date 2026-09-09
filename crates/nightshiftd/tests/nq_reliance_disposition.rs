//! Night Shift's read-only NQ reliance consumer.
//!
//! Two things are under test: that NQ testimony maps to a read-only posture
//! without gaining permissions along the way, and that **Night Shift's own
//! observations never wear NQ's voice**.

use nightshiftd::nq_disposition::{
    derive_disposition, Disposition, NqRelianceReceiptDto, SourceState, EXPECTED_CONSUMER_PROFILE,
    HISTORICAL_NQ_RELIANCE_RECEIPT_SCHEMA,
};

const NOW: &str = "2026-07-26T00:00:00Z";

fn receipt_json(decision: &str, underlying: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": HISTORICAL_NQ_RELIANCE_RECEIPT_SCHEMA,
        "decision_id": "sha256:dddd",
        "request_digest": "sha256:rrrr",
        "evidence_context_digest": "sha256:eeee",
        "consumer_profile_id": EXPECTED_CONSUMER_PROFILE,
        "caller_binding": "configured",
        "caller_binding_disclosure":
            "consumer profile was selected from local configuration; this is not an \
             authenticated consumer identity",
        "purpose": "continue_observing",
        "claim": "docket_attempt_settled",
        "receipt_content_hash": "sha256:cccc",
        "underlying_status": underlying,
        "decision": decision,
        "premises": [],
        "coverage_limits": [],
        "unresolved_residuals": [],
        "retained_contradictions": [],
        "refusal_reasons": [],
        "establishes": [],
        "does_not_establish": ["this decision grants no execution authority"],
        "policy_version": "v1",
        "generated_at": NOW
    })
}

fn parse(v: &serde_json::Value) -> NqRelianceReceiptDto {
    NqRelianceReceiptDto::parse_historical_checked(&serde_json::to_vec(v).unwrap(), EXPECTED_CONSUMER_PROFILE)
        .expect("valid receipt")
}

fn disposition_for(decision: &str, underlying: &str) -> Disposition {
    let dto = parse(&receipt_json(decision, underlying));
    derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    )
    .disposition
}

// 1. fresh authorized reliance
#[test]
fn fresh_authorized_reliance_permits_continued_observation_only() {
    let dto = parse(&receipt_json("authorized_reliance", "verified"));
    let rec = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    assert_eq!(rec.disposition, Disposition::ContinueObserving);
    assert!(!rec.human_judgment_required);
    // It establishes continued *consideration*, never execution.
    assert!(rec
        .does_not_establish
        .iter()
        .any(|d| d.contains("no action was executed or authorized")));
    assert!(rec
        .establishes
        .iter()
        .all(|e| !e.contains("execute") && !e.contains("proceed")));
}

// 2/3. configuration and policy errors stop rather than adapt
#[test]
fn unknown_consumer_and_unauthorized_purpose_stop() {
    assert_eq!(
        disposition_for("consumer_unknown", "verified"),
        Disposition::Stop
    );
    assert_eq!(
        disposition_for("purpose_not_authorized", "verified"),
        Disposition::Stop
    );
    assert_eq!(
        disposition_for("claim_not_authorized_for_consumer", "verified"),
        Disposition::Stop
    );
}

#[test]
fn stop_disposition_does_not_diagnose_why() {
    let unknown_consumer = parse(&receipt_json("consumer_unknown", "verified"));
    let unauthorized_purpose = parse(&receipt_json("purpose_not_authorized", "verified"));

    let consumer_record = derive_disposition(
        &SourceState::Fresh,
        Some(&unknown_consumer),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    let purpose_record = derive_disposition(
        &SourceState::Fresh,
        Some(&unauthorized_purpose),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );

    // The enum is sufficient for the bounded "stop" directive, but it is not
    // sufficient to explain the stop. The full record preserves that split.
    assert_eq!(consumer_record.disposition, Disposition::Stop);
    assert_eq!(purpose_record.disposition, Disposition::Stop);
    assert_ne!(consumer_record.reasons, purpose_record.reasons);
    assert_ne!(
        consumer_record.source.as_ref().unwrap().decision,
        purpose_record.source.as_ref().unwrap().decision
    );
}

// 4. needs_more_evidence is never retry permission
#[test]
fn needs_more_evidence_requests_evidence_and_is_not_a_retry() {
    let dto = parse(&receipt_json("claim_not_verified", "needs_more_evidence"));
    let rec = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    assert_eq!(rec.disposition, Disposition::RequestAdditionalEvidence);
    assert!(rec.required_next_evidence.is_some());
    assert!(rec
        .reasons
        .iter()
        .any(|r| r.contains("not permission to retry")));
    let text = serde_json::to_string(&rec).unwrap();
    assert!(!text.contains("\"retry\""));
}

// 5. cannot_testify is never proceed
#[test]
fn cannot_testify_requires_human_judgment_and_never_proceeds() {
    let dto = parse(&receipt_json("cannot_testify", "verified"));
    let rec = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    assert_eq!(rec.disposition, Disposition::HumanJudgmentRequired);
    assert!(rec.human_judgment_required);
    assert!(rec
        .reasons
        .iter()
        .any(|r| r.contains("inability is not authorization")));
}

// 6. stale receipt
#[test]
fn stale_receipt_waits_and_is_still_nq_testimony() {
    let dto = parse(&receipt_json("authorized_reliance", "verified"));
    let state = SourceState::Stale {
        age_seconds: 5_000,
        max_age_seconds: 900,
    };
    assert!(state.is_nq_testimony());
    let rec = derive_disposition(&state, Some(&dto), NOW, EXPECTED_CONSUMER_PROFILE);
    assert_eq!(rec.disposition, Disposition::WaitForFreshEvidence);
}

// 7. no response — Night Shift's own observation, not an NQ refusal
#[test]
fn no_response_is_night_shifts_observation_and_not_an_nq_verdict() {
    let state = SourceState::NoResponse {
        elapsed_seconds: 30,
        timeout_seconds: 30,
    };
    assert!(!state.is_nq_testimony());
    let rec = derive_disposition(&state, None, NOW, EXPECTED_CONSUMER_PROFILE);
    assert_eq!(rec.disposition, Disposition::EvidenceUnavailable);
    // No fabricated NQ receipt.
    assert!(rec.source.is_none());
    assert!(rec
        .reasons
        .iter()
        .any(|r| r.contains("Night Shift's observation, not NQ testimony")));
    assert!(rec
        .does_not_establish
        .iter()
        .any(|d| d.contains("absence of a response is not evidence of health or of failure")));
    // Never phrased as an NQ conclusion.
    let text = serde_json::to_string(&rec).unwrap();
    assert!(!text.contains("cannot_testify"));
    assert!(!text.contains("claim_not_verified"));
}

// 8. transport unavailable
#[test]
fn transport_unavailable_is_also_night_shifts_observation() {
    let state = SourceState::TransportUnavailable {
        detail: "could not spawn nq-monitor".into(),
    };
    assert!(!state.is_nq_testimony());
    let rec = derive_disposition(&state, None, NOW, EXPECTED_CONSUMER_PROFILE);
    assert_eq!(rec.disposition, Disposition::EvidenceUnavailable);
    assert!(rec.source.is_none());
}

// 9. malformed JSON refuses at the contract boundary
#[test]
fn malformed_and_wrong_schema_receipts_are_refused_before_disposition() {
    assert!(NqRelianceReceiptDto::parse_historical_checked(b"{not json", EXPECTED_CONSUMER_PROFILE).is_err());

    let mut wrong = receipt_json("authorized_reliance", "verified");
    wrong["schema"] = serde_json::json!("nq.reliance.receipt.v99");
    assert!(NqRelianceReceiptDto::parse_historical_checked(
        &serde_json::to_vec(&wrong).unwrap(),
        EXPECTED_CONSUMER_PROFILE
    )
    .is_err());
}

// 10. a receipt addressed to another consumer is refused
#[test]
fn receipt_for_a_different_consumer_is_refused() {
    let mut other = receipt_json("authorized_reliance", "verified");
    other["consumer_profile_id"] = serde_json::json!("operator-review");
    let err = NqRelianceReceiptDto::parse_historical_checked(
        &serde_json::to_vec(&other).unwrap(),
        EXPECTED_CONSUMER_PROFILE,
    )
    .expect_err("must refuse another consumer's receipt");
    assert!(err.to_string().contains("operator-review"));
}

// 11/12/13. premise, contradiction and residual outcomes hold, and the carried
// facts survive into the disposition rather than being summarised away.
#[test]
fn premise_contradiction_and_residual_hold_and_survive() {
    for decision in [
        "premise_not_accepted",
        "contradiction_retained",
        "residual_obligation_blocks",
    ] {
        assert_eq!(
            disposition_for(decision, "verified"),
            Disposition::HumanJudgmentRequired,
            "{decision}"
        );
    }

    let mut v = receipt_json("authorized_reliance", "verified");
    v["premises"] = serde_json::json!(["clock_trusted"]);
    v["retained_contradictions"] = serde_json::json!(["A says committed, B says not"]);
    v["unresolved_residuals"] = serde_json::json!(["upstream review not discharged"]);
    v["coverage_limits"] = serde_json::json!(["source assertions not independently verified"]);
    let dto = parse(&v);
    let rec = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    let src = rec.source.as_ref().unwrap();
    assert_eq!(src.premises, vec!["clock_trusted".to_string()]);
    assert_eq!(src.retained_contradictions.len(), 1);
    assert_eq!(src.unresolved_residuals.len(), 1);
    assert_eq!(src.coverage_limits.len(), 1);
    assert!(rec
        .does_not_establish
        .iter()
        .any(|d| d.contains("remain undischarged")));
    assert!(rec
        .does_not_establish
        .iter()
        .any(|d| d.contains("is not resolved")));
}

// 14/15. source identities preserved verbatim; nothing reinterpreted
#[test]
fn source_identities_are_preserved_verbatim() {
    let v = receipt_json("authorized_reliance", "verified");
    let dto = parse(&v);
    let rec = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    let s = rec.source.as_ref().unwrap();
    assert_eq!(s.decision_id, "sha256:dddd");
    assert_eq!(s.receipt_content_hash, "sha256:cccc");
    assert_eq!(s.request_digest, "sha256:rrrr");
    assert_eq!(s.evidence_context_digest, "sha256:eeee");
    assert_eq!(s.schema, HISTORICAL_NQ_RELIANCE_RECEIPT_SCHEMA);
    assert_eq!(s.decision, "authorized_reliance");
    assert_eq!(s.underlying_status, "verified");
    // The binding disclosure is carried, and never rewritten as authenticated.
    assert!(s.caller_binding_disclosure.contains("not an authenticated"));
    assert!(rec
        .does_not_establish
        .iter()
        .any(|d| d.contains("not an authenticated")));
}

#[test]
fn a_receipt_without_a_binding_disclosure_is_not_consumable() {
    let mut v = receipt_json("authorized_reliance", "verified");
    v["caller_binding_disclosure"] = serde_json::json!("   ");
    assert!(NqRelianceReceiptDto::parse_historical_checked(
        &serde_json::to_vec(&v).unwrap(),
        EXPECTED_CONSUMER_PROFILE
    )
    .is_err());
}

// 16/17. no action, capability, or downstream office is ever emitted
#[test]
fn no_disposition_emits_action_capability_or_touches_another_office() {
    for decision in [
        "authorized_reliance",
        "claim_not_verified",
        "cannot_testify",
        "contradiction_retained",
        "residual_obligation_blocks",
        "consumer_unknown",
        "malformed_request",
    ] {
        let dto = parse(&receipt_json(decision, "verified"));
        let rec = derive_disposition(
            &SourceState::Fresh,
            Some(&dto),
            NOW,
            EXPECTED_CONSUMER_PROFILE,
        );
        let text = serde_json::to_string(&rec).unwrap();
        for forbidden in [
            "\"capability\"",
            "\"lease\"",
            "\"grant\"",
            "\"execute\"",
            "\"authorization_request\"",
            "docket_standing",
            "ag_authorization",
            "git_push",
        ] {
            assert!(
                !text.contains(forbidden),
                "{decision} disposition must not carry {forbidden}"
            );
        }
        assert!(rec
            .does_not_establish
            .iter()
            .any(|d| d.contains("not execution authority")));
    }
}

// 18/19. identity behaviour
#[test]
fn duplicate_input_is_idempotent_and_a_changed_receipt_changes_the_record() {
    let a = parse(&receipt_json("authorized_reliance", "verified"));
    let r1 = derive_disposition(
        &SourceState::Fresh,
        Some(&a),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    let r2 = derive_disposition(
        &SourceState::Fresh,
        Some(&a),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    assert_eq!(
        serde_json::to_string(&r1).unwrap(),
        serde_json::to_string(&r2).unwrap()
    );

    let mut changed = receipt_json("authorized_reliance", "verified");
    changed["decision_id"] = serde_json::json!("sha256:9999");
    let b = parse(&changed);
    let r3 = derive_disposition(
        &SourceState::Fresh,
        Some(&b),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    assert_ne!(
        serde_json::to_string(&r1).unwrap(),
        serde_json::to_string(&r3).unwrap()
    );
    assert_eq!(r3.source.as_ref().unwrap().decision_id, "sha256:9999");
}

// 20. deriving a disposition mutates no NQ evidence
#[test]
fn deriving_a_disposition_does_not_mutate_the_source() {
    let v = receipt_json("authorized_reliance", "verified");
    let before = serde_json::to_vec(&v).unwrap();
    let dto = parse(&v);
    let _ = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    let _ = derive_disposition(
        &SourceState::Fresh,
        Some(&dto),
        NOW,
        EXPECTED_CONSUMER_PROFILE,
    );
    assert_eq!(before, serde_json::to_vec(&v).unwrap());
}
