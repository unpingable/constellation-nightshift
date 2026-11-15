//! Shared source-shaped historical read fixtures, not acquired native evidence.
//! Owning types validate structure/identities; this does not reevaluate posture.
use nightshiftd::canonical_store::ObservationCycleV1;
use nightshiftd::currentness::PresentEvidenceQueryV1;
use serde_json::Value;

#[test]
fn shared_monitor_cycle_support_goldens_parse_with_the_owning_types() {
    for raw in [
        include_str!("fixtures/cycle_support_read/current.json"),
        include_str!("fixtures/cycle_support_read/unsupported.json"),
        include_str!("fixtures/cycle_support_read/condition-present.json"),
        include_str!("fixtures/cycle_support_read/unknown.json"),
    ] {
        let value: Value = serde_json::from_str(raw).unwrap();
        let cycle: ObservationCycleV1 = serde_json::from_value(value.clone()).unwrap();
        cycle.validate().unwrap();
        assert_eq!(serde_json::to_value(&cycle).unwrap(), value);
        let support = &cycle.observation.as_ref().unwrap().support;
        let mut query = serde_json::to_value(support).unwrap();
        query.as_object_mut().unwrap().retain(|key, _| {
            [
                "query_id",
                "observation_cycle_id",
                "request_nonce",
                "observation_id",
                "diagnostic_inputs_id",
                "subject_id",
                "scope_id",
                "artifact_ids",
            ]
            .contains(&key.as_str())
        });
        query["schema"] = serde_json::json!("nightshift.present_evidence_query.v1");
        let query: PresentEvidenceQueryV1 = serde_json::from_value(query).unwrap();
        support.validate_for(&query).unwrap();
    }
}
