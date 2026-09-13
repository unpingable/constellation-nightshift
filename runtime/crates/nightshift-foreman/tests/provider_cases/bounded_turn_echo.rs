//! Independently constructed source-shaped substitution cases; no provider contact.
use super::*;

const RECORD_DOMAIN: &[u8] = b"switchyard.codex-provider-admission-evidence.digest/v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"switchyard.codex-provider-admission-snapshot.digest/v1\0";

fn set_raw(record: &mut Value, wire: Vec<u8>) {
    record["raw"]["byte_length"] = json!(wire.len());
    record["raw"]["sha256"] = json!(format!("sha256:{:x}", Sha256::digest(&wire)));
    record["raw"]["bytes_hex"] = json!(hex::encode(wire));
    *record = holding_seal_value(record.clone(), "evidence_digest", RECORD_DOMAIN);
}

fn wire(record: &Value) -> Value {
    serde_json::from_slice(&hex::decode(record["raw"]["bytes_hex"].as_str().unwrap()).unwrap())
        .unwrap()
}

fn change(snapshot: &Value, index: usize, edit: impl FnOnce(&mut Value)) -> Value {
    let mut changed = snapshot.clone();
    let record = &mut changed["records"][index];
    let mut value = wire(record);
    edit(&mut value);
    if record["acquisition_kind"] == "CLIENT_REQUEST" {
        record["method"] = json!(format!(
            "client-request/{}",
            value["method"].as_str().unwrap()
        ));
    } else {
        record["method"] = value["method"].clone();
    }
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    set_raw(record, bytes);
    holding_seal_value(changed, "snapshot_digest", SNAPSHOT_DOMAIN)
}

fn expanded_vector() -> Value {
    let vector: Value =
        serde_json::from_slice(include_bytes!("bounded-turn-echo-synthetic.json")).unwrap();
    assert_eq!(vector["qualification"], "SYNTHETIC_NO_PROVIDER_CONTACT");
    let mut snapshot = vector["compact_snapshot"].clone();
    let original =
        hex::decode(snapshot["records"][0]["raw"]["bytes_hex"].as_str().unwrap()).unwrap();
    let input = "S".repeat(118500 - original.len());
    let escaped_output = "\\u0000".repeat(32768);
    for (index, record) in snapshot["records"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        if record["raw"].is_null() {
            continue;
        }
        let raw =
            String::from_utf8(hex::decode(record["raw"]["bytes_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let expanded = match index {
            0 | 2 | 3 => raw.replacen("\"text\":\"\"", &format!("\"text\":\"{input}\""), 1),
            8 => raw.replacen(
                "\"delta\":\"\"",
                &format!("\"delta\":\"{escaped_output}\""),
                1,
            ),
            9 | 10 => raw.replacen(
                "\"text\":\"\"",
                &format!("\"text\":\"{escaped_output}\""),
                1,
            ),
            _ => raw,
        };
        set_raw(record, expanded.into_bytes());
    }
    let request = wire(&snapshot["records"][0]);
    let params_digest = json!(format!(
        "sha256:{:x}",
        Sha256::digest(holding_canonical(&request["params"]))
    ));
    for index in [0, 1] {
        snapshot["records"][index]["normalized"]["params_sha256"] = params_digest.clone();
        snapshot["records"][index] = holding_seal_value(
            snapshot["records"][index].clone(),
            "evidence_digest",
            RECORD_DOMAIN,
        );
    }
    snapshot = holding_seal_value(snapshot, "snapshot_digest", SNAPSHOT_DOMAIN);
    assert_eq!(
        snapshot["snapshot_digest"],
        vector["expected_snapshot_digest"]
    );
    assert_eq!(holding_canonical(&snapshot).len(), 1_908_318);
    snapshot
}

#[test]
fn bounded_turn_echo_cross_language_vector_is_exact() {
    let snapshot = expanded_vector();
    let sizes: Vec<_> = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|record| record["raw"]["byte_length"].as_u64())
        .collect();
    assert_eq!(
        sizes,
        [118500, 53, 118606, 118610, 249, 282, 155, 240, 196756, 196852, 196959]
    );
    assert_eq!(
        wire(&snapshot["records"][9])["params"]["item"]["text"]
            .as_str()
            .unwrap()
            .len(),
        32768
    );
}

#[test]
fn bounded_turn_echo_native_intake_replays_full_echo_and_output_custody() {
    let snapshot = expanded_vector();
    let negatives = vec![
        change(&snapshot, 2, |value| {
            value["params"]["item"]["content"][0]["text"] = json!("replacement".repeat(12000))
        }),
        change(&snapshot, 2, |value| {
            value["params"]["item"]["content"][0]["text_elements"] = json!([{}])
        }),
        change(&snapshot, 2, |value| {
            value["params"]["threadId"] = json!("different-thread")
        }),
        change(&snapshot, 3, |value| {
            value["params"]["turnId"] = json!("different-turn")
        }),
        change(&snapshot, 3, |value| {
            value["method"] = json!("item/started");
            let tick = value["params"]
                .as_object_mut()
                .unwrap()
                .remove("completedAtMs")
                .unwrap();
            value["params"]["startedAtMs"] = tick;
        }),
        change(&snapshot, 8, |value| {
            value["params"]["itemId"] = json!("different-item")
        }),
        change(&snapshot, 9, |value| {
            value["params"]["item"]["text"] = json!("x".repeat(32769))
        }),
        change(&snapshot, 9, |value| {
            value["params"]["item"]["phase"] = json!("unknown")
        }),
        change(&snapshot, 9, |value| {
            value["params"]["item"]["memoryCitation"] = json!({"entries":[],"threadIds":[]})
        }),
        change(&snapshot, 10, |value| {
            value["params"]["turn"]["items"][0]["text"] = json!("x".repeat(32768))
        }),
        change(&snapshot, 9, |value| value["extra"] = json!(true)),
        change(
            &snapshot,
            7,
            |value| {
                value["params"]["item"] =
                    json!({"type":"reasoning","id":"reasoning-item","summary":[],"content":[]})
            },
        ),
    ];
    bounded_turn_cases::native_intake(
        snapshot,
        ProviderAdmissionOwnerPinsV1::bounded_turn_echo_candidate(),
        &negatives,
    );
}

fn sequential_vector(output_bytes: usize) -> Value {
    let mut snapshot = expanded_vector();
    for index in [8, 9, 10] {
        snapshot = change(&snapshot, index, |value| match index {
            8 => value["params"]["delta"] = json!("\0".repeat(output_bytes)),
            9 => value["params"]["item"]["text"] = json!("\0".repeat(output_bytes)),
            _ => value["params"]["turn"]["items"][0]["text"] = json!("\0".repeat(output_bytes)),
        });
    }
    let start = change(&snapshot, 7, |value| {
        value["params"]["startedAtMs"] = json!(4);
        value["params"]["item"]["id"] = json!("commentary-item");
        value["params"]["item"]["phase"] = json!("commentary");
    })["records"][7]
        .clone();
    let complete = change(&snapshot, 9, |value| {
        value["params"]["completedAtMs"] = json!(4);
        value["params"]["item"]["id"] = json!("commentary-item");
        value["params"]["item"]["phase"] = json!("commentary");
        value["params"]["item"]["text"] = json!("progress");
    })["records"][9]
        .clone();
    let reasoning_start = change(&snapshot, 7, |value| {
        value["params"]["startedAtMs"] = json!(4);
        value["params"]["item"] =
            json!({"type":"reasoning","id":"reasoning-item","summary":[],"content":[]});
    })["records"][7]
        .clone();
    let reasoning_complete = change(&snapshot, 9, |value| {
        value["params"]["completedAtMs"] = json!(4);
        value["params"]["item"] =
            json!({"type":"reasoning","id":"reasoning-item","summary":[],"content":[]});
    })["records"][9]
        .clone();
    let records = snapshot["records"].as_array_mut().unwrap();
    records.splice(7..7, [reasoning_start, reasoning_complete, start, complete]);
    let count = records.len() - 1;
    for (index, record) in records.iter_mut().enumerate() {
        record["sequence"] = json!(index);
        if record["kind"] == "ACQUISITION_CUT" {
            record["normalized"]["ordered_high_water"] = json!(count);
            record["normalized"]["consumed_ordinal_count"] = json!(count);
        } else {
            record["acquisition_ordinal"] = json!(index);
        }
        *record = holding_seal_value(record.clone(), "evidence_digest", RECORD_DOMAIN);
    }
    snapshot["acquisition_cut"]["ordered_high_water"] = json!(count);
    snapshot["acquisition_cut"]["consumed_ordinal_count"] = json!(count);
    holding_seal_value(snapshot, "snapshot_digest", SNAPSHOT_DOMAIN)
}

#[test]
fn bounded_turn_echo_sequential_output_and_small_reasoning_remain_compatible() {
    let snapshot = sequential_vector(32760);
    let over_total = sequential_vector(32761);
    let mut over_raw = snapshot.clone();
    for index in [0, 2, 3] {
        over_raw = change(&over_raw, index, |value| {
            if index == 0 {
                value["params"]["input"][0]["text"] = json!("S".repeat(262000));
            } else {
                value["params"]["item"]["content"][0]["text"] = json!("S".repeat(262000));
            }
        });
    }
    let params_digest = json!(format!(
        "sha256:{:x}",
        Sha256::digest(holding_canonical(&wire(&over_raw["records"][0])["params"]))
    ));
    for index in [0, 1] {
        over_raw["records"][index]["normalized"]["params_sha256"] = params_digest.clone();
    }
    assert!(
        over_raw["records"][0]["raw"]["byte_length"]
            .as_u64()
            .unwrap()
            <= 262144
    );
    assert!(
        over_raw["records"][2]["raw"]["byte_length"]
            .as_u64()
            .unwrap()
            > 262144
    );
    bounded_turn_cases::native_intake(
        snapshot,
        ProviderAdmissionOwnerPinsV1::bounded_turn_echo_candidate(),
        &[over_total, over_raw],
    );
}
