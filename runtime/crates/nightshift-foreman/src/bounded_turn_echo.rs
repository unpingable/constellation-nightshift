//! Pure mirror of Switchyard's BOUNDED_TURN_ECHO_V1 selector and ordered replay.
//! Raw framing custody is not provider admission or additional output authority.
use super::*;

const OUTPUT_BYTES: usize = 32768;
const SAFE: i64 = 9_007_199_254_740_991;
const INPUT_SHAPE: &str = "bounded turn input is outside the closed echo shape";
const INPUT_DUPLICATE: &str = "bounded turn echo permits only one selected input";
const ITEM_SHAPE: &str = "large item lifecycle is outside the selected bounded turn contract";
const USER_START: &str = "duplicate bounded user input start";
const USER_COMPLETE: &str = "bounded user input completion lacks exact start";
const USER_DUPLICATE: &str = "duplicate bounded user input lifecycle event";
const AGENT_START: &str = "duplicate bounded agent output start";
const AGENT_COMPLETE: &str = "bounded agent output completion lacks exact start";
const AGENT_DELTA: &str = "bounded agent delta lacks exact item start";
const AGENT_SUMMARY: &str = "bounded turn summary lacks exact completed agent item";
const AGENT_TOTAL: &str = "bounded completed agent output exceeds decoded byte bound";

fn known_error(detail: &str) -> bool {
    matches!(
        detail,
        INPUT_SHAPE
            | INPUT_DUPLICATE
            | ITEM_SHAPE
            | USER_START
            | USER_COMPLETE
            | USER_DUPLICATE
            | AGENT_START
            | AGENT_COMPLETE
            | AGENT_DELTA
            | AGENT_SUMMARY
            | AGENT_TOTAL
    )
}

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|field| object.contains_key(*field))
    })
}

fn identity(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|id| (1..=512).contains(&id.chars().count()))
}

fn tick(value: &Value) -> bool {
    value
        .as_i64()
        .is_some_and(|value| (-SAFE..=SAFE).contains(&value))
}

fn output(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| text.len() <= OUTPUT_BYTES)
}

fn normalize_input(value: &Value) -> Option<Value> {
    let input = value.as_array()?;
    if input.len() != 1
        || !keys(&input[0], &["type", "text"])
        || input[0]["type"] != "text"
        || !input[0]["text"].is_string()
    {
        return None;
    }
    Some(serde_json::json!([{"type":"text", "text":input[0]["text"], "text_elements":[]}]))
}

fn agent_item(item: &Value) -> bool {
    keys(
        item,
        &["type", "id", "text", "phase", "memoryCitation", "delivery"],
    ) && item["type"] == "agentMessage"
        && identity(&item["id"])
        && output(&item["text"])
        && (item["phase"].is_null()
            || matches!(item["phase"].as_str(), Some("commentary" | "final_answer")))
        && item["memoryCitation"].is_null()
        && item["delivery"].is_null()
}

fn user_echo(method: &str, params: &Value, binding: &Value, input: Option<&Value>) -> bool {
    let timestamp = if method == "item/started" {
        "startedAtMs"
    } else {
        "completedAtMs"
    };
    let item = &params["item"];
    matches!(method, "item/started" | "item/completed")
        && keys(params, &["threadId", "turnId", "item", timestamp])
        && params["threadId"] == binding["thread_id"]
        && params["turnId"] == binding["turn_id"]
        && tick(&params[timestamp])
        && keys(item, &["type", "id", "clientId", "content"])
        && item["type"] == "userMessage"
        && identity(&item["id"])
        && item["clientId"].is_null()
        && input.is_some_and(|input| item["content"] == *input)
}

fn agent_output(method: &str, params: &Value, binding: &Value) -> bool {
    if params["threadId"] != binding["thread_id"] {
        return false;
    }
    match method {
        "item/started" | "item/completed" => {
            let timestamp = if method == "item/started" {
                "startedAtMs"
            } else {
                "completedAtMs"
            };
            keys(params, &["threadId", "turnId", "item", timestamp])
                && params["turnId"] == binding["turn_id"]
                && tick(&params[timestamp])
                && agent_item(&params["item"])
        }
        "item/agentMessage/delta" => {
            keys(params, &["threadId", "turnId", "itemId", "delta"])
                && params["turnId"] == binding["turn_id"]
                && identity(&params["itemId"])
                && output(&params["delta"])
        }
        "turn/completed" => {
            let turn = &params["turn"];
            keys(params, &["threadId", "turn", "emittedAtMs"])
                && tick(&params["emittedAtMs"])
                && keys(
                    turn,
                    &[
                        "id",
                        "items",
                        "itemsView",
                        "status",
                        "error",
                        "startedAt",
                        "completedAt",
                        "durationMs",
                    ],
                )
                && turn["id"] == binding["turn_id"]
                && turn["items"]
                    .as_array()
                    .is_some_and(|items| items.len() == 1 && agent_item(&items[0]))
                && turn["itemsView"] == "summary"
                && turn["status"] == "completed"
                && turn["error"].is_null()
                && ["startedAt", "completedAt", "durationMs"]
                    .iter()
                    .all(|key| turn[*key].is_null() || tick(&turn[*key]))
        }
        _ => false,
    }
}

#[derive(Default)]
struct EchoState {
    input: Option<Value>,
    user_id: Option<Value>,
    user_completed: bool,
    agent_id: Option<Value>,
    agent_text: Option<Value>,
    agent_completed: bool,
    completed_agent_ids: BTreeSet<String>,
    completed_output_bytes: usize,
}

impl EchoState {
    fn transition(
        &mut self,
        method: &str,
        params: &Value,
        is_user: bool,
        is_agent: bool,
    ) -> Option<&'static str> {
        if !is_user && !is_agent {
            return Some(ITEM_SHAPE);
        }
        if is_user {
            let id = &params["item"]["id"];
            if method == "item/started" {
                if self.user_id.is_some() {
                    return Some(USER_START);
                }
                self.user_id = Some(id.clone());
            } else if self.user_id.as_ref() != Some(id) {
                return Some(USER_COMPLETE);
            } else if self.user_completed {
                return Some(USER_DUPLICATE);
            } else {
                self.user_completed = true;
            }
        } else if matches!(method, "item/started" | "item/completed") {
            let item = &params["item"];
            if method == "item/started" {
                if self.agent_id.is_some() && !self.agent_completed
                    || self
                        .completed_agent_ids
                        .contains(item["id"].as_str().unwrap_or_default())
                {
                    return Some(AGENT_START);
                }
                self.agent_id = Some(item["id"].clone());
                self.agent_text = Some(item["text"].clone());
                self.agent_completed = false;
            } else if self.agent_id.as_ref() != Some(&item["id"]) || self.agent_completed {
                return Some(AGENT_COMPLETE);
            } else {
                let completed_bytes = item["text"].as_str().map_or(0, str::len);
                if self.completed_output_bytes + completed_bytes > OUTPUT_BYTES {
                    return Some(AGENT_TOTAL);
                }
                self.completed_output_bytes += completed_bytes;
                self.completed_agent_ids
                    .insert(item["id"].as_str().unwrap_or_default().to_owned());
                self.agent_text = Some(item["text"].clone());
                self.agent_completed = true;
            }
        } else if method == "item/agentMessage/delta" {
            if self.agent_completed || self.agent_id.as_ref() != Some(&params["itemId"]) {
                return Some(AGENT_DELTA);
            }
        } else {
            let item = &params["turn"]["items"][0];
            if !self.agent_completed
                || self.agent_id.as_ref() != Some(&item["id"])
                || self.agent_text.as_ref() != Some(&item["text"])
            {
                return Some(AGENT_SUMMARY);
            }
        }
        None
    }
}

/// Structural validation uses this only when new large incoming evidence (or an
/// exact new failure detail) is present. Full-graph enrollment always invokes it.
/// Historical small-frame snapshots retain their existing replay interpretation.
pub(super) fn validate_snapshot(
    snapshot: &Value,
    enrolled: bool,
) -> Result<Vec<Option<&'static str>>, ContractError> {
    let records = snapshot["records"]
        .as_array()
        .ok_or(ContractError::InvalidField("echo records"))?;
    let mut errors = vec![None; records.len()];
    let enabled = enrolled
        || records.iter().any(|record| {
            record["acquisition_kind"] == "NOTIFICATION"
                && record["raw"]["byte_length"]
                    .as_u64()
                    .is_some_and(|n| n > MAXIMUM_AVAILABILITY_EVIDENCE_BYTES as u64)
                || record["normalized"]["detail"]
                    .as_str()
                    .is_some_and(known_error)
        });
    if !enabled {
        return Ok(errors);
    }
    let binding = &snapshot["binding"];
    let mut state = EchoState::default();
    for (index, record) in records.iter().enumerate() {
        let Some(raw) = record.get("raw").filter(|raw| !raw.is_null()) else {
            continue;
        };
        let wire = decode_switchyard_raw(raw, switchyard_record_raw_bound(record))?;
        let method = string(record, "method")?;
        let kind = string(record, "kind")?;
        let params = &wire["params"];
        let retained_error = record["normalized"]["detail"]
            .as_str()
            .filter(|detail| known_error(detail));
        let mut expected = None;
        if method == "client-request/turn/start"
            && (kind == "CLIENT_REQUEST_ISSUED" || retained_error.is_some())
        {
            if let Some(input) = normalize_input(&params["input"]) {
                if state.input.is_some() {
                    expected = Some(INPUT_DUPLICATE);
                } else {
                    state.input = Some(input);
                }
            } else {
                expected = Some(INPUT_SHAPE);
            }
        } else if record["acquisition_kind"] == "NOTIFICATION" {
            let closed_wire = keys(&wire, &["method", "params"]);
            let is_user = closed_wire && user_echo(method, params, binding, state.input.as_ref());
            let is_agent = closed_wire && agent_output(method, params, binding);
            if raw["byte_length"]
                .as_u64()
                .is_some_and(|n| n > MAXIMUM_AVAILABILITY_EVIDENCE_BYTES as u64)
                && !is_user
                && !is_agent
            {
                return Err(ContractError::InvalidField("bounded echo raw selector"));
            }
            if (kind != "ADMISSION_DISCREPANCY" || retained_error.is_some())
                && (is_user || is_agent)
            {
                expected = state.transition(method, params, is_user, is_agent);
            } else if (kind != "ADMISSION_DISCREPANCY" || retained_error.is_some())
                && method == "item/completed"
                && params["threadId"] == binding["thread_id"]
                && params["turnId"] == binding["turn_id"]
                && params["item"]["type"] == "agentMessage"
            {
                // Nonselected small metadata stays a watermark, but its actual
                // completed text still consumes the unchanged worker output cap.
                if let Some(text) = params["item"]["text"].as_str() {
                    state.completed_output_bytes += text.len();
                    if state.completed_output_bytes > OUTPUT_BYTES {
                        expected = Some(AGENT_TOTAL);
                    }
                }
            }
        }
        if let Some(detail) = expected {
            if kind != "ADMISSION_DISCREPANCY" || retained_error != Some(detail) {
                return Err(ContractError::InvalidField("bounded echo ordered replay"));
            }
            let exact_method = if method == "client-request/turn/start" {
                record["acquisition_kind"] == "CLIENT_REQUEST"
                    && keys(&wire, &["id", "method", "params"])
                    && wire["method"] == "turn/start"
                    && wire["id"]
                        .as_i64()
                        .is_some_and(|id| (0..=SAFE).contains(&id))
                    && params.is_object()
                    && params["threadId"] == binding["thread_id"]
            } else {
                record["acquisition_kind"] == "NOTIFICATION"
                    && keys(&wire, &["method", "params"])
                    && wire["method"] == method
            };
            if !exact_method {
                return Err(ContractError::InvalidField(
                    "bounded echo failure wire binding",
                ));
            }
            errors[index] = Some(detail);
        } else if retained_error.is_some() {
            return Err(ContractError::InvalidField(
                "unsubstantiated bounded echo failure",
            ));
        }
    }
    Ok(errors)
}
