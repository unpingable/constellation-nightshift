use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use nightshiftd::packet::NightshiftPacketV1;
use rustix::fs::{open, openat, Mode, OFlags};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::model::*;

const PACKET_FILE: &str = "packet.v1.json";
const RECEIPTS_FILE: &str = "run-receipts.v1.json";

#[derive(Debug, Error)]
pub enum CaseworkError {
    #[error("run directory is invalid: {0}")]
    InvalidRunDirectory(String),
    #[error("run input path is not a regular non-symlink file: {0}")]
    InvalidInputPath(String),
    #[error("cannot read run input {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("packet validation failed: {0}")]
    Packet(String),
    #[error("receipt compatibility validation failed: {0}")]
    Receipt(String),
    #[error("duplicate run packet digest: {0}")]
    DuplicateRun(String),
    #[error("projection serialization failed: {0}")]
    Projection(String),
}

#[derive(Clone, Debug)]
pub struct LoadedRun {
    pub projection: CaseworkRunV1,
    pub packet_bytes: Vec<u8>,
    pub receipt_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ReceiptDocument {
    schema: Value,
    packet_digest: Value,
    updated_at: Value,
    work_items: Value,
    human_questions: Value,
    repository_custody: Value,
}

#[derive(Debug, Deserialize)]
struct ReceiptItem {
    id: Value,
    state: Value,
    result_classification: Value,
    repositories: Value,
    tests: Value,
    evidence: Value,
    live_or_production_mutations: Value,
    remaining_trigger: Value,
    next_lawful_action: Value,
}

pub fn load_runs_at(
    run_dirs: &[PathBuf],
    evaluated_now: DateTime<Utc>,
) -> Result<BTreeMap<String, LoadedRun>, CaseworkError> {
    let mut runs = BTreeMap::new();
    for run_dir in run_dirs {
        let loaded = load_run_at(run_dir, evaluated_now)?;
        let run_id = loaded.projection.run_id.clone();
        if runs.insert(run_id.clone(), loaded).is_some() {
            return Err(CaseworkError::DuplicateRun(run_id));
        }
    }
    Ok(runs)
}

pub fn load_run_at(
    run_dir: &Path,
    evaluated_now: DateTime<Utc>,
) -> Result<LoadedRun, CaseworkError> {
    let directory = open(
        run_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| CaseworkError::InvalidRunDirectory(error.to_string()))?;
    let packet_bytes = read_exact_input(&directory, PACKET_FILE)?;
    let receipt_bytes = read_exact_input(&directory, RECEIPTS_FILE)?;

    let packet = NightshiftPacketV1::from_slice(&packet_bytes)
        .map_err(|error| CaseworkError::Packet(error.to_string()))?;
    packet
        .validate_integrity()
        .map_err(|error| CaseworkError::Packet(error.to_string()))?;
    let receipts = parse_receipts(&receipt_bytes, &packet)?;
    let projection = project(
        &packet,
        &packet_bytes,
        receipts,
        &receipt_bytes,
        evaluated_now,
    )?;
    Ok(LoadedRun {
        projection,
        packet_bytes,
        receipt_bytes,
    })
}

fn open_exact_input(
    directory: &rustix::fd::OwnedFd,
    filename: &str,
) -> Result<File, CaseworkError> {
    let descriptor = openat(
        directory,
        filename,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| CaseworkError::InvalidInputPath(filename.to_owned()))?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| CaseworkError::Read {
        path: filename.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(CaseworkError::InvalidInputPath(filename.to_owned()));
    }
    Ok(file)
}

fn read_exact_input(
    directory: &rustix::fd::OwnedFd,
    filename: &str,
) -> Result<Vec<u8>, CaseworkError> {
    let mut file = open_exact_input(directory, filename)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CaseworkError::Read {
            path: filename.to_owned(),
            source,
        })?;
    Ok(bytes)
}

#[derive(Debug)]
struct ParsedReceipts {
    updated_at: CompatibleTimestampV1,
    updated_at_instant: Option<DateTime<Utc>>,
    items: BTreeMap<String, ParsedReceiptItem>,
    questions: Vec<ParsedQuestion>,
    custody: Vec<ParsedCustody>,
}

#[derive(Debug)]
struct ParsedReceiptItem {
    state: CompatibleValueV1,
    classification: CompatibleValueV1,
    repositories: RenderedRepositoriesV1,
    tests: RendererJoinedValueV1,
    evidence: RendererJoinedValueV1,
    mutations: RendererJoinedValueV1,
    remaining_trigger: CompatibleValueV1,
    next_lawful_action: CompatibleValueV1,
}

#[derive(Debug)]
struct ParsedQuestion {
    work_item: CompatibleValueV1,
    linked_work_item: Option<String>,
    exact_question: CompatibleValueV1,
    evidence_exhausted: CompatibleValueV1,
    safe_default: CompatibleValueV1,
    consequences: CompatibleValueV1,
    resume_point: CompatibleValueV1,
}

#[derive(Debug)]
struct ParsedCustody {
    repository: CompatibleValueV1,
    branch_head: CompatibleValueV1,
    push_custody: CompatibleValueV1,
    dirty: CompatibleValueV1,
    live_runtime: CompatibleValueV1,
    secrets: CompatibleValueV1,
    teardown: CompatibleValueV1,
}

fn parse_receipts(
    bytes: &[u8],
    packet: &NightshiftPacketV1,
) -> Result<ParsedReceipts, CaseworkError> {
    let value: Value = serde_json::from_slice(bytes).map_err(receipt_error)?;
    let doc: ReceiptDocument = serde_json::from_value(value).map_err(receipt_error)?;
    if string(&doc.schema, "schema")? != RUN_RECEIPTS_SCHEMA_V1 {
        return Err(receipt("foreign receipt schema"));
    }
    if string(&doc.packet_digest, "packet_digest")? != packet.packet_digest {
        return Err(receipt("receipt packet digest mismatch"));
    }
    let (updated_at, updated_at_instant) = compatible_timestamp(&doc.updated_at);
    let packet_ids: BTreeSet<&str> = packet
        .work_items
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    let mut items = BTreeMap::new();
    for item_value in array(&doc.work_items, "work_items")? {
        let item: ReceiptItem =
            serde_json::from_value(item_value.clone()).map_err(receipt_error)?;
        let id = string(&item.id, "work_items.id")?.to_owned();
        if items.contains_key(&id) {
            return Err(receipt(format!("duplicate receipt work item: {id}")));
        }
        if !packet_ids.contains(id.as_str()) {
            return Err(receipt(format!("unknown receipt work item: {id}")));
        }
        items.insert(
            id,
            ParsedReceiptItem {
                state: compatible_value(&item.state),
                classification: compatible_value(&item.result_classification),
                repositories: parse_repositories(&item.repositories),
                tests: renderer_joined(&item.tests, "work_items.tests")?,
                evidence: renderer_joined(&item.evidence, "work_items.evidence")?,
                mutations: renderer_joined(
                    &item.live_or_production_mutations,
                    "work_items.live_or_production_mutations",
                )?,
                remaining_trigger: compatible_value(&item.remaining_trigger),
                next_lawful_action: compatible_value(&item.next_lawful_action),
            },
        );
    }
    let missing: Vec<_> = packet_ids
        .iter()
        .filter(|id| !items.contains_key(**id))
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(receipt(format!(
            "missing receipt work item: {}",
            missing.join(", ")
        )));
    }
    Ok(ParsedReceipts {
        updated_at,
        updated_at_instant,
        items,
        questions: parse_questions(&doc.human_questions, &packet_ids)?,
        custody: parse_custody(&doc.repository_custody)?,
    })
}

fn parse_repositories(value: &Value) -> RenderedRepositoriesV1 {
    let recognized_rows = value.as_array().and_then(|rows| {
        rows.iter()
            .map(|row| {
                let object = row.as_object()?;
                Some(ResultRepositoryV1 {
                    repository: object.get("repository")?.as_str()?.to_owned(),
                    branch: object.get("branch")?.as_str()?.to_owned(),
                    head: object.get("head")?.as_str()?.to_owned(),
                    push_status: object.get("push_status")?.as_str()?.to_owned(),
                })
            })
            .collect::<Option<Vec<_>>>()
    });
    RenderedRepositoriesV1 { recognized_rows }
}

fn parse_questions(
    value: &Value,
    packet_ids: &BTreeSet<&str>,
) -> Result<Vec<ParsedQuestion>, CaseworkError> {
    array(value, "human_questions")?
        .iter()
        .map(|row| {
            let object = object(row, "human_questions row")?;
            let work_item =
                compatible_value(object_required(object, "work_item", "human_questions")?);
            let linked_work_item = work_item
                .recognized_string
                .as_deref()
                .filter(|id| packet_ids.contains(*id))
                .map(ToOwned::to_owned);
            Ok(ParsedQuestion {
                work_item,
                linked_work_item,
                exact_question: compatible_value(object_required(
                    object,
                    "exact_question",
                    "human_questions",
                )?),
                evidence_exhausted: compatible_value(object_required(
                    object,
                    "evidence_exhausted",
                    "human_questions",
                )?),
                safe_default: compatible_value(object_required(
                    object,
                    "safe_default",
                    "human_questions",
                )?),
                consequences: compatible_value(object_required(
                    object,
                    "consequences",
                    "human_questions",
                )?),
                resume_point: compatible_value(object_required(
                    object,
                    "resume_point",
                    "human_questions",
                )?),
            })
        })
        .collect()
}

fn parse_custody(value: &Value) -> Result<Vec<ParsedCustody>, CaseworkError> {
    array(value, "repository_custody")?
        .iter()
        .map(|row| {
            let object = object(row, "repository_custody row")?;
            Ok(ParsedCustody {
                repository: compatible_value(object_required(
                    object,
                    "repository",
                    "repository_custody",
                )?),
                branch_head: compatible_value(object_required(
                    object,
                    "branch_head",
                    "repository_custody",
                )?),
                push_custody: compatible_value(object_required(
                    object,
                    "push_custody",
                    "repository_custody",
                )?),
                dirty: compatible_value(object_required(object, "dirty", "repository_custody")?),
                live_runtime: compatible_value(object_required(
                    object,
                    "live_runtime",
                    "repository_custody",
                )?),
                secrets: compatible_value(object_required(
                    object,
                    "secrets",
                    "repository_custody",
                )?),
                teardown: compatible_value(object_required(
                    object,
                    "teardown",
                    "repository_custody",
                )?),
            })
        })
        .collect()
}

fn project(
    packet: &NightshiftPacketV1,
    packet_bytes: &[u8],
    mut receipts: ParsedReceipts,
    receipt_bytes: &[u8],
    evaluated_now: DateTime<Utc>,
) -> Result<CaseworkRunV1, CaseworkError> {
    let run_id = packet
        .packet_digest
        .strip_prefix("sha256:")
        .expect("integrity validation requires this prefix")
        .to_owned();
    let packet_digest = packet.packet_digest.clone();
    let starting_custody = packet
        .repository_custody
        .iter()
        .enumerate()
        .map(|(index, row)| StartingCustodyV1 {
            derived_id: derived_id(
                "nightshift.casework.custody-row/v1",
                &[
                    &packet_digest,
                    "packet",
                    &row.repository,
                    &index.to_string(),
                ],
            ),
            repository: row.repository.clone(),
            path: row.path.clone(),
            branch: row.branch.clone(),
            commit: row.commit.clone(),
            remote: row.remote.clone(),
            remote_commit: row.remote_commit.clone(),
            worktree_clean: row.worktree_clean,
            discrepancy: row.discrepancy.clone(),
        })
        .collect::<Vec<_>>();
    let discrepancy_count = starting_custody
        .iter()
        .filter(|row| row.discrepancy.is_some())
        .count();
    let mut state_counts = BTreeMap::new();
    let mut unrecognized_state_count = 0;
    let mut work_items = Vec::with_capacity(packet.work_items.len());
    for item in &packet.work_items {
        let outcome = receipts
            .items
            .remove(&item.id)
            .expect("one-to-one receipt validation established linkage");
        if let Some(state) = &outcome.state.recognized_string {
            *state_counts.entry(state.clone()).or_insert(0) += 1;
        } else {
            unrecognized_state_count += 1;
        }
        work_items.push(CaseworkItemV1 {
            derived_id: derived_id(
                "nightshift.casework.work-item/v1",
                &[&packet_digest, &item.id],
            ),
            id: item.id.clone(),
            track: item.track.clone(),
            campaign: CampaignV1 {
                codename: item.campaign.codename.clone(),
                canonical_slug: item.campaign.canonical_slug.clone(),
            },
            predecessor_lineage: item
                .predecessor_lineage
                .iter()
                .map(|row| PredecessorV1 {
                    campaign: row.campaign.clone(),
                    classification: row.classification.clone(),
                    commit: row.commit.clone(),
                })
                .collect(),
            dependencies: item.dependencies.clone(),
            exact_work_refs: item
                .exact_work_refs
                .iter()
                .map(|row| ExactWorkRefV1 {
                    contract_kind: row.contract_kind.clone(),
                    contract_schema: row.contract_schema.clone(),
                    repository: row.repository.clone(),
                    branch: row.branch.clone(),
                    commit: row.commit.clone(),
                    path: row.path.clone(),
                    proposal_ref: row.proposal_ref.clone(),
                })
                .collect(),
            entry_predicates: item.entry_predicates.clone(),
            allowed_mutation_surfaces: item.allowed_mutation_surfaces.clone(),
            forbidden_actions: item.forbidden_actions.clone(),
            acceptance_tests: item.acceptance_tests.clone(),
            stop_conditions: item.stop_conditions.clone(),
            expected_receipts: item.expected_receipts.clone(),
            closeout_requirements: item.closeout_requirements.clone(),
            model_routing: ModelRoutingV1 {
                class: item.model_routing.class.clone(),
                reason: item.model_routing.reason.clone(),
                maximum_mutating_workers: item.model_routing.maximum_mutating_workers,
            },
            outcome: WorkItemOutcomeV1 {
                state: outcome.state,
                result_classification: outcome.classification,
                repositories: outcome.repositories,
                tests: outcome.tests,
                evidence: outcome.evidence,
                live_or_production_mutations: outcome.mutations,
                remaining_trigger: outcome.remaining_trigger,
                next_lawful_action: outcome.next_lawful_action,
            },
        });
    }
    let questions = receipts
        .questions
        .into_iter()
        .enumerate()
        .map(|(index, question)| {
            let base_id = question
                .linked_work_item
                .as_deref()
                .zip(question.exact_question.recognized_string.as_deref())
                .map(|(work_item, text)| {
                    derived_id(
                        "nightshift.casework.question/v1",
                        &[&packet_digest, work_item, text],
                    )
                });
            let navigation_id = derived_id(
                "nightshift.casework.question-row/v1",
                &[&packet_digest, &index.to_string()],
            );
            HumanQuestionV1 {
                derived_id: base_id,
                navigation_id,
                source_ordinal: index,
                work_item: question.work_item,
                linked_work_item: question.linked_work_item,
                exact_question: question.exact_question,
                evidence_exhausted: question.evidence_exhausted,
                safe_default: question.safe_default,
                consequences: question.consequences,
                resume_point: question.resume_point,
            }
        })
        .collect::<Vec<_>>();
    let final_custody = receipts
        .custody
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            let base_derived_id = row
                .repository
                .recognized_string
                .as_deref()
                .map(|repository| {
                    derived_id(
                        "nightshift.casework.custody-row/v1",
                        &[&packet_digest, "receipts", repository, &index.to_string()],
                    )
                });
            FinalCustodyV1 {
                derived_id: base_derived_id,
                navigation_id: derived_id(
                    "nightshift.casework.custody-row-navigation/v1",
                    &[&packet_digest, "receipts", &index.to_string()],
                ),
                source_ordinal: index,
                repository: row.repository,
                branch_head: row.branch_head,
                push_custody: row.push_custody,
                dirty: row.dirty,
                live_runtime: row.live_runtime,
                secrets: row.secrets,
                teardown: row.teardown,
            }
        })
        .collect();
    let snapshot_currentness = receipts
        .updated_at_instant
        .map(|instant| currentness(packet, instant))
        .unwrap_or("UNAVAILABLE");
    let now_currentness = currentness(packet, evaluated_now);
    let mut projection = CaseworkRunV1 {
        schema: CASEWORK_RUN_SCHEMA_V1.to_owned(),
        projection_digest: String::new(),
        run_id,
        packet: PacketCaseV1 {
            packet_id: packet.packet_id.clone(),
            packet_digest,
            created_at: packet.created_at.to_rfc3339(),
            current_until: packet.current_until.to_rfc3339(),
            source_bytes_digest: bytes_digest(packet_bytes),
            integrity: "VALID_PACKET_INTEGRITY".to_owned(),
            currentness_at_receipt_snapshot: snapshot_currentness.to_owned(),
            currentness_evaluated_at: evaluated_now.to_rfc3339(),
            currentness_now: now_currentness.to_owned(),
            repository_custody: starting_custody,
        },
        receipts: ReceiptSnapshotV1 {
            schema: RUN_RECEIPTS_SCHEMA_V1.to_owned(),
            updated_at: receipts.updated_at,
            source_bytes_digest: bytes_digest(receipt_bytes),
            validation: "VALID_RENDERER_COMPATIBLE_RECEIPT_SNAPSHOT".to_owned(),
        },
        summary: RunSummaryV1 {
            work_item_count: work_items.len(),
            state_counts,
            unrecognized_state_count,
            human_question_count: questions.len(),
            packet_custody_discrepancy_count: discrepancy_count,
        },
        work_items,
        human_questions: questions,
        final_repository_custody: final_custody,
    };
    projection.projection_digest = projection_digest(&projection)?;
    Ok(projection)
}

fn currentness(packet: &NightshiftPacketV1, instant: DateTime<Utc>) -> &'static str {
    if instant < packet.created_at {
        "NOT_YET_CURRENT"
    } else if instant > packet.current_until {
        "EXPIRED"
    } else {
        "CURRENT"
    }
}

fn compatible_value(value: &Value) -> CompatibleValueV1 {
    CompatibleValueV1 {
        recognized_string: value.as_str().map(ToOwned::to_owned),
    }
}

fn compatible_timestamp(value: &Value) -> (CompatibleTimestampV1, Option<DateTime<Utc>>) {
    let recognized_string = value.as_str().map(ToOwned::to_owned);
    let instant = recognized_string
        .as_deref()
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|instant| instant.with_timezone(&Utc));
    (
        CompatibleTimestampV1 {
            recognized_string,
            recognized_rfc3339: instant.map(|instant| instant.to_rfc3339()),
        },
        instant,
    )
}

fn renderer_joined(value: &Value, field: &str) -> Result<RendererJoinedValueV1, CaseworkError> {
    let recognized_strings = match value {
        Value::Array(values) => Some(
            values
                .iter()
                .map(|value| value.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| receipt(format!("{field} is not renderer-joinable")))?,
        ),
        Value::String(_) | Value::Object(_) => None,
        _ => return Err(receipt(format!("{field} is not renderer-joinable"))),
    };
    Ok(RendererJoinedValueV1 { recognized_strings })
}

fn derived_id(domain: &str, components: &[&str]) -> String {
    let canonical = serde_jcs::to_vec(components).expect("strings have a JCS representation");
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(canonical);
    format!("sha256:{:x}", digest.finalize())
}

fn projection_digest(projection: &CaseworkRunV1) -> Result<String, CaseworkError> {
    let mut value = serde_json::to_value(projection)
        .map_err(|error| CaseworkError::Projection(error.to_string()))?;
    value
        .as_object_mut()
        .expect("projection serializes as an object")
        .remove("projection_digest");
    let canonical =
        serde_jcs::to_vec(&value).map_err(|error| CaseworkError::Projection(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(CASEWORK_RUN_DIGEST_DOMAIN_V1);
    digest.update(canonical);
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn bytes_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn receipt_error(error: impl std::fmt::Display) -> CaseworkError {
    receipt(error.to_string())
}

fn receipt(message: impl Into<String>) -> CaseworkError {
    CaseworkError::Receipt(message.into())
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, CaseworkError> {
    value
        .as_str()
        .ok_or_else(|| receipt(format!("{field} must be a string")))
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value], CaseworkError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| receipt(format!("{field} must be an array")))
}

fn object<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, CaseworkError> {
    value
        .as_object()
        .ok_or_else(|| receipt(format!("{field} must be an object")))
}

fn object_required<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a Value, CaseworkError> {
    object
        .get(key)
        .ok_or_else(|| receipt(format!("{field} missing required field {key}")))
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    #[test]
    fn opened_file_descriptor_is_stable_across_pathname_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(PACKET_FILE);
        std::fs::write(&path, b"original bytes").unwrap();
        let directory_fd = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let mut opened = open_exact_input(&directory_fd, PACKET_FILE).unwrap();
        std::fs::rename(&path, directory.path().join("packet.original")).unwrap();
        std::fs::write(&path, b"substituted bytes").unwrap();
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original bytes");
    }

    #[test]
    fn directory_handle_is_stable_across_run_directory_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let run_dir = parent.path().join("run");
        std::fs::create_dir(&run_dir).unwrap();
        std::fs::write(run_dir.join(PACKET_FILE), b"original directory").unwrap();
        let directory_fd = open(
            &run_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        std::fs::rename(&run_dir, parent.path().join("run.original")).unwrap();
        std::fs::create_dir(&run_dir).unwrap();
        std::fs::write(run_dir.join(PACKET_FILE), b"substituted directory").unwrap();
        assert_eq!(
            read_exact_input(&directory_fd, PACKET_FILE).unwrap(),
            b"original directory"
        );
    }
}
