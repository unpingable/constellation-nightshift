use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::fd::OwnedFd,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use nightshiftd::operational_lineage::{
    admit_operational_lineage, NextLawfulActionV1, OperationalObservationLineageV1,
    OperationalReobservationEvaluationV1, ReobservationProfileV1,
};
use rustix::fs::{openat, Mode, OFlags, CWD};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::operational_model::{
    CaseworkOperationalConditionV1, OperationalQuestionSourceV1, OperationalQuestionV1,
    OperationalRawSourceV1, OperationalRawSourcesV1,
    CASEWORK_OPERATIONAL_CONDITION_DIGEST_DOMAIN_V1,
    CASEWORK_OPERATIONAL_CONDITION_NAVIGATION_DOMAIN_V1, CASEWORK_OPERATIONAL_CONDITION_SCHEMA_V1,
    CASEWORK_OPERATIONAL_QUESTION_NAVIGATION_DOMAIN_V1,
};

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_CONDITIONS: usize = 4096;
const MONITOR_FILE: &str = "monitor.v1.json";
const NQ_FILE: &str = "nq.v1.json";
const LINEAGE_FILE: &str = "lineage.v1.json";
const PROFILE_FILE: &str = "profile.v1.json";
const EVALUATION_FILE: &str = "evaluation.v1.json";

#[derive(Debug, Error)]
pub enum OperationalCaseworkError {
    #[error("operational condition source failed: {0}")]
    Source(String),
    #[error("operational condition contract failed: {0}")]
    Contract(String),
    #[error("operational condition projection failed: {0}")]
    Projection(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedOperationalCondition {
    pub projection: CaseworkOperationalConditionV1,
    pub monitor_bytes: Vec<u8>,
    pub nq_bytes: Vec<u8>,
    pub lineage_bytes: Vec<u8>,
    pub profile_bytes: Vec<u8>,
    pub evaluation_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct RawCondition {
    monitor_bytes: Vec<u8>,
    nq_bytes: Vec<u8>,
    lineage_bytes: Vec<u8>,
    profile_bytes: Vec<u8>,
    evaluation_bytes: Vec<u8>,
    lineage: OperationalObservationLineageV1,
    profile: ReobservationProfileV1,
    evaluation: OperationalReobservationEvaluationV1,
}

pub fn load_operational_conditions_at(
    directories: &[PathBuf],
) -> Result<BTreeMap<String, LoadedOperationalCondition>, OperationalCaseworkError> {
    if directories.len() > MAX_CONDITIONS {
        return Err(OperationalCaseworkError::Contract(
            "operational condition count exceeds 4096".into(),
        ));
    }
    let raw_conditions = directories
        .iter()
        .map(|directory| read_condition(directory))
        .collect::<Result<Vec<_>, _>>()?;
    let mut loaded = BTreeMap::new();

    for (index, raw) in raw_conditions.iter().enumerate() {
        let history = raw_conditions
            .iter()
            .enumerate()
            .filter(|(other, candidate)| {
                *other != index && same_temporal_branch(&candidate.lineage, &raw.lineage)
            })
            .map(|(_, other)| other.lineage.clone())
            .collect::<Vec<_>>();
        let admitted_at = raw
            .lineage
            .nightshift_admitted_at
            .parse::<DateTime<Utc>>()
            .map_err(|error| {
                OperationalCaseworkError::Contract(format!("lineage admission time: {error}"))
            })?;
        let (derived, _) = admit_operational_lineage(
            &raw.monitor_bytes,
            &raw.nq_bytes,
            &raw.lineage.nq_input_id,
            admitted_at,
            &history,
        )
        .map_err(OperationalCaseworkError::Contract)?;
        if derived != raw.lineage {
            return Err(OperationalCaseworkError::Contract(
                "supplied lineage differs from exact owner derivation".into(),
            ));
        }
        raw.evaluation
            .validate_against(&raw.lineage, &raw.profile)
            .map_err(OperationalCaseworkError::Contract)?;

        let condition = project(raw)?;
        let navigation_id = condition.projection.navigation_id.clone();
        if loaded.insert(navigation_id.clone(), condition).is_some() {
            return Err(OperationalCaseworkError::Contract(format!(
                "duplicate operational navigation id {navigation_id}"
            )));
        }
    }
    Ok(loaded)
}

fn same_temporal_branch(
    candidate: &OperationalObservationLineageV1,
    target: &OperationalObservationLineageV1,
) -> bool {
    candidate.subject_identity_digest == target.subject_identity_digest
        && candidate.producer_identity_digest == target.producer_identity_digest
        && candidate.epoch == target.epoch
}

fn read_condition(directory: &Path) -> Result<RawCondition, OperationalCaseworkError> {
    let root = openat(
        CWD,
        directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| OperationalCaseworkError::Source(error.to_string()))?;
    let monitor_bytes = read_regular_at(&root, MONITOR_FILE)?;
    let nq_bytes = read_regular_at(&root, NQ_FILE)?;
    let lineage_bytes = read_regular_at(&root, LINEAGE_FILE)?;
    let profile_bytes = read_regular_at(&root, PROFILE_FILE)?;
    let evaluation_bytes = read_regular_at(&root, EVALUATION_FILE)?;
    let lineage: OperationalObservationLineageV1 = serde_json::from_slice(&lineage_bytes)
        .map_err(|error| OperationalCaseworkError::Contract(format!("lineage: {error}")))?;
    lineage
        .validate()
        .map_err(OperationalCaseworkError::Contract)?;
    let profile: ReobservationProfileV1 = serde_json::from_slice(&profile_bytes)
        .map_err(|error| OperationalCaseworkError::Contract(format!("profile: {error}")))?;
    profile
        .semantic_digest()
        .map_err(OperationalCaseworkError::Contract)?;
    let evaluation: OperationalReobservationEvaluationV1 =
        serde_json::from_slice(&evaluation_bytes)
            .map_err(|error| OperationalCaseworkError::Contract(format!("evaluation: {error}")))?;
    Ok(RawCondition {
        monitor_bytes,
        nq_bytes,
        lineage_bytes,
        profile_bytes,
        evaluation_bytes,
        lineage,
        profile,
        evaluation,
    })
}

fn read_regular_at(root: &OwnedFd, name: &str) -> Result<Vec<u8>, OperationalCaseworkError> {
    read_regular_at_after_open(root, name, || {})
}

fn read_regular_at_after_open(
    root: &OwnedFd,
    name: &str,
    after_open: impl FnOnce(),
) -> Result<Vec<u8>, OperationalCaseworkError> {
    let fd = openat(
        root,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| OperationalCaseworkError::Source(format!("{name}: {error}")))?;
    let mut file = File::from(fd);
    let before = file
        .metadata()
        .map_err(|error| OperationalCaseworkError::Source(format!("{name}: {error}")))?;
    if !before.file_type().is_file() || before.len() == 0 || before.len() > MAX_SOURCE_BYTES {
        return Err(OperationalCaseworkError::Source(format!(
            "{name} is not a nonempty regular file at most one MiB"
        )));
    }
    let admitted_size = before.len();
    after_open();
    let mut bytes = Vec::with_capacity(admitted_size as usize);
    file.by_ref()
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| OperationalCaseworkError::Source(format!("{name}: {error}")))?;
    let after = file
        .metadata()
        .map_err(|error| OperationalCaseworkError::Source(format!("{name}: {error}")))?;
    if bytes.is_empty() || bytes.len() as u64 != admitted_size || !stable_metadata(&before, &after)
    {
        return Err(OperationalCaseworkError::Source(format!(
            "{name} changed during exact source-byte acquisition"
        )));
    }
    Ok(bytes)
}

fn stable_metadata(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.file_type().is_file()
        && after.file_type().is_file()
}

fn project(raw: &RawCondition) -> Result<LoadedOperationalCondition, OperationalCaseworkError> {
    let lineage = &raw.lineage;
    if lineage.subject_identity_digest
        != monitor_identity_digest("operational.subject.v1", &lineage.subject)?
        || lineage.producer_identity_digest
            != monitor_identity_digest("operational.producer-principal.v1", &lineage.producer)?
    {
        return Err(OperationalCaseworkError::Contract(
            "lineage duplicated subject or producer identity is not exact".into(),
        ));
    }
    if raw.evaluation.lineage_id != lineage.lineage_id
        || raw.evaluation.profile_id != raw.profile.profile_id
        || raw.evaluation.profile_digest
            != raw
                .profile
                .semantic_digest()
                .map_err(OperationalCaseworkError::Contract)?
        || raw.evaluation.max_age_seconds != raw.profile.max_age_seconds
    {
        return Err(OperationalCaseworkError::Contract(
            "evaluation or profile duplicate differs from exact owner binding".into(),
        ));
    }

    let navigation_id = navigation_digest(
        CASEWORK_OPERATIONAL_CONDITION_NAVIGATION_DOMAIN_V1,
        lineage.lineage_id.as_bytes(),
    );
    let questions = questions(lineage, &raw.evaluation, &navigation_id)?;
    let raw_sources = OperationalRawSourcesV1 {
        monitor: raw_source(&raw.monitor_bytes),
        nq: raw_source(&raw.nq_bytes),
        lineage: raw_source(&raw.lineage_bytes),
        profile: raw_source(&raw.profile_bytes),
        evaluation: raw_source(&raw.evaluation_bytes),
    };
    let mut projection = CaseworkOperationalConditionV1 {
        schema: CASEWORK_OPERATIONAL_CONDITION_SCHEMA_V1.into(),
        projection_digest: String::new(),
        navigation_id,
        subject: lineage.subject.clone(),
        subject_identity_digest: lineage.subject_identity_digest.clone(),
        producer: lineage.producer.clone(),
        producer_identity_digest: lineage.producer_identity_digest.clone(),
        acquisition_outcome: lineage.acquisition_outcome,
        lineage: lineage.clone(),
        evaluation: raw.evaluation.clone(),
        profile: raw.profile.clone(),
        questions,
        raw_sources,
        authority_effect: "read_only_projection_no_authority".into(),
    };
    projection.projection_digest = object_digest(
        &projection,
        "projection_digest",
        CASEWORK_OPERATIONAL_CONDITION_DIGEST_DOMAIN_V1,
    )?;
    Ok(LoadedOperationalCondition {
        projection,
        monitor_bytes: raw.monitor_bytes.clone(),
        nq_bytes: raw.nq_bytes.clone(),
        lineage_bytes: raw.lineage_bytes.clone(),
        profile_bytes: raw.profile_bytes.clone(),
        evaluation_bytes: raw.evaluation_bytes.clone(),
    })
}

fn questions(
    lineage: &OperationalObservationLineageV1,
    evaluation: &OperationalReobservationEvaluationV1,
    condition_navigation_id: &str,
) -> Result<Vec<OperationalQuestionV1>, OperationalCaseworkError> {
    let mut values = Vec::new();
    for (index, finding) in lineage.cannot_testify.iter().enumerate() {
        values.push(question(
            condition_navigation_id,
            "cannot_testify",
            index,
            format!(
                "NQ cannot testify to claim {}: {}",
                finding.claim_id, finding.reason
            ),
            OperationalQuestionSourceV1::CannotTestify(finding.clone()),
            evaluation.next_lawful_action,
        ));
    }
    for (index, finding) in lineage.refusals.iter().enumerate() {
        values.push(question(
            condition_navigation_id,
            "refusal",
            index,
            format!("NQ refused input {}: {}", finding.code, finding.detail),
            OperationalQuestionSourceV1::Refusal(finding.clone()),
            evaluation.next_lawful_action,
        ));
    }
    for (index, finding) in lineage.contradictions.iter().enumerate() {
        values.push(question(
            condition_navigation_id,
            "contradiction",
            index,
            format!(
                "NQ records contradictory values for claim {}",
                finding.claim_id
            ),
            OperationalQuestionSourceV1::Contradiction(finding.clone()),
            evaluation.next_lawful_action,
        ));
    }
    if values.len() > 192 {
        return Err(OperationalCaseworkError::Projection(
            "operational question count exceeds closed bound".into(),
        ));
    }
    Ok(values)
}

fn question(
    condition_navigation_id: &str,
    source_kind: &str,
    source_index: usize,
    text: String,
    source: OperationalQuestionSourceV1,
    next_lawful_action: NextLawfulActionV1,
) -> OperationalQuestionV1 {
    let basis = format!("{condition_navigation_id}\0{source_kind}\0{source_index}");
    let question_id = navigation_digest(
        CASEWORK_OPERATIONAL_QUESTION_NAVIGATION_DOMAIN_V1,
        basis.as_bytes(),
    );
    OperationalQuestionV1 {
        navigation_id: question_id.clone(),
        question_id,
        question: text,
        source_index,
        source,
        next_lawful_action,
        presentation_only: true,
    }
}

fn raw_source(bytes: &[u8]) -> OperationalRawSourceV1 {
    OperationalRawSourceV1 {
        exact_bytes_sha256: sha256(bytes),
        exact_bytes_length: bytes.len() as u64,
        validation: "exact_owner_contract_valid".into(),
    }
}

fn monitor_identity_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, OperationalCaseworkError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| OperationalCaseworkError::Projection(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(b"monitor-skunkworks.digest.v1\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn object_digest<T: Serialize>(
    value: &T,
    omitted: &str,
    domain: &[u8],
) -> Result<String, OperationalCaseworkError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| OperationalCaseworkError::Projection(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| OperationalCaseworkError::Projection("object expected".into()))?
        .remove(omitted);
    let bytes = serde_jcs::to_vec(&value)
        .map_err(|error| OperationalCaseworkError::Projection(error.to_string()))?;
    Ok(domain_digest(domain, &bytes))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("sha256:{:x}", digest.finalize())
}

fn navigation_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::DateTime;
    use rustix::fs::{openat, Mode, OFlags, CWD};

    use super::*;

    const MONITOR: &[u8] = include_bytes!(
        "../../nightshiftd/tests/fixtures/operational_lineage/field-monitor.accepted.json"
    );
    const NQ: &[u8] = include_bytes!(
        "../../nightshiftd/tests/fixtures/operational_lineage/field-nq.accepted.json"
    );

    fn lineage() -> OperationalObservationLineageV1 {
        admit_operational_lineage(
            MONITOR,
            NQ,
            "input:field-vector",
            "2026-08-30T03:00:00.523456789Z"
                .parse::<DateTime<Utc>>()
                .unwrap(),
            &[],
        )
        .unwrap()
        .0
    }

    #[test]
    #[ignore = "set NIGHTSHIFT_SHIFT_ATLAS_FIXTURE_DIR for the installed-browser qualification journey"]
    fn emit_installed_browser_condition_fixture() {
        let output = std::env::var_os("NIGHTSHIFT_SHIFT_ATLAS_FIXTURE_DIR")
            .map(PathBuf::from)
            .expect("NIGHTSHIFT_SHIFT_ATLAS_FIXTURE_DIR must name an explicit temporary directory");
        assert!(output.is_dir());
        assert_eq!(fs::read_dir(&output).unwrap().count(), 0);

        let mut nq: serde_json::Value = serde_json::from_slice(NQ).unwrap();
        let input = nq["inputs"][0].as_object_mut().unwrap();
        let support = input
            .get_mut("claim_support")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .remove(0);
        let claim_id = support["claim_id"].as_str().unwrap().to_owned();
        input.insert("claim_support".into(), serde_json::Value::Array(Vec::new()));
        input.insert(
            "cannot_testify".into(),
            serde_json::json!([{
                "claim_id": claim_id,
                "reason": "profile claim absent from exact observation payload"
            }]),
        );
        let nq_bytes = serde_json::to_vec(&nq).unwrap();
        let admitted_at = "2026-08-30T03:00:00.523456789Z"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let lineage =
            admit_operational_lineage(MONITOR, &nq_bytes, "input:field-vector", admitted_at, &[])
                .unwrap()
                .0;
        let profile = ReobservationProfileV1 {
            profile_id: "profile:shift-atlas-browser-fixture".into(),
            max_age_seconds: 60,
        };
        let evaluation = nightshiftd::operational_lineage::evaluate_reobservation(
            &lineage,
            &profile,
            admitted_at,
        )
        .unwrap();
        fs::write(output.join(MONITOR_FILE), MONITOR).unwrap();
        fs::write(output.join(NQ_FILE), nq_bytes).unwrap();
        fs::write(
            output.join(LINEAGE_FILE),
            serde_jcs::to_vec(&lineage).unwrap(),
        )
        .unwrap();
        fs::write(
            output.join(PROFILE_FILE),
            serde_jcs::to_vec(&profile).unwrap(),
        )
        .unwrap();
        fs::write(
            output.join(EVALUATION_FILE),
            serde_jcs::to_vec(&evaluation).unwrap(),
        )
        .unwrap();
        let loaded = load_operational_conditions_at(std::slice::from_ref(&output)).unwrap();
        assert_eq!(
            loaded.values().next().unwrap().projection.questions.len(),
            1
        );
    }

    #[test]
    fn unrelated_subjects_are_excluded_but_successors_share_history() {
        let target = lineage();
        let mut successor = target.clone();
        successor.sequence += 1;
        assert!(same_temporal_branch(&successor, &target));

        let mut unrelated_subject = target.clone();
        unrelated_subject.subject_identity_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert!(!same_temporal_branch(&unrelated_subject, &target));

        let mut unrelated_producer = target.clone();
        unrelated_producer.producer_identity_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        assert!(!same_temporal_branch(&unrelated_producer, &target));

        let mut unrelated_epoch = target.clone();
        unrelated_epoch.epoch = "epoch:other".into();
        assert!(!same_temporal_branch(&unrelated_epoch, &target));
    }

    #[test]
    fn content_mutation_between_admission_and_read_is_refused() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("source.json");
        fs::write(&path, b"original-content").unwrap();
        let root = openat(
            CWD,
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let result = read_regular_at_after_open(&root, "source.json", || {
            fs::write(&path, b"replacement-content-with-another-size").unwrap();
        });
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("changed during exact source-byte acquisition"));
    }

    #[test]
    fn pathname_replacement_cannot_replace_the_admitted_inode() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("source.json");
        let displaced = temporary.path().join("displaced.json");
        fs::write(&path, b"original-content").unwrap();
        let root = openat(
            CWD,
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let bytes = read_regular_at_after_open(&root, "source.json", || {
            fs::rename(&path, &displaced).unwrap();
            fs::write(&path, b"replacement-content").unwrap();
        })
        .unwrap();
        assert_eq!(bytes, b"original-content");
        assert_eq!(fs::read(path).unwrap(), b"replacement-content");
    }
}
