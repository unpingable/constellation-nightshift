use std::collections::{BTreeMap, BTreeSet};

use nightshiftd::packet::NightshiftPacketV1;
use serde::{Deserialize, Serialize};

use crate::{
    AdapterEventKindV1, AdapterEventV1, ExecutionProfileV2, HumanQuestionV1,
    ProviderExecutionIdentityV1, ProviderMechanismStateV1, SchedulerStateV1,
    LIVE_RUN_PROJECTION_SCHEMA_V1,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedOutcomeV1 {
    pub state: String,
    pub result_classification: String,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveWorkItemV1 {
    pub work_item_id: String,
    pub dependencies: Vec<String>,
    pub scheduler_state: SchedulerStateV1,
    pub dependency_terminality: BTreeMap<String, bool>,
    pub resource_lock_keys: Vec<String>,
    pub active_attempt_id: Option<String>,
    pub adapter_id: String,
    pub adapter_version: String,
    pub provider_model_class: String,
    pub provider_identity: Option<String>,
    pub model_identity: Option<String>,
    pub session_identity: Option<String>,
    pub thread_identity: Option<String>,
    pub turn_identity: Option<String>,
    pub queue_identity: Option<String>,
    pub last_event_sequence: Option<u64>,
    pub last_event_digest: Option<String>,
    pub human_questions: Vec<HumanQuestionV1>,
    pub accepted_terminal_outcome: Option<AcceptedOutcomeV1>,
    pub result_absent_until_terminal_receipt_acceptance: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceClaimV1 {
    pub resource_lock_key: String,
    pub work_item_id: String,
    pub attempt_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveRunProjectionV1 {
    pub schema: String,
    pub run_id: String,
    pub packet_id: String,
    pub packet_digest: String,
    pub admission_digest: String,
    pub profile_digest: String,
    pub maximum_concurrent_workers: u16,
    pub work_items: Vec<LiveWorkItemV1>,
    pub resource_claims: Vec<ResourceClaimV1>,
    pub closed_final_receipts_digest: Option<String>,
    pub authority_effect: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ReplayEvent {
    pub sequence: u64,
    pub work_item_id: Option<String>,
    pub attempt_id: Option<String>,
    pub kind: ReplayKind,
    pub raw_digest: String,
}

#[derive(Clone, Debug)]
pub(crate) enum ReplayKind {
    RunAdmitted,
    AttemptCreated {
        resource_lock_keys: Vec<String>,
    },
    DispatchRequested,
    ResumeRequested,
    Adapter(Box<AdapterEventV1>),
    TerminalAccepted(AcceptedOutcomeV1),
    TerminalRefused,
    NotStartedAccepted(AcceptedOutcomeV1),
    ResourcesReleased,
    CapacityEvidence,
    ExecutionAvailabilityConfigured,
    ProviderDispatchOpened,
    ProviderDispositionRecorded {
        mechanism_state: ProviderMechanismStateV1,
        execution_identity: Option<ProviderExecutionIdentityV1>,
    },
    ProviderWakeOpened,
    ProviderExecutionResumeRequested,
    ProviderResourcesReleased,
    ProviderResourcesReacquired {
        resource_lock_keys: Vec<String>,
    },
    RunClosed {
        final_receipts_digest: String,
    },
}

pub struct Scheduler;

impl Scheduler {
    pub(crate) fn replay(
        packet: &NightshiftPacketV1,
        run_id: &str,
        admission_digest: &str,
        profile: &ExecutionProfileV2,
        maximum_concurrent_workers: u16,
        events: &[ReplayEvent],
    ) -> LiveRunProjectionV1 {
        let mut items: BTreeMap<String, LiveWorkItemV1> = packet
            .work_items
            .iter()
            .map(|item| {
                let execution = &profile.work_items[&item.id];
                (
                    item.id.clone(),
                    LiveWorkItemV1 {
                        work_item_id: item.id.clone(),
                        dependencies: item.dependencies.clone(),
                        scheduler_state: SchedulerStateV1::WaitingDependencies,
                        dependency_terminality: BTreeMap::new(),
                        resource_lock_keys: execution.resource_lock_keys.clone(),
                        active_attempt_id: None,
                        adapter_id: execution.adapter_id.clone(),
                        adapter_version: profile.adapters[&execution.adapter_id]
                            .adapter_version
                            .clone(),
                        provider_model_class: execution.provider_model_class.clone(),
                        provider_identity: None,
                        model_identity: None,
                        session_identity: None,
                        thread_identity: None,
                        turn_identity: None,
                        queue_identity: None,
                        last_event_sequence: None,
                        last_event_digest: None,
                        human_questions: Vec::new(),
                        accepted_terminal_outcome: None,
                        result_absent_until_terminal_receipt_acceptance: true,
                    },
                )
            })
            .collect();
        let mut claims: BTreeMap<String, ResourceClaimV1> = BTreeMap::new();
        let mut closed_final_receipts_digest = None;

        for event in events {
            if let Some(work_item_id) = &event.work_item_id {
                let Some(item) = items.get_mut(work_item_id) else {
                    continue;
                };
                item.last_event_sequence = Some(event.sequence);
                item.last_event_digest = Some(event.raw_digest.clone());
                match &event.kind {
                    ReplayKind::AttemptCreated { resource_lock_keys } => {
                        item.active_attempt_id = event.attempt_id.clone();
                        item.scheduler_state = SchedulerStateV1::Dispatching;
                        if let Some(attempt_id) = &event.attempt_id {
                            for key in resource_lock_keys {
                                claims.insert(
                                    key.clone(),
                                    ResourceClaimV1 {
                                        resource_lock_key: key.clone(),
                                        work_item_id: work_item_id.clone(),
                                        attempt_id: attempt_id.clone(),
                                    },
                                );
                            }
                        }
                    }
                    ReplayKind::DispatchRequested | ReplayKind::ResumeRequested => {
                        item.scheduler_state = SchedulerStateV1::Dispatching;
                    }
                    ReplayKind::Adapter(adapter_event) => {
                        apply_adapter_event(item, adapter_event);
                    }
                    ReplayKind::TerminalAccepted(outcome)
                    | ReplayKind::NotStartedAccepted(outcome) => {
                        item.scheduler_state =
                            if matches!(event.kind, ReplayKind::NotStartedAccepted(_)) {
                                SchedulerStateV1::NotStarted
                            } else {
                                SchedulerStateV1::TerminalReceiptAccepted
                            };
                        item.accepted_terminal_outcome = Some(outcome.clone());
                        item.result_absent_until_terminal_receipt_acceptance = false;
                    }
                    ReplayKind::TerminalRefused => {
                        item.scheduler_state = SchedulerStateV1::TerminalReceiptRefused;
                    }
                    ReplayKind::ResourcesReleased => {
                        claims.retain(|_, claim| claim.work_item_id != *work_item_id);
                    }
                    ReplayKind::ProviderResourcesReleased => {
                        claims.retain(|_, claim| {
                            claim.work_item_id != *work_item_id
                                || event.attempt_id.as_deref() != Some(claim.attempt_id.as_str())
                        });
                    }
                    ReplayKind::ProviderResourcesReacquired { resource_lock_keys } => {
                        if let Some(attempt_id) = &event.attempt_id {
                            for key in resource_lock_keys {
                                claims.insert(
                                    key.clone(),
                                    ResourceClaimV1 {
                                        resource_lock_key: key.clone(),
                                        work_item_id: work_item_id.clone(),
                                        attempt_id: attempt_id.clone(),
                                    },
                                );
                            }
                        }
                    }
                    ReplayKind::ProviderDispatchOpened | ReplayKind::ProviderWakeOpened => {
                        item.scheduler_state = SchedulerStateV1::Dispatching;
                    }
                    ReplayKind::ProviderDispositionRecorded {
                        mechanism_state,
                        execution_identity,
                    } => {
                        if let Some(identity) = execution_identity {
                            item.provider_identity = Some(identity.provider_id.clone());
                            item.model_identity = Some(identity.model_id.clone());
                            item.session_identity =
                                Some(identity.app_server_session_identity.clone());
                            item.thread_identity = Some(identity.thread_id.clone());
                            item.turn_identity = Some(identity.turn_id.clone());
                        }
                        item.scheduler_state = match mechanism_state {
                            ProviderMechanismStateV1::ParkedNotAdmitted => {
                                SchedulerStateV1::WaitingProvider
                            }
                            ProviderMechanismStateV1::AdmissionIndeterminate => {
                                SchedulerStateV1::IndeterminateMechanismState
                            }
                            ProviderMechanismStateV1::ExecutionAdmitted
                            | ProviderMechanismStateV1::PostAdmissionInterrupted => {
                                SchedulerStateV1::WaitingProvider
                            }
                            ProviderMechanismStateV1::WaitingApproval => {
                                SchedulerStateV1::WaitingApproval
                            }
                            ProviderMechanismStateV1::ProviderCompleted => {
                                SchedulerStateV1::WaitingProvider
                            }
                        };
                    }
                    ReplayKind::ProviderExecutionResumeRequested => {
                        item.scheduler_state = SchedulerStateV1::Dispatching;
                    }
                    ReplayKind::RunAdmitted
                    | ReplayKind::CapacityEvidence
                    | ReplayKind::ExecutionAvailabilityConfigured
                    | ReplayKind::RunClosed { .. } => {}
                }
            }
            if let ReplayKind::RunClosed {
                final_receipts_digest,
            } = &event.kind
            {
                closed_final_receipts_digest = Some(final_receipts_digest.clone());
            }
        }

        let terminal: BTreeSet<String> = items
            .values()
            .filter(|item| item.scheduler_state.is_explicit_terminal())
            .map(|item| item.work_item_id.clone())
            .collect();
        let held: BTreeSet<&str> = claims.keys().map(String::as_str).collect();
        for item in items.values_mut() {
            item.dependency_terminality = item
                .dependencies
                .iter()
                .map(|dependency| (dependency.clone(), terminal.contains(dependency)))
                .collect();
            if item.active_attempt_id.is_none()
                && !item.scheduler_state.is_explicit_terminal()
                && !matches!(
                    item.scheduler_state,
                    SchedulerStateV1::TerminalReceiptRefused
                        | SchedulerStateV1::IndeterminateMechanismState
                )
            {
                if item.dependencies.iter().all(|dep| terminal.contains(dep)) {
                    item.scheduler_state = if item
                        .resource_lock_keys
                        .iter()
                        .any(|key| held.contains(key.as_str()))
                    {
                        SchedulerStateV1::WaitingResource
                    } else {
                        SchedulerStateV1::ReadyEntryEvaluation
                    };
                } else {
                    item.scheduler_state = SchedulerStateV1::WaitingDependencies;
                }
            }
        }

        LiveRunProjectionV1 {
            schema: LIVE_RUN_PROJECTION_SCHEMA_V1.to_owned(),
            run_id: run_id.to_owned(),
            packet_id: packet.packet_id.clone(),
            packet_digest: packet.packet_digest.clone(),
            admission_digest: admission_digest.to_owned(),
            profile_digest: profile.profile_digest.clone(),
            maximum_concurrent_workers,
            work_items: items.into_values().collect(),
            resource_claims: claims.into_values().collect(),
            closed_final_receipts_digest,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        }
    }
}

fn apply_adapter_event(item: &mut LiveWorkItemV1, event: &AdapterEventV1) {
    if let Some(value) = &event.provider_identity {
        item.provider_identity = Some(value.clone());
    }
    if let Some(value) = &event.model_identity {
        item.model_identity = Some(value.clone());
    }
    if let Some(value) = &event.session_identity {
        item.session_identity = Some(value.clone());
    }
    if let Some(value) = &event.thread_identity {
        item.thread_identity = Some(value.clone());
    }
    if let Some(value) = &event.turn_identity {
        item.turn_identity = Some(value.clone());
    }
    if let Some(value) = &event.queue_identity {
        item.queue_identity = Some(value.clone());
    }
    item.scheduler_state = match event.kind {
        AdapterEventKindV1::AdapterAccepted | AdapterEventKindV1::WorkerStarted => {
            SchedulerStateV1::Running
        }
        AdapterEventKindV1::ProviderIdentity => SchedulerStateV1::WaitingProvider,
        AdapterEventKindV1::Checkpoint => SchedulerStateV1::Checkpointed,
        AdapterEventKindV1::WaitingApproval => SchedulerStateV1::WaitingApproval,
        AdapterEventKindV1::HumanQuestion => SchedulerStateV1::WaitingHuman,
        AdapterEventKindV1::ProviderCompletionObservation => SchedulerStateV1::WaitingProvider,
        AdapterEventKindV1::AdapterDiagnostic => item.scheduler_state.clone(),
        AdapterEventKindV1::MechanismIndeterminate => SchedulerStateV1::IndeterminateMechanismState,
    };
    if let Some(question) = &event.human_question {
        if !item
            .human_questions
            .iter()
            .any(|existing| existing.question_id == question.question_id)
        {
            item.human_questions.push(question.clone());
        }
    }
}
