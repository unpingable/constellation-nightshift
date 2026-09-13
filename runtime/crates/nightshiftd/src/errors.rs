use thiserror::Error;

/// A closed classification of NQ interface-contract violations. NS
/// speaks a specific NQ export contract; these are the ways an inbound
/// export can fail to honor it. Deliberately a *category* taxonomy, not
/// a pin to today's wire schema: nq-ng (`~/git/skunkworks/nq-ng`) is
/// being rebuilt correctness-first, and these categories survive a wire
/// redesign even as the concrete schema id / field set changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NqContractViolationKind {
    /// The export declared a `schema` id NS does not speak.
    SchemaMismatch,
    /// The export's `contract_version` is not the one NS speaks.
    ContractVersionMismatch,
    /// A field NS requires was present but unparseable (e.g. a
    /// timestamp that is not RFC3339).
    MalformedField,
}

#[derive(Debug, Error)]
pub enum NightShiftError {
    /// A violation of the NQ export/interface contract. Distinct from
    /// `InvalidAgenda`: an NQ refusal arrives in its own stratum rather
    /// than wearing agenda vocabulary (no-vocabulary-laundering). The
    /// `detail` carries the specific mismatch for operator display.
    #[error("NQ contract violation ({kind:?}): {detail}")]
    NqContractViolation {
        kind: NqContractViolationKind,
        detail: String,
    },
}

pub type Result<T, E = NightShiftError> = std::result::Result<T, E>;
