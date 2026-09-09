# NQ as a diagnostic and reliance source

Nightshift consumes NQ as evidence, never as standing or action authority. NQ
determines what its complete diagnostic basis supports. Nightshift derives
application posture and attention without re-evaluating diagnostic truth.

## Canonical runtime boundary

The production `nightshift cycle run` request carries an exact closed
`DiagnosticInputs` basis containing canonical NQ diagnostic artifacts.
For every delivered input, Nightshift separately invokes the configured NQ-NG
`diagnostics qualify` read boundary and persists the exact
`nq.diagnostic_admission_provenance.v1` carrier in
`nightshift.observation_record.v2`. The carrier must bind the artifact's full
canonical bytes, local store-genesis source, run, profile semantic identity,
provider admission context, and judgment or refusal/failure disposition.
Imported custody and substitution refuse before a cycle is claimed.
Present support/currentness arrives separately through the exact
`PresentEvidencePortV1` query/response contract. Nightshift does not compare a
raw NQ producer timestamp to its scheduler clock to make the basis actionable.

There is no standalone production `nq disposition` or `nq findings` command in
the canonical CLI. The retained `nq_disposition` module and conformance vectors
are read-only contract specimens used to preserve testimony/refusal semantics;
they do not create a second runtime path.

Nightshift does not link NQ storage internals, parse human prose, or share
authority-bearing Rust types across the repository boundary. Its configured
NQ-NG subprocess opens the source store read-only and returns a closed JSON
carrier. The carrier is historical evidence eligibility, not reliance,
standing, authorization, or permission to act.

## Full-basis preservation

Consequence-bearing posture retains or exactly references the complete basis,
including applicable premises, admitted/failed/refused inputs, acquisition
coordinates, coverage, contradictions, limitations, nonclaims, residuals,
subject/scope, request/run/artifact identity, and projection omissions.

Headline and severity are display/attention projections only. A projection
cannot replace `OperationalPosture.current` or its completeness, coverage, and
recurrence axes.

## Read-only reliance disposition specimen

The native `nq.diagnostic-purpose-support/v1` consumer now requires explicit
request-bound ingestion. Historical `nq.reliance.receipt.v1` vectors remain only
behind an expressly named archive reader; no current-mode fallback exists.
`historical_readonly` is retained-claim consideration, not operational currency.
`continue_observing` fails closed without current-source prerequisites. See
[the R4 qualification boundary](working/gaps/NATIVE_PURPOSE_SUPPORT_RETIREMENT.md).

The consumer preserves these source states (response freshness never implies
source-world freshness):

| Source state | Meaning |
|---|---|
| `Fresh` | current NQ testimony under the supplied external basis |
| `Stale` | historical NQ testimony, not current authority |
| `NoResponse` | Nightshift observed no response; not NQ testimony |
| `TransportUnavailable` | Nightshift transport observation |
| `Malformed` | Nightshift integrity observation |

A fresh refusal is NQ speaking. No answer is Nightshift observing silence.
No synthetic NQ receipt is fabricated when nothing arrived.

The closed read-only vocabulary is:

| NQ decision | Nightshift disposition |
|---|---|
| `authorized_reliance` | `continue_observing` |
| `claim_not_verified` | `request_additional_evidence`—never retry permission |
| `cannot_testify` | `human_judgment_required` |
| `coverage_insufficient` | `human_judgment_required` |
| contradiction, rejected premise, or blocking residual | `human_judgment_required` |
| `stale_evidence` | `wait_for_fresh_evidence` |
| unknown consumer, unauthorized claim/purpose | `stop` |
| malformed/substituted input | `stop` |
| no response | `evidence_unavailable` |

None is an instruction to act. The enum is a bounded read-only directive, not
a diagnosis of its cause. Distinct failures intentionally map to `stop`;
consumers explaining why must retain the complete disposition record,
especially `source_state`, `source`, and `reasons`.

Premises, contradictions, supporting identities, and residuals are carried
verbatim. Nightshift does not resolve or discharge them. A report, headline,
disposition, or receipt cannot create standing, AG authorization, execution
custody, retry permission, or currentness.

## Development evidence

```sh
cargo test --locked --test diagnostic_posture_foundation
cargo test --locked --test nq_reliance_disposition
cargo test --locked --test nq_reliance_conformance
cargo test --locked --test nq_supporting_consumption
```

The NQ reliance fixtures are independent sealed vectors. The successor
diagnostic fixtures round-trip exactly and hostile projection collisions refuse
when a required distinction was omitted.
