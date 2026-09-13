//! Deterministic read-only casework projections over exact Nightshift packet
//! and run-receipt bytes.
//!
//! This crate is an operator inspection tool. It creates no authorization,
//! aggregate result, retry, execution request, or canonical runtime state.

mod live_capacity;
mod live_execution;
mod live_loader;
mod live_model;
mod loader;
mod model;
mod operational_loader;
mod operational_model;
pub mod server;
pub mod static_ui;

pub use live_loader::{load_live_run_at, LiveCaseworkError, LoadedLiveRun};
pub use live_model::*;
pub use loader::{load_run_at, load_runs_at, CaseworkError, LoadedRun};
pub use model::*;
pub use operational_loader::{
    load_operational_conditions_at, LoadedOperationalCondition, OperationalCaseworkError,
};
pub use operational_model::*;
