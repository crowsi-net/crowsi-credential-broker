//! IPC scenarios share one executable while remaining separate test modules.

#[path = "../ipc_support/mod.rs"]
mod ipc_support;

#[path = "../ipc_binding.rs"]
mod ipc_binding;
#[path = "../ipc_cli.rs"]
mod ipc_cli;
#[path = "../ipc_enrollment.rs"]
mod ipc_enrollment;
#[path = "../ipc_framing.rs"]
mod ipc_framing;
#[path = "../ipc_replay.rs"]
mod ipc_replay;
#[path = "../ipc_store_failure.rs"]
mod ipc_store_failure;
