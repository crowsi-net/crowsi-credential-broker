//! Lease and status contracts share one integration-test executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../bound_leases.rs"]
mod bound_leases;
#[path = "../broker.rs"]
mod broker;
#[path = "../lease_capacity.rs"]
mod lease_capacity;
#[path = "../lease_metadata_port.rs"]
mod lease_metadata_port;
#[path = "../status_contract.rs"]
mod status_contract;
#[path = "../status_limits.rs"]
mod status_limits;
