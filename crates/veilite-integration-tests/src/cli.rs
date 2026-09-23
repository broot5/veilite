// Reuse the production entry point for CLI integration tests. `--all-targets`
// also builds a test harness for this binary; keep CLI unit tests in their crate.
#[cfg(not(test))]
include!("../../veilite-cli/src/main.rs");
