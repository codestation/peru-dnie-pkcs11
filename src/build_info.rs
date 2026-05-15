//! Compile-time package and Git metadata.

/// Application/package name compiled into the module.
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// Cargo package version compiled into the module.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Git commit id captured by `build.rs`.
pub const GIT_REVISION: &str = env!("PERU_DNIE_GIT_REVISION");

/// Git commit timestamp captured by `build.rs`.
pub const GIT_TIME: &str = env!("PERU_DNIE_GIT_TIME");

/// Whether the worktree was clean when built.
pub const CLEAN_BUILD: &str = env!("PERU_DNIE_CLEAN_BUILD");

/// Logs build metadata at startup when runtime logging is enabled.
pub fn log_startup_metadata() {
    crate::log_info!(
        "module metadata: app={}, version={}, git_revision={}, git_time={}, clean_build={}",
        APP_NAME,
        VERSION,
        GIT_REVISION,
        GIT_TIME,
        CLEAN_BUILD
    );
}
