use std::{env, fmt};

/// Log level accepted by `PERU_DNIE_LOG`.
///
/// Messages are written to stderr and must never include PINs, CAN codes,
/// secure messaging keys, private keys, private key material, or sensitive APDU
/// payload bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// Returns true when `level` is enabled by `PERU_DNIE_LOG` or
/// `PERU_DNIE_DEBUG`.
pub fn enabled(level: Level) -> bool {
    configured_level().is_some_and(|configured| level <= configured)
}

/// Emits a sanitized module log message to stderr when the level is enabled.
pub fn log(level: Level, args: fmt::Arguments<'_>) {
    if enabled(level) {
        eprintln!("[peru-dnie] {}: {}", level.as_str(), args);
    }
}

fn configured_level() -> Option<Level> {
    if env_flag("PERU_DNIE_DEBUG") {
        return Some(Level::Debug);
    }
    parse_level(&env::var("PERU_DNIE_LOG").unwrap_or_else(|_| "none".to_owned()))
}

fn parse_level(value: &str) -> Option<Level> {
    match value.trim().to_ascii_lowercase().as_str() {
        "error" => Some(Level::Error),
        "warn" => Some(Level::Warn),
        "info" => Some(Level::Info),
        "debug" => Some(Level::Debug),
        "trace" => Some(Level::Trace),
        "none" | "" => None,
        _ => None,
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name).is_ok_and(|v| parse_bool_flag(&v))
}

fn parse_bool_flag(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value == "1" || value == "true"
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Error, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Warn, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Info, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Debug, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        $crate::logging::log($crate::logging::Level::Trace, format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_log_levels_case_insensitively() {
        assert_eq!(parse_level(" ERROR "), Some(Level::Error));
        assert_eq!(parse_level("warn"), Some(Level::Warn));
        assert_eq!(parse_level("Info"), Some(Level::Info));
        assert_eq!(parse_level("debug"), Some(Level::Debug));
        assert_eq!(parse_level("trace"), Some(Level::Trace));
        assert_eq!(parse_level("none"), None);
        assert_eq!(parse_level(""), None);
        assert_eq!(parse_level("verbose"), None);
    }

    #[test]
    fn parses_debug_flag_values() {
        assert!(parse_bool_flag("1"));
        assert!(parse_bool_flag(" true "));
        assert!(parse_bool_flag("TRUE"));
        assert!(!parse_bool_flag("0"));
        assert!(!parse_bool_flag("false"));
        assert!(!parse_bool_flag(""));
    }
}
