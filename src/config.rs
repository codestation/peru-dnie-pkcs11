use std::{env, fs, path::PathBuf};

/// Runtime configuration loaded from environment and optional user config.
#[derive(Default)]
pub struct Config {
    /// Manually configured issuer/intermediate certificate files.
    ///
    /// A non-empty value disables AIA discovery and cache use for signing.
    pub cert_chain: Vec<PathBuf>,
    /// Optional Card Access Number used to establish PACE secure messaging.
    pub can: Option<String>,
}

/// Loads module configuration.
///
/// `PERU_DNIE_CERT_CHAIN` takes precedence over the optional
/// `~/.config/peru-dnie-pkcs11/config.toml` `cert_chain` value.
pub fn load() -> Config {
    let mut cfg = Config::default();
    let env_chain = env::var("PERU_DNIE_CERT_CHAIN")
        .ok()
        .filter(|chain| !chain.is_empty());
    let env_can = env::var("PERU_DNIE_CAN").ok().filter(|v| !v.is_empty());

    let Some(home) = env::var_os("HOME") else {
        cfg.cert_chain = chain_paths(env_chain.as_deref());
        cfg.can = env_can;
        return cfg;
    };
    let path = PathBuf::from(home).join(".config/peru-dnie-pkcs11/config.toml");
    let Ok(text) = fs::read_to_string(path) else {
        cfg.cert_chain = chain_paths(env_chain.as_deref());
        cfg.can = env_can;
        return cfg;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(v) = quoted_value(line, "cert_chain") {
            cfg.cert_chain = chain_paths(Some(v));
        }
        if let Some(v) = quoted_value(line, "can").filter(|v| !v.is_empty()) {
            cfg.can = Some(v.to_owned());
        }
    }
    if env_chain.is_some() {
        cfg.cert_chain = chain_paths(env_chain.as_deref());
    }
    if let Some(can) = env_can {
        cfg.can = Some(can);
    }
    cfg
}

fn quoted_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let quote = rest.as_bytes().first().copied()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    rest[1..].split_once(quote as char).map(|(v, _)| v)
}

fn chain_paths(value: Option<&str>) -> Vec<PathBuf> {
    value
        .into_iter()
        .flat_map(|chain| chain.split(':'))
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_value_accepts_single_and_double_quotes() {
        assert_eq!(
            quoted_value("cert_chain = '/a:/b'", "cert_chain"),
            Some("/a:/b")
        );
        assert_eq!(
            quoted_value("cert_chain = \"/a:/b\"", "cert_chain"),
            Some("/a:/b")
        );
        assert_eq!(quoted_value("other = \"/a\"", "cert_chain"), None);
        assert_eq!(quoted_value("cert_chain = /a", "cert_chain"), None);
    }

    #[test]
    fn chain_paths_ignores_empty_segments() {
        let paths = chain_paths(Some(":/one::/two:"));
        assert_eq!(paths, vec![PathBuf::from("/one"), PathBuf::from("/two")]);
        assert!(chain_paths(None).is_empty());
        assert!(chain_paths(Some("")).is_empty());
    }
}
