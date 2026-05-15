use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=build.rs");

    emit_git_env(
        "PERU_DNIE_GIT_REVISION",
        &["rev-parse", "--short=12", "HEAD"],
    );
    emit_git_env(
        "PERU_DNIE_GIT_TIME",
        &["show", "-s", "--format=%cI", "HEAD"],
    );

    let clean_build = git_output_allow_empty(&["status", "--porcelain"])
        .map(|status| status.trim().is_empty().to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=PERU_DNIE_CLEAN_BUILD={clean_build}");
}

fn emit_git_env(name: &str, args: &[&str]) {
    let value = git_output(args).unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env={name}={value}");
}

fn git_output(args: &[&str]) -> Option<String> {
    let text = git_output_allow_empty(args)?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn git_output_allow_empty(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}
