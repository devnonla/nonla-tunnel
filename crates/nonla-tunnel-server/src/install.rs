//! Client installers on the apex host:
//!
//! - `GET /install` (alias `/install.sh`) — POSIX sh installer for Linux/macOS
//! - `GET /install.ps1` — PowerShell installer for Windows
//!
//! Both are the repo's `scripts/install.{sh,ps1}` with this server's version
//! and control address filled in, so `curl -fsSL https://<domain>/install | sh
//! -s -- --invite …` installs the matching client and enrolls it. Binaries
//! come from GitHub Releases and are checksum-verified by the script.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

const INSTALL_SH: &str = include_str!("../../../scripts/install.sh");
const INSTALL_PS1: &str = include_str!("../../../scripts/install.ps1");

#[derive(Clone)]
pub struct InstallState {
    /// Client version to install (this server's version).
    pub version: String,
    /// Control address clients enroll against, e.g. `connect.example.com:443`.
    pub server: String,
    /// Extra `enroll` flags, e.g. `--no-tls` when Traefik is not in front.
    pub enroll_flags: Vec<String>,
}

pub fn create_router(state: InstallState) -> Router {
    Router::new()
        .route("/install", get(serve_sh))
        .route("/install.sh", get(serve_sh))
        .route("/install.ps1", get(serve_ps1))
        .with_state(state)
}

/// Replace exactly one `from` line; the scripts' placeholders are fixed text.
fn set_line(script: &str, from: &str, to: &str) -> String {
    debug_assert!(script.contains(from), "placeholder {from:?} missing");
    script.replacen(from, to, 1)
}

pub fn render_sh(state: &InstallState) -> String {
    // Values are a version string and a validated DNS name + port: no quoting issues.
    let s = set_line(
        INSTALL_SH,
        "NONLA_DEFAULT_VERSION=\"\"",
        &format!("NONLA_DEFAULT_VERSION=\"{}\"", state.version),
    );
    let s = set_line(
        &s,
        "NONLA_DEFAULT_SERVER=\"\"",
        &format!("NONLA_DEFAULT_SERVER=\"{}\"", state.server),
    );
    set_line(
        &s,
        "NONLA_DEFAULT_ENROLL_FLAGS=\"\"",
        &format!(
            "NONLA_DEFAULT_ENROLL_FLAGS=\"{}\"",
            state.enroll_flags.join(" ")
        ),
    )
}

pub fn render_ps1(state: &InstallState) -> String {
    let s = set_line(
        INSTALL_PS1,
        "$NonlaDefaultVersion = ''",
        &format!("$NonlaDefaultVersion = '{}'", state.version),
    );
    let s = set_line(
        &s,
        "$NonlaDefaultServer = ''",
        &format!("$NonlaDefaultServer = '{}'", state.server),
    );
    let flags = state
        .enroll_flags
        .iter()
        .map(|f| format!("'{}'", f))
        .collect::<Vec<_>>()
        .join(",");
    set_line(
        &s,
        "$NonlaDefaultEnrollFlags = @()",
        &format!("$NonlaDefaultEnrollFlags = @({})", flags),
    )
}

async fn serve_sh(State(state): State<InstallState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        render_sh(&state),
    )
}

async fn serve_ps1(State(state): State<InstallState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        render_ps1(&state),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(flags: &[&str]) -> InstallState {
        InstallState {
            version: "0.1.0".into(),
            server: "connect.t.example.com:443".into(),
            enroll_flags: flags.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn sh_has_server_defaults_and_is_valid() {
        let s = render_sh(&state(&[]));
        assert!(s.contains("NONLA_DEFAULT_VERSION=\"0.1.0\""));
        assert!(s.contains("NONLA_DEFAULT_SERVER=\"connect.t.example.com:443\""));
        assert!(s.contains("NONLA_DEFAULT_ENROLL_FLAGS=\"\""));
        let path = std::env::temp_dir().join(format!("nonla-install-{}.sh", uuid::Uuid::new_v4()));
        std::fs::write(&path, &s).unwrap();
        let ok = std::process::Command::new("sh")
            .arg("-n")
            .arg(&path)
            .status()
            .unwrap()
            .success();
        let _ = std::fs::remove_file(&path);
        assert!(ok);
    }

    #[test]
    fn sh_parses_options() {
        // Run only the option parsing part of the script.
        let s = render_sh(&state(&[]));
        let end = s.find("# --- platform").unwrap();
        let prefix = &s[..end];
        for args in [
            &["--invite", "nti_abc", "--server", "x.example.com"][..],
            &["--invite=nti_abc", "--server=x.example.com"][..],
        ] {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("{prefix}\necho \"$INVITE $SERVER $VERSION\""))
                .arg("install")
                .args(args)
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                "nti_abc x.example.com 0.1.0"
            );
        }
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{prefix}\necho ok"))
            .arg("install")
            .arg("--bogus")
            .output()
            .unwrap();
        assert!(!out.status.success());
    }

    #[test]
    fn ps1_has_server_defaults() {
        let s = render_ps1(&state(&["--no-tls"]));
        assert!(s.contains("$NonlaDefaultVersion = '0.1.0'"));
        assert!(s.contains("$NonlaDefaultServer = 'connect.t.example.com:443'"));
        assert!(s.contains("$NonlaDefaultEnrollFlags = @('--no-tls')"));
    }

    #[test]
    fn placeholders_exist_in_repo_scripts() {
        for p in [
            "NONLA_DEFAULT_VERSION=\"\"",
            "NONLA_DEFAULT_SERVER=\"\"",
            "NONLA_DEFAULT_ENROLL_FLAGS=\"\"",
        ] {
            assert_eq!(INSTALL_SH.matches(p).count(), 1, "{p}");
        }
        for p in [
            "$NonlaDefaultVersion = ''",
            "$NonlaDefaultServer = ''",
            "$NonlaDefaultEnrollFlags = @()",
        ] {
            assert_eq!(INSTALL_PS1.matches(p).count(), 1, "{p}");
        }
    }
}
