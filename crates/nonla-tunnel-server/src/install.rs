//! Client distribution on the apex host: `GET /install` (shell script) and
//! `GET /download/:filename` (prebuilt client binaries). No UI, no auth.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

#[derive(Clone)]
pub struct InstallState {
    pub domain: String,
    /// `config set` arguments for this server, e.g. `--server connect.<domain>:443`.
    pub connect_hint: String,
    pub clients_dir: String,
}

pub fn create_router(state: InstallState) -> Router {
    Router::new()
        .route("/install", get(serve_install_script))
        .route("/download/:filename", get(serve_download))
        .with_state(state)
}

async fn serve_install_script(State(state): State<InstallState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        render_install_script(&state),
    )
}

fn render_install_script(state: &InstallState) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

# Usage: curl -sSL https://{domain}/install | bash -s -- [--invite nti_...]
INVITE="${{NONLA_INVITE:-}}"
while [ $# -gt 0 ]; do
  case "$1" in
    --invite) INVITE="${{2:-}}"; shift 2 ;;
    --invite=*) INVITE="${{1#*=}}"; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

DOMAIN="{domain}"
BASE="https://${{DOMAIN}}"
INSTALL_DIR="$HOME/.nonla-tunnel/bin"
CURL="curl --proto =https --tlsv1.2 -fsSL"
mkdir -p "$INSTALL_DIR"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
  linux) OS_LABEL=linux ;;
  darwin) OS_LABEL=darwin ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH_LABEL=amd64 ;;
  aarch64|arm64) ARCH_LABEL=arm64 ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

FILE="nonla-tunnel-${{OS_LABEL}}-${{ARCH_LABEL}}"
SRC_FILE="nonla-tunnel-src.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sha256() {{
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}}

# Verify $1 (downloaded as $2) against the server's SHA256SUMS.
verify() {{
  if ! $CURL "${{BASE}}/download/SHA256SUMS" -o "$TMP/SHA256SUMS"; then
    echo "❌ ${{BASE}}/download/SHA256SUMS not available — refusing to install unverified binary"
    exit 1
  fi
  want="$(awk -v f="$1" '$2 == f || $2 == "*"f {{ print $1 }}' "$TMP/SHA256SUMS" | head -1)"
  got="$(sha256 "$2")"
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "❌ Checksum mismatch for $1 (want ${{want:-none}}, got $got)"
    exit 1
  fi
  echo "▸ Checksum OK"
}}

install_from_source() {{
  echo "▸ Prebuilt binary not available for ${{OS_LABEL}}-${{ARCH_LABEL}}"
  echo "▸ Building nonla-tunnel from source (needs Rust + network)..."
  $CURL "${{BASE}}/download/${{SRC_FILE}}" -o "$TMP/src.tar.gz"
  verify "$SRC_FILE" "$TMP/src.tar.gz"
  if ! command -v cargo >/dev/null 2>&1; then
    echo "▸ Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  mkdir -p "$TMP/src"
  tar -xzf "$TMP/src.tar.gz" -C "$TMP/src"
  cargo build --release --manifest-path "$TMP/src/Cargo.toml" -p nonla-tunnel-client
  install -m 755 "$TMP/src/target/release/nonla-tunnel" "$INSTALL_DIR/nonla-tunnel"
}}

echo "▸ Downloading ${{FILE}}..."
if $CURL "${{BASE}}/download/${{FILE}}" -o "$TMP/$FILE"; then
  verify "$FILE" "$TMP/$FILE"
  install -m 755 "$TMP/$FILE" "$INSTALL_DIR/nonla-tunnel"
else
  install_from_source
fi

SHELL_RC=""
case "${{SHELL:-}}" in
  */zsh) SHELL_RC="$HOME/.zshrc" ;;
  */bash) SHELL_RC="$HOME/.bashrc" ;;
  *) SHELL_RC="$HOME/.profile" ;;
esac
if [ -n "$SHELL_RC" ] && ! grep -q '.nonla-tunnel/bin' "$SHELL_RC" 2>/dev/null; then
  echo 'export PATH="$HOME/.nonla-tunnel/bin:$PATH"' >> "$SHELL_RC"
fi
export PATH="$INSTALL_DIR:$PATH"

echo "✅ nonla-tunnel installed to $INSTALL_DIR/nonla-tunnel"
echo

if [ -n "$INVITE" ]; then
  echo "▸ Enrolling with one-time invite..."
  NONLA_INVITE="$INVITE" "$INSTALL_DIR/nonla-tunnel" enroll {connect_hint}
  echo
  echo "Next:"
  echo "  nonla-tunnel http 3000 --name my-app -d"
else
  echo "Next (invite from: nonla-tunnel-server invite):"
  echo "  nonla-tunnel enroll {connect_hint} --invite <nti_...>"
  echo "  nonla-tunnel http 3000 --name my-app -d"
fi
"#,
        domain = state.domain,
        connect_hint = state.connect_hint,
    )
}

async fn serve_download(
    State(state): State<InstallState>,
    axum::extract::Path(filename): axum::extract::Path<String>,
) -> Result<Response, (StatusCode, String)> {
    if !filename
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        || filename.contains("..")
    {
        return Err((StatusCode::BAD_REQUEST, "invalid filename".to_string()));
    }

    let path = std::path::Path::new(&state.clients_dir).join(&filename);
    let (path, disposition) = if path.is_file() {
        (path, filename.clone())
    } else {
        let alt = std::path::Path::new(&state.clients_dir).join(format!("{}.tar.gz", filename));
        if alt.is_file() {
            let name = alt.file_name().unwrap().to_string_lossy().into_owned();
            (alt, name)
        } else {
            return Err((StatusCode::NOT_FOUND, format!("{} not found", filename)));
        }
    };

    let data = std::fs::read(&path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read error: {}", e),
        )
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", disposition),
        )
        .body(axum::body::Body::from(data))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script() -> String {
        render_install_script(&InstallState {
            domain: "t.example.com".into(),
            connect_hint: "--server connect.t.example.com:443".into(),
            clients_dir: "/nonexistent".into(),
        })
    }

    #[test]
    fn install_script_is_valid_bash() {
        let path = std::env::temp_dir().join(format!("nonla-install-{}.sh", uuid::Uuid::new_v4()));
        std::fs::write(&path, script()).unwrap();
        let ok = std::process::Command::new("bash")
            .arg("-n")
            .arg(&path)
            .status()
            .unwrap()
            .success();
        let _ = std::fs::remove_file(&path);
        assert!(ok);
    }

    #[test]
    fn install_script_parses_invite_arg() {
        // Run only the argument-parsing prefix of the script.
        let s = script();
        let prefix = &s[..s.find("DOMAIN=").unwrap()];
        for args in [&["--invite", "nti_abc"][..], &["--invite=nti_abc"][..]] {
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("{prefix}\necho \"$INVITE\""))
                .arg("install")
                .args(args)
                .output()
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "nti_abc");
        }
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("{prefix}\necho ok"))
            .arg("install")
            .arg("--bogus")
            .output()
            .unwrap();
        assert!(!out.status.success());
    }

    #[test]
    fn install_script_enrolls_with_connect_hint() {
        let s = script();
        assert!(s.contains("enroll --server connect.t.example.com:443"));
        // Passed via env so the invite is not visible in `ps`.
        assert!(s.contains("NONLA_INVITE=\"$INVITE\""));
    }
}
