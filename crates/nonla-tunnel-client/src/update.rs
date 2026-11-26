//! `upgrade` and `uninstall` for the client — Linux, macOS and Windows.
//!
//! Upgrades download the plain release binary for this platform from GitHub
//! Releases, verify it against the release's `SHA256SUMS.txt`, and replace
//! the running executable in place. No curl/tar/sudo needed.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

const REPO: &str = "devnonla/nonla-tunnel";
const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// Marker lines the installer puts around its PATH entry in shell rc files.
pub const PATH_BLOCK_START: &str = "# >>> nonla-tunnel >>>";
pub const PATH_BLOCK_END: &str = "# <<< nonla-tunnel <<<";
const MAX_DOWNLOAD: u64 = 64 * 1024 * 1024;

/// Release asset label for this build, e.g. `linux-amd64`.
pub fn platform_label() -> Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        ("macos", "aarch64") => "darwin-arm64",
        ("windows", "x86_64") => "windows-amd64",
        ("windows", "aarch64") => "windows-arm64",
        (os, arch) => bail!("no prebuilt nonla-tunnel for {os}/{arch}"),
    })
}

/// Release asset file name for a platform label.
pub fn asset_name(label: &str) -> String {
    if label.starts_with("windows-") {
        format!("nonla-tunnel-{label}.exe")
    } else {
        format!("nonla-tunnel-{label}")
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(&format!("nonla-tunnel/{CURRENT}"))
        .timeout(std::time::Duration::from_secs(120))
        .try_proxy_from_env(true)
        .build()
}

fn get(url: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let resp = agent()
        .get(url)
        .call()
        .map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_DOWNLOAD)
        .read_to_end(&mut buf)
        .with_context(|| format!("read {url}"))?;
    Ok(buf)
}

fn latest_tag() -> Result<String> {
    let body = get(&format!(
        "https://api.github.com/repos/{REPO}/releases/latest"
    ))?;
    let v: serde_json::Value = serde_json::from_slice(&body).context("parse GitHub release")?;
    v["tag_name"]
        .as_str()
        .map(String::from)
        .context("GitHub release has no tag_name")
}

fn parse_version(s: &str) -> (u64, u64, u64) {
    let mut it = s
        .trim_start_matches('v')
        .split(['.', '-'])
        .map(|p| p.parse().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// Check `data` against the `file` entry of a `sha256sum`-style listing.
pub fn verify_checksum(sums: &str, file: &str, data: &[u8]) -> Result<()> {
    let want = sums
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let hash = it.next()?;
            let name = it.next()?.trim_start_matches('*');
            (name == file).then(|| hash.to_ascii_lowercase())
        })
        .next()
        .with_context(|| format!("{file} is not listed in SHA256SUMS.txt"))?;
    let got = nonla_tunnel_protocol::sha256_hex(data);
    if want != got {
        bail!("checksum mismatch for {file}: expected {want}, got {got}");
    }
    Ok(())
}

fn exe_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locate current executable")?;
    Ok(std::fs::canonicalize(&exe).unwrap_or(exe))
}

/// Path a replaced Windows executable is parked at until the next start.
fn old_exe_path(exe: &Path) -> PathBuf {
    exe.with_extension("old.exe")
}

/// Windows cannot overwrite a running .exe, so `upgrade` renames it aside;
/// remove that leftover on the next start. No-op elsewhere.
pub fn cleanup_after_upgrade() {
    if cfg!(windows) {
        if let Ok(exe) = exe_path() {
            let _ = std::fs::remove_file(old_exe_path(&exe));
        }
    }
}

/// Swap the running executable for `data` (atomic rename on Unix).
fn replace_exe(exe: &Path, data: &[u8]) -> Result<()> {
    let dir = exe.parent().context("executable has no parent directory")?;
    let tmp = dir.join(".nonla-tunnel.new");
    std::fs::write(&tmp, data).with_context(|| {
        format!(
            "cannot write to {} — reinstall with the installer, or run upgrade with permission to write there",
            dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    if cfg!(windows) {
        let old = old_exe_path(exe);
        let _ = std::fs::remove_file(&old);
        std::fs::rename(exe, &old).context("move current executable aside")?;
        if let Err(e) = std::fs::rename(&tmp, exe) {
            let _ = std::fs::rename(&old, exe); // roll back
            return Err(e).context("install new executable");
        }
    } else {
        std::fs::rename(&tmp, exe).context("install new executable")?;
    }
    Ok(())
}

pub fn upgrade(version: Option<&str>) -> Result<()> {
    let label = platform_label()?;
    let tag = match version {
        Some(v) => format!("v{}", v.trim_start_matches('v')),
        None => latest_tag()?,
    };
    println!("Current version: v{CURRENT}");
    if version.is_none() && parse_version(&tag) <= parse_version(CURRENT) {
        println!("Already up to date ({tag}).");
        return Ok(());
    }

    let asset = asset_name(label);
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");
    println!("Downloading {asset} ({tag})...");
    let data = get(&format!("{base}/{asset}"))?;
    let sums = String::from_utf8(get(&format!("{base}/SHA256SUMS.txt"))?)
        .context("SHA256SUMS.txt is not text")?;
    verify_checksum(&sums, &asset, &data)?;
    println!("Checksum OK");

    let exe = exe_path()?;
    replace_exe(&exe, &data)?;
    println!("Upgraded {} → {tag}", exe.display());
    println!("Restart background tunnels to use it: nonla-tunnel stop && nonla-tunnel http <port> --name <name> -d");
    Ok(())
}

/// Shell rc files the installer may have edited.
fn rc_files(home: &Path) -> Vec<PathBuf> {
    [".bashrc", ".bash_profile", ".zshrc", ".profile"]
        .iter()
        .map(|f| home.join(f))
        .chain(std::iter::once(home.join(".config/fish/config.fish")))
        .collect()
}

/// Remove the installer's marked PATH block from `text`.
pub fn strip_path_block(text: &str) -> Option<String> {
    if !text.contains(PATH_BLOCK_START) {
        return None;
    }
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line.trim() == PATH_BLOCK_START {
            inside = true;
            continue;
        }
        if inside && line.trim() == PATH_BLOCK_END {
            inside = false;
            continue;
        }
        if !inside {
            out.push(line);
        }
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    Some(s)
}

pub fn uninstall(yes: bool) -> Result<()> {
    let home = crate::platform::home_dir()?;
    let data_dir = crate::config::config_dir()?;
    let exe = exe_path()?;
    let exe_outside = !exe.starts_with(&data_dir);

    println!("This will remove:");
    println!(
        "  • {} (config, credential, claim keys, logs, binary)",
        data_dir.display()
    );
    if exe_outside {
        println!("  • {}", exe.display());
    }
    println!("  • the PATH entry added by the installer");
    if !yes {
        eprint!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // PATH entry
    #[cfg(windows)]
    {
        let bin = data_dir.join("bin");
        let script = format!(
            "$b='{}'; $p=[Environment]::GetEnvironmentVariable('Path','User'); \
             if ($p) {{ $n=($p -split ';' | Where-Object {{ $_ -and $_ -ne $b }}) -join ';'; \
             [Environment]::SetEnvironmentVariable('Path',$n,'User') }}",
            bin.display().to_string().replace('\'', "''")
        );
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status();
    }
    for rc in rc_files(&home) {
        if let Ok(text) = std::fs::read_to_string(&rc) {
            if let Some(new) = strip_path_block(&text) {
                std::fs::write(&rc, new).with_context(|| format!("update {}", rc.display()))?;
                println!("Removed PATH entry from {}", rc.display());
            }
        }
    }

    if exe_outside {
        if cfg!(windows) {
            // A running .exe cannot be deleted; park it for the OS temp cleaner.
            let parked = std::env::temp_dir().join("nonla-tunnel-uninstalled.exe");
            let _ = std::fs::remove_file(&parked);
            let _ = std::fs::rename(&exe, &parked);
        } else {
            let _ = std::fs::remove_file(&exe);
        }
    }

    if data_dir.exists() {
        if cfg!(windows) && !exe_outside {
            // The running binary lives inside data_dir: delete it after we exit.
            let dir = data_dir.display().to_string();
            std::process::Command::new("cmd")
                .args([
                    "/C",
                    &format!("ping -n 3 127.0.0.1 >NUL & rmdir /S /Q \"{dir}\""),
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .context("schedule removal")?;
        } else {
            std::fs::remove_dir_all(&data_dir)
                .with_context(|| format!("remove {}", data_dir.display()))?;
        }
    }
    println!("nonla-tunnel uninstalled.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_assets() {
        assert!(platform_label().is_ok());
        assert_eq!(asset_name("linux-amd64"), "nonla-tunnel-linux-amd64");
        assert_eq!(
            asset_name("windows-arm64"),
            "nonla-tunnel-windows-arm64.exe"
        );
    }

    #[test]
    fn version_ordering() {
        assert!(parse_version("v0.1.1") > parse_version("0.1.0"));
        assert!(parse_version("v1.0.0") > parse_version("0.9.9"));
        assert!(parse_version("v0.1.0") <= parse_version("0.1.0"));
    }

    #[test]
    fn checksum_verification() {
        let h = nonla_tunnel_protocol::sha256_hex(b"bin");
        let sums = format!("deadbeef  other\n{h}  nonla-tunnel-linux-amd64\n");
        assert!(verify_checksum(&sums, "nonla-tunnel-linux-amd64", b"bin").is_ok());
        assert!(verify_checksum(&sums, "nonla-tunnel-linux-amd64", b"evil").is_err());
        assert!(verify_checksum(&sums, "missing", b"bin").is_err());
    }

    #[test]
    fn path_block_removed_cleanly() {
        let rc = format!(
            "alias ll='ls -l'\n{PATH_BLOCK_START}\nexport PATH=\"$HOME/.nonla-tunnel/bin:$PATH\"\n{PATH_BLOCK_END}\nexport EDITOR=vim\n"
        );
        assert_eq!(
            strip_path_block(&rc).unwrap(),
            "alias ll='ls -l'\nexport EDITOR=vim\n"
        );
        assert!(strip_path_block("export A=1\n").is_none());
    }

    #[test]
    fn replace_exe_swaps_file() {
        let dir = std::env::temp_dir().join(format!("nonla-upd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(if cfg!(windows) { "nt.exe" } else { "nt" });
        std::fs::write(&exe, b"old").unwrap();
        replace_exe(&exe, b"new").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert!(!dir.join(".nonla-tunnel.new").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
