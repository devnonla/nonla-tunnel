//! OS-specific bits: home directory, background processes, file permissions.
//! Unix (Linux, macOS) and Windows.

use std::path::{Path, PathBuf};
use std::process::Command;

/// User home: `$HOME`, or `%USERPROFILE%` on Windows.
pub fn home_dir() -> anyhow::Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .or_else(|| std::env::var_os("HOME"))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("{} environment variable not set", var))
}

/// Restrict a file to its owner (0600). On Windows files under the user
/// profile are already private to the user; nothing to do.
pub fn restrict_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

/// Restrict a directory to its owner (0700).
pub fn restrict_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let _ = path;
    Ok(())
}

/// OpenOptions that create files as 0600 on Unix.
pub fn private_open_options() -> std::fs::OpenOptions {
    #[allow(unused_mut)]
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts
}

/// Detach a child from this terminal/session so it survives the parent.
pub fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

/// Whether a process with this PID is running.
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(windows)]
    {
        win::exit_code(pid) == Some(win::STILL_ACTIVE)
    }
}

/// Whether `pid` is still our background tunnel `name` — guards against PID
/// reuse, so we never signal an unrelated process.
pub fn pid_is_tunnel(pid: u32, name: &str) -> bool {
    #[cfg(target_os = "linux")]
    let args: Option<Vec<String>> =
        std::fs::read(format!("/proc/{}/cmdline", pid))
            .ok()
            .map(|raw| {
                raw.split(|b| *b == 0)
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect()
            });
    #[cfg(all(unix, not(target_os = "linux")))]
    let args: Option<Vec<String>> = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(String::from)
                .collect()
        });
    #[cfg(unix)]
    {
        match args {
            Some(args) => {
                args.iter().any(|a| a == "--daemon-child")
                    && args.windows(2).any(|w| w[0] == "--name" && w[1] == name)
            }
            None => false,
        }
    }
    #[cfg(windows)]
    {
        // The command line of another process is not readable without
        // elevated APIs; matching the executable image is enough to rule
        // out PID reuse by an unrelated program.
        let _ = name;
        match (win::image_path(pid), std::env::current_exe()) {
            (Some(img), Ok(me)) => {
                let norm = |p: &Path| p.to_string_lossy().to_ascii_lowercase();
                norm(&img) == norm(&me)
            }
            _ => false,
        }
    }
}

/// Ask a background tunnel to stop.
pub fn terminate(pid: u32) {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    #[cfg(windows)]
    win::terminate(pid);
}

#[cfg(windows)]
mod win {
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    pub const STILL_ACTIVE: u32 = 259;

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn open(pid: u32, access: u32) -> Option<Handle> {
        let h = unsafe { OpenProcess(access, 0, pid) };
        if h.is_null() {
            None
        } else {
            Some(Handle(h))
        }
    }

    pub fn exit_code(pid: u32) -> Option<u32> {
        let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut code = 0u32;
        (unsafe { GetExitCodeProcess(h.0, &mut code) } != 0).then_some(code)
    }

    pub fn image_path(pid: u32) -> Option<PathBuf> {
        let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        if unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut len) } == 0 {
            return None;
        }
        Some(PathBuf::from(String::from_utf16_lossy(
            &buf[..len as usize],
        )))
    }

    pub fn terminate(pid: u32) {
        if let Some(h) = open(pid, PROCESS_TERMINATE) {
            unsafe {
                TerminateProcess(h.0, 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_dir_resolves() {
        assert!(home_dir().is_ok());
    }

    #[test]
    fn own_process_is_alive_and_unrelated_pid_is_not_a_tunnel() {
        assert!(is_pid_alive(std::process::id()));
        // The test runner is not a `--daemon-child` tunnel process.
        #[cfg(unix)]
        assert!(!pid_is_tunnel(std::process::id(), "x"));
    }
}
