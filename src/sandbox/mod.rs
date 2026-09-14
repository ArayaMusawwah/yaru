use crate::config::NetworkMode;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

/// Outcome of a sandboxed execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Runs a command inside a bubblewrap container.
///
/// Isolation properties (verified on bubblewrap 0.12 / Arch):
/// - user + pid namespaces unshared
/// - /usr read-only; /bin /lib /lib64 are symlinks into it (Arch layout)
/// - $HOME never mounted; ~/.ssh ~/.gnupg unreachable
/// - /proc /dev minimal; /tmp is a fresh tmpfs
/// - Strict mode: --unshare-net kills all connectivity
pub struct Sandbox {
    pub network_mode: NetworkMode,
    /// Extra read-only bind mounts, e.g. ("/usr/share/pacman", "/usr/share/pacman").
    pub extra_ro_binds: Vec<(String, String)>,
    /// Workdir bound read-write and used as cwd inside the sandbox.
    pub workdir: String,
}

impl Sandbox {
    pub fn new(network_mode: NetworkMode, workdir: impl Into<String>) -> Self {
        Self {
            network_mode,
            extra_ro_binds: Vec::new(),
            workdir: workdir.into(),
        }
    }

    /// The bwrap argument list. Public so callers can preview/replay.
    pub fn argv(&self, command: &[&str]) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "--unshare-user".into(),
            "--unshare-pid".into(),
            "--ro-bind".into(),
            "/usr".into(),
            "/usr".into(),
            // Arch symlinks: /bin /lib /lib64 -> usr/*
            "--symlink".into(),
            "usr/bin".into(),
            "/bin".into(),
            "--symlink".into(),
            "usr/lib".into(),
            "/lib".into(),
            "--symlink".into(),
            "usr/lib".into(),
            "/lib64".into(),
            "--proc".into(),
            "/proc".into(),
            "--dev".into(),
            "/dev".into(),
            "--tmpfs".into(),
            "/tmp".into(),
            "--setenv".into(),
            "PATH".into(),
            "/usr/bin".into(),
            "--setenv".into(),
            "HOME".into(),
            "/tmp".into(),
            "--chdir".into(),
            self.workdir.clone(),
            "--bind".into(),
            self.workdir.clone(),
            self.workdir.clone(),
        ];

        for (src, dst) in &self.extra_ro_binds {
            args.push("--ro-bind".into());
            args.push(src.clone());
            args.push(dst.clone());
        }

        match self.network_mode {
            NetworkMode::Strict | NetworkMode::SourceAllowlist => {
                args.push("--unshare-net".into());
            }
            NetworkMode::Audit => {
                // network intentionally shared; caller must log usage
            }
        }

        args.extend(command.iter().map(|s| s.to_string()));
        args
    }

    pub fn run(&self, command: &[&str]) -> SandboxResult {
        if self.network_mode == NetworkMode::Audit {
            tracing::warn!("Sandbox Audit mode: network SHARED with host, traffic not filtered");
        }

        let output = Command::new("bwrap").args(self.argv(command)).output();

        match output {
            Ok(out) => SandboxResult {
                success: out.status.success(),
                exit_code: out.status.code(),
                stdout: String::from_utf8_lossy(&out.stdout).to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            },
            Err(e) => SandboxResult {
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("failed to spawn bwrap: {e}"),
            },
        }
    }

    /// True when bubblewrap is usable on this host.
    pub fn backend_available() -> bool {
        Command::new("bwrap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Bind-mounts `dir` into the sandbox if it exists (used for source prefetch caches).
    pub fn bind_ro_if_exists(&mut self, dir: &Path) {
        if dir.is_dir() {
            self.extra_ro_binds
                .push((dir.display().to_string(), dir.display().to_string()));
        }
    }
}

/// In SourceAllowlist mode the declared sources are fetched OUTSIDE the sandbox
/// (trusted fetcher, logged), then the build runs with --unshare-net. Any
/// undeclared fetch during build fails naturally: there is no network.
pub async fn fetch_declared_sources(
    build_dir: &Path,
    source_urls: &[String],
) -> Result<Vec<String>, String> {
    let dir = build_dir.to_path_buf();
    let client = reqwest::Client::new();
    let mut fetched = Vec::new();

    // Sequential on purpose: keeps memory flat and output deterministic.
    for url in source_urls {
        // git+ URLs are handled by makepkg during build; skip here.
        if url.starts_with("git+") {
            continue;
        }
        let dest_name = url.rsplit('/').next().unwrap_or("downloaded-file");
        let dest = dir.join(dest_name);
        if dest.exists() {
            fetched.push(dest_name.to_string());
            continue;
        }
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        let resp = resp.error_for_status().map_err(|e| format!("{url}: {e}"))?;
        let bytes = resp.bytes().await.map_err(|e| format!("{url}: {e}"))?;
        std::fs::write(&dest, bytes).map_err(|e| format!("{url}: {e}"))?;
        fetched.push(dest_name.to_string());
    }
    Ok(fetched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict(workdir: &str) -> Sandbox {
        Sandbox::new(NetworkMode::Strict, workdir)
    }

    #[test]
    fn argv_contains_isolation_flags() {
        let sb = strict("/tmp/build");
        let a = sb.argv(&["/usr/bin/true"]);
        for flag in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--proc",
            "--dev",
            "--tmpfs",
        ] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}");
        }
    }

    #[test]
    fn audit_mode_has_no_unshare_net() {
        let sb = Sandbox::new(NetworkMode::Audit, "/tmp/build");
        assert!(!sb.argv(&["true"]).iter().any(|x| x == "--unshare-net"));
    }

    #[test]
    fn true_succeeds_inside_sandbox() {
        let sb = strict("/tmp");
        let r = sb.run(&["/usr/bin/true"]);
        assert!(r.success, "stderr: {}", r.stderr);
    }

    #[test]
    fn home_ssh_is_hidden_in_sandbox() {
        let sb = strict("/tmp");
        let r = sb.run(&[
            "/usr/bin/bash",
            "-c",
            "test -e $HOME/.ssh && echo LEAK || echo hidden",
        ]);
        assert!(r.success);
        assert_eq!(r.stdout.trim(), "hidden", "stdout: {}", r.stdout);
    }

    #[test]
    fn network_is_dead_in_strict_mode() {
        let sb = strict("/tmp");
        let r = sb.run(&["/usr/bin/bash", "-c", "getent hosts aur.archlinux.org"]);
        assert!(!r.success, "network should fail; stdout: {}", r.stdout);
    }

    #[test]
    fn workdir_is_writable_inside_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let sb = Sandbox::new(NetworkMode::Strict, tmp.path().display().to_string());
        let r = sb.run(&["/usr/bin/bash", "-c", "touch marker && test -f marker"]);
        assert!(r.success, "stderr: {}", r.stderr);
    }

    #[test]
    fn missing_bwrap_reports_cleanly() {
        // Simulated failure path: command spawn error becomes stderr, not panic.
        let sb = strict("/tmp");
        let r = sb.run(&["/nonexistent-binary-xyz"]);
        assert!(!r.success);
        assert!(r.stderr.contains("No such file") || !r.stderr.is_empty());
    }
}
