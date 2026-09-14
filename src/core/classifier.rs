use std::path::{Path, PathBuf};

use crate::core::aur::AurClient;
use crate::core::types::{SourceClassification, TrustZone};

#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error(transparent)]
    Aur(#[from] crate::core::aur::AurError),
    #[error("local PKGBUILD unreadable: {0}")]
    Local(String),
}

/// Official repos on Arch. Anything found here is Zone 0.
pub const OFFICIAL_REPOS: &[&str] = &[
    "core",
    "extra",
    "multilib",
    "core-testing",
    "extra-testing",
    "multilib-testing",
];

const TRUSTED_REPOS: &[&str] = &["cachyos", "chaotic-aur", "archlinuxcn"];

fn pacman_root() -> PathBuf {
    std::env::var("YARU_PACMAN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/pacman"))
}

/// Sync database repo names on disk (`*.db` under the pacman root's `sync/`).
fn sync_repo_names(root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root.join("sync")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".db").map(|s| s.to_string())
        })
        .collect()
}

/// Repo a package belongs to, derived from an on-disk signal only.
///
/// Membership cannot be established from the sync `*.db` files alone without
/// linking libalpm, so they serve as the known-repo allowlist and the installed
/// entry `local/<pkg>-<version>/desc` supplies the actual repo attribution.
pub fn local_repo_for(package: &str) -> Option<String> {
    local_repo_for_in(&pacman_root(), package)
}

fn local_repo_for_in(root: &Path, package: &str) -> Option<String> {
    let repos = sync_repo_names(root);
    if repos.is_empty() {
        return None;
    }

    let entries = std::fs::read_dir(root.join("local")).ok()?;
    for entry in entries.flatten() {
        if let Some((name, repo)) = desc_metadata(&entry.path()) {
            if name == package && repos.contains(&repo) {
                return Some(repo);
            }
        }
    }
    None
}

fn desc_metadata(entry: &Path) -> Option<(String, String)> {
    let desc = std::fs::read_to_string(entry.join("desc")).ok()?;
    let mut name = None;
    let mut repo = None;
    let mut lines = desc.lines();
    while let Some(line) = lines.next() {
        match line {
            "%NAME%" => name = lines.next().map(str::to_string),
            "%REPOSITORY%" => repo = lines.next().map(str::to_string),
            _ => {}
        }
    }
    Some((name?, repo?))
}

pub fn zone_for_repo(repo: &str) -> TrustZone {
    if repo == "aur" {
        TrustZone::Aur
    } else if OFFICIAL_REPOS.contains(&repo) {
        TrustZone::Official
    } else if TRUSTED_REPOS.contains(&repo) {
        TrustZone::Trusted
    } else if repo.is_empty() {
        TrustZone::Unknown
    } else {
        TrustZone::ThirdParty
    }
}

pub async fn classify(
    package: &str,
    aur: &AurClient,
) -> Result<SourceClassification, ClassifyError> {
    if let Some(repo) = local_repo_for(package) {
        return Ok(SourceClassification {
            package: package.to_string(),
            zone: zone_for_repo(&repo),
            repository: Some(repo),
            version: None,
            maintainer: None,
            url: None,
            url_path: None,
        });
    }

    if let Some(pkg) = aur.info(package).await? {
        return Ok(SourceClassification {
            package: package.to_string(),
            repository: Some("aur".to_string()),
            zone: TrustZone::Aur,
            version: Some(pkg.version),
            maintainer: pkg.maintainer,
            url: pkg.url,
            url_path: pkg.url_path,
        });
    }

    Ok(SourceClassification {
        package: package.to_string(),
        repository: None,
        zone: TrustZone::Unknown,
        version: None,
        maintainer: None,
        url: None,
        url_path: None,
    })
}

pub fn classify_local_pkgbuild(dir: &Path, package: &str) -> SourceClassification {
    let pkgbuild = dir.join("PKGBUILD");
    match std::fs::read_to_string(&pkgbuild) {
        Ok(_) => SourceClassification {
            package: package.to_string(),
            repository: None,
            zone: TrustZone::Aur,
            version: None,
            maintainer: None,
            url: None,
            url_path: None,
        },
        Err(_) => SourceClassification {
            package: package.to_string(),
            repository: None,
            zone: TrustZone::Unknown,
            version: None,
            maintainer: None,
            url: None,
            url_path: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_for_official_repos() {
        assert_eq!(zone_for_repo("core"), TrustZone::Official);
        assert_eq!(zone_for_repo("extra"), TrustZone::Official);
        assert_eq!(zone_for_repo("multilib"), TrustZone::Official);
        assert_eq!(zone_for_repo("core-testing"), TrustZone::Official);
        assert_eq!(zone_for_repo("extra-testing"), TrustZone::Official);
        assert_eq!(zone_for_repo("multilib-testing"), TrustZone::Official);
    }

    #[test]
    fn zone_for_trusted_repos() {
        assert_eq!(zone_for_repo("cachyos"), TrustZone::Trusted);
        assert_eq!(zone_for_repo("chaotic-aur"), TrustZone::Trusted);
        assert_eq!(zone_for_repo("archlinuxcn"), TrustZone::Trusted);
    }

    #[test]
    fn zone_for_aur() {
        assert_eq!(zone_for_repo("aur"), TrustZone::Aur);
    }

    #[test]
    fn zone_for_third_party() {
        assert_eq!(zone_for_repo("some-random-repo"), TrustZone::ThirdParty);
    }

    #[test]
    fn zone_for_empty_is_unknown() {
        assert_eq!(zone_for_repo(""), TrustZone::Unknown);
    }

    fn fixture_root(tmp: &tempfile::TempDir) -> &Path {
        let root = tmp.path();
        std::fs::create_dir_all(root.join("sync")).unwrap();
        std::fs::write(root.join("sync/core.db"), b"").unwrap();
        std::fs::write(root.join("sync/extra.db"), b"").unwrap();
        root
    }

    fn write_desc(root: &Path, dir: &str, name: &str, repo: &str) {
        std::fs::create_dir_all(root.join("local").join(dir)).unwrap();
        std::fs::write(
            root.join("local").join(dir).join("desc"),
            format!("%NAME%\n{name}\n\n%REPOSITORY%\n{repo}\n\n%VERSION%\n1.0-1\n\n"),
        )
        .unwrap();
    }

    #[test]
    fn local_repo_for_reads_installed_package_desc() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = fixture_root(&tmp);
        write_desc(root, "git-2.47.1-1", "git", "extra");

        assert_eq!(local_repo_for_in(root, "git").as_deref(), Some("extra"));
    }

    #[test]
    fn local_repo_for_matches_hyphenated_package_names() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = fixture_root(&tmp);
        write_desc(root, "python-foo-1.0-1", "python-foo", "core");

        assert_eq!(
            local_repo_for_in(root, "python-foo").as_deref(),
            Some("core")
        );
    }

    #[test]
    fn local_repo_for_unknown_package_is_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = fixture_root(&tmp);
        write_desc(root, "git-2.47.1-1", "git", "extra");

        assert!(local_repo_for_in(root, "google-chrome").is_none());
    }

    #[test]
    fn local_repo_for_repo_absent_from_sync_db_is_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = fixture_root(&tmp);
        write_desc(root, "mything-1.0-1", "mything", "ghost-repo");

        assert!(local_repo_for_in(root, "mything").is_none());
    }

    #[test]
    fn local_repo_for_missing_root_is_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(local_repo_for_in(tmp.path(), "anything").is_none());
    }

    #[test]
    fn local_repo_for_honours_pacman_root_env_var() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = fixture_root(&tmp);
        write_desc(root, "git-2.47.1-1", "git", "extra");

        unsafe { std::env::set_var("YARU_PACMAN_ROOT", root) };
        let resolved = local_repo_for("git");
        unsafe { std::env::remove_var("YARU_PACMAN_ROOT") };

        assert_eq!(resolved.as_deref(), Some("extra"));
    }

    #[test]
    fn classify_local_pkgbuild_missing_file_is_unknown() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = classify_local_pkgbuild(tmp.path(), "foo");
        assert_eq!(result.zone, TrustZone::Unknown);
        assert_eq!(result.package, "foo");
    }

    #[test]
    fn classify_local_pkgbuild_present_is_aur() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("PKGBUILD"), b"pkgname=foo\n").unwrap();
        let result = classify_local_pkgbuild(tmp.path(), "foo");
        assert_eq!(result.zone, TrustZone::Aur);
        assert_eq!(result.package, "foo");
    }
}
