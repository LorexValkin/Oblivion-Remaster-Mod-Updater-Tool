use crate::archive::{copy_tree, extract_archive, sha256_file};
use crate::game::validate_game_install;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use sysinfo::System;
use walkdir::WalkDir;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum DependencyKind {
    UE4SS,
    TesSyncMapInjector,
}

impl fmt::Display for DependencyKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UE4SS => "UE4SS",
            Self::TesSyncMapInjector => "TesSyncMapInjector",
        })
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyCandidate {
    pub path: PathBuf,
    pub source: String,
    pub kinds: Vec<DependencyKind>,
    pub input_type: String,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledKind {
    pub installed: bool,
    pub files: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledState {
    pub ue4ss: InstalledKind,
    pub tes_sync_map_injector: InstalledKind,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledFile {
    pub kind: DependencyKind,
    pub relative_path: String,
    pub action: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyReport {
    pub game_root: PathBuf,
    pub candidates: Vec<DependencyCandidate>,
    pub before: InstalledState,
    pub requested_install: bool,
    pub installed_files: Vec<InstalledFile>,
    pub backup_root: Option<PathBuf>,
    pub after: InstalledState,
    pub ready: bool,
}

pub fn installed_state(game_root: &Path) -> InstalledState {
    let win64 = game_root.join(r"OblivionRemastered\Binaries\Win64");
    let ue4ss_files = vec![win64.join("dwmapi.dll"), win64.join(r"ue4ss\UE4SS.dll")];
    let injector_files = vec![
        win64.join(r"ue4ss\Mods\TesSyncMapInjector\Scripts\main.lua"),
        win64.join(r"ue4ss\Mods\TesSyncMapInjector\enabled.txt"),
    ];
    InstalledState {
        ue4ss: InstalledKind {
            installed: ue4ss_files.iter().all(|path| path.is_file()),
            files: ue4ss_files,
        },
        tes_sync_map_injector: InstalledKind {
            installed: injector_files.iter().all(|path| path.is_file()),
            files: injector_files,
        },
    }
}

fn payload_roots(root: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut ue4ss = Vec::new();
    let mut injector = Vec::new();
    let directories = std::iter::once(root.to_path_buf()).chain(
        WalkDir::new(root)
            .max_depth(8)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_dir())
            .map(|entry| entry.path().to_path_buf()),
    );
    for directory in directories {
        if directory.join("dwmapi.dll").is_file() && directory.join(r"ue4ss\UE4SS.dll").is_file() {
            ue4ss.push(directory.clone());
        }
        if directory
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("TesSyncMapInjector"))
            && directory.join(r"Scripts\main.lua").is_file()
            && directory.join("enabled.txt").is_file()
        {
            injector.push(directory);
        }
    }
    ue4ss.sort();
    ue4ss.dedup();
    injector.sort();
    injector.dedup();
    (ue4ss, injector)
}

fn inspect_candidate(path: &Path, source: &str) -> Result<Option<DependencyCandidate>> {
    if !path.exists() {
        return Ok(None);
    }
    let temporary;
    let root = if path.is_dir() {
        path
    } else {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension != "zip" && extension != "7z" && extension != "rar" {
            return Ok(None);
        }
        temporary = tempfile::Builder::new()
            .prefix("obr-dependency-scan-")
            .tempdir()?;
        if extract_archive(path, temporary.path()).is_err() {
            return Ok(None);
        }
        temporary.path()
    };
    let (ue4ss, injector) = payload_roots(root);
    let mut kinds = Vec::new();
    if !ue4ss.is_empty() {
        kinds.push(DependencyKind::UE4SS);
    }
    if !injector.is_empty() {
        kinds.push(DependencyKind::TesSyncMapInjector);
    }
    if kinds.is_empty() {
        return Ok(None);
    }
    Ok(Some(DependencyCandidate {
        path: fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
        source: source.to_owned(),
        kinds,
        input_type: if path.is_dir() {
            "directory"
        } else {
            "archive"
        }
        .to_owned(),
        sha256: path.is_file().then(|| sha256_file(path)).transpose()?,
    }))
}

fn add_candidate(
    rows: &mut Vec<DependencyCandidate>,
    seen: &mut HashSet<String>,
    path: &Path,
    source: &str,
) {
    let key = path.to_string_lossy().to_lowercase();
    if !seen.insert(key) {
        return;
    }
    if let Ok(Some(candidate)) = inspect_candidate(path, source) {
        rows.push(candidate);
    }
}

pub fn scan_dependencies(
    explicit: &[PathBuf],
    near_path: Option<&Path>,
) -> Vec<DependencyCandidate> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    for path in explicit {
        add_candidate(&mut rows, &mut seen, path, "attached");
    }
    let mut roots = Vec::new();
    if let Some(path) = near_path {
        roots.push(if path.is_file() {
            path.parent().unwrap_or(path).to_path_buf()
        } else {
            path.to_path_buf()
        });
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(parent) = executable.parent()
    {
        roots.push(parent.join("Dependencies"));
        roots.push(parent.to_path_buf());
    }
    let mut root_seen = HashSet::new();
    for root in roots {
        if !root.is_dir() || !root_seen.insert(root.to_string_lossy().to_lowercase()) {
            continue;
        }
        add_candidate(&mut rows, &mut seen, &root, "same folder tree");
        for entry in WalkDir::new(&root)
            .max_depth(4)
            .into_iter()
            .filter_map(Result::ok)
            .take(500)
        {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            let interesting = if entry.file_type().is_dir() {
                name.contains("ue4ss") || name.contains("tessyncmapinjector")
            } else {
                let extension = path
                    .extension()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                matches!(extension.as_str(), "zip" | "7z" | "rar")
                    && (name.contains("ue4ss") || name.contains("syncmap") || name.contains("1272"))
            };
            if interesting {
                add_candidate(&mut rows, &mut seen, path, "same folder tree");
            }
        }
    }
    rows
}

pub(crate) fn game_is_running() -> bool {
    #[cfg(test)]
    {
        false
    }
    #[cfg(not(test))]
    {
        let system = System::new_all();
        system.processes().values().any(|process| {
            let name = process.name().to_string_lossy().to_ascii_lowercase();
            name.contains("oblivionremastered") || name.contains("obse64")
        })
    }
}

fn backup_root() -> Result<PathBuf> {
    #[cfg(test)]
    let base = std::env::temp_dir()
        .join("OBRModUpdaterTests")
        .join("Backups");
    #[cfg(not(test))]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("OBRModUpdater")
        .join("Backups");
    let base = base.join(format!(
        "runtime-dependencies-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S-%3f")
    ));
    fs::create_dir_all(&base)?;
    Ok(base)
}

fn install_files(
    source_root: &Path,
    destination_root: &Path,
    backup: &Path,
    kind: DependencyKind,
) -> Result<Vec<InstalledFile>> {
    let mut rows = Vec::new();
    for entry in WalkDir::new(source_root) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(source_root)?;
        if kind == DependencyKind::UE4SS {
            let normalized = relative.to_string_lossy().replace('/', "\\");
            if !normalized.eq_ignore_ascii_case("dwmapi.dll")
                && !normalized.to_ascii_lowercase().starts_with("ue4ss\\")
            {
                continue;
            }
        }
        let destination = destination_root.join(relative);
        let hash = sha256_file(entry.path())?;
        let old_hash = destination
            .is_file()
            .then(|| sha256_file(&destination))
            .transpose()?;
        if old_hash.as_deref() == Some(hash.as_str()) {
            rows.push(InstalledFile {
                kind,
                relative_path: relative.to_string_lossy().replace('\\', "/"),
                action: "unchanged".to_owned(),
                sha256: hash,
            });
            continue;
        }
        if let Some(old_hash) = old_hash {
            let backup_path = backup.join(relative);
            fs::create_dir_all(backup_path.parent().context("backup has no parent")?)?;
            fs::copy(&destination, &backup_path)?;
            if sha256_file(&backup_path)? != old_hash {
                bail!("backup hash mismatch: {}", destination.display());
            }
        }
        fs::create_dir_all(destination.parent().context("install file has no parent")?)?;
        let temporary = destination.with_extension(format!(
            "{}.obrdep.tmp",
            destination
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
        ));
        fs::copy(entry.path(), &temporary)?;
        if sha256_file(&temporary)? != hash {
            bail!(
                "temporary dependency copy hash mismatch: {}",
                relative.display()
            );
        }
        if destination.exists() {
            fs::remove_file(&destination)?;
        }
        fs::rename(&temporary, &destination)?;
        if sha256_file(&destination)? != hash {
            bail!("installed dependency hash mismatch: {}", relative.display());
        }
        rows.push(InstalledFile {
            kind,
            relative_path: relative.to_string_lossy().replace('\\', "/"),
            action: if backup.join(relative).exists() {
                "replaced-with-backup"
            } else {
                "installed"
            }
            .to_owned(),
            sha256: hash,
        });
    }
    Ok(rows)
}

pub fn check_or_install(
    game_root: &Path,
    candidates: Vec<DependencyCandidate>,
    install: bool,
) -> Result<DependencyReport> {
    let game = validate_game_install(game_root, "runtime dependency installer");
    if !game.valid {
        bail!("incomplete game installation: {}", game.missing.join(", "));
    }
    let before = installed_state(&game.root);
    let mut needed = Vec::new();
    if !before.ue4ss.installed {
        needed.push(DependencyKind::UE4SS);
    }
    if !before.tes_sync_map_injector.installed {
        needed.push(DependencyKind::TesSyncMapInjector);
    }
    let mut installed_files = Vec::new();
    let mut backup = None;
    if install && !needed.is_empty() {
        if game_is_running() {
            bail!("close Oblivion Remastered before installing runtime dependencies");
        }
        for kind in &needed {
            if !candidates
                .iter()
                .any(|candidate| candidate.kinds.contains(kind))
            {
                bail!("required dependency was not attached or found nearby: {kind}");
            }
        }
        let backup_path = backup_root()?;
        let win64 = game.root.join(r"OblivionRemastered\Binaries\Win64");
        for kind in needed {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.kinds.contains(&kind))
                .context("dependency candidate disappeared")?;
            let expanded = tempfile::Builder::new()
                .prefix("obr-dependency-install-")
                .tempdir()?;
            let root = if candidate.path.is_dir() {
                let destination = expanded.path().join("source");
                copy_tree(&candidate.path, &destination)?;
                destination
            } else {
                extract_archive(&candidate.path, expanded.path())?;
                expanded.path().to_path_buf()
            };
            let (ue4ss_roots, injector_roots) = payload_roots(&root);
            let payload = match kind {
                DependencyKind::UE4SS if ue4ss_roots.len() == 1 => &ue4ss_roots[0],
                DependencyKind::TesSyncMapInjector if injector_roots.len() == 1 => {
                    &injector_roots[0]
                }
                _ => bail!(
                    "could not identify one {kind} payload root in {}",
                    candidate.path.display()
                ),
            };
            let (destination, backup_destination) = match kind {
                DependencyKind::UE4SS => (win64.clone(), backup_path.join("Win64")),
                DependencyKind::TesSyncMapInjector => (
                    win64.join(r"ue4ss\Mods\TesSyncMapInjector"),
                    backup_path.join(r"Win64\ue4ss\Mods\TesSyncMapInjector"),
                ),
            };
            installed_files.extend(install_files(
                payload,
                &destination,
                &backup_destination,
                kind,
            )?);
        }
        backup = Some(backup_path);
    }
    let after = installed_state(&game.root);
    let ready = after.ue4ss.installed && after.tes_sync_map_injector.installed;
    Ok(DependencyReport {
        game_root: game.root,
        candidates,
        before,
        requested_install: install,
        installed_files,
        backup_root: backup,
        after,
        ready,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::game::REQUIRED_GAME_FILES;

    #[test]
    fn discovers_and_installs_external_tools_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let game = temp.path().join("game");
        for (_, relative) in REQUIRED_GAME_FILES {
            let path = game.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }
        let source = temp.path().join("external-tools");
        fs::create_dir_all(source.join(r"ue4ss\Mods\TesSyncMapInjector\Scripts")).unwrap();
        fs::write(source.join("dwmapi.dll"), b"proxy-v2").unwrap();
        fs::write(source.join(r"ue4ss\UE4SS.dll"), b"ue4ss-v2").unwrap();
        fs::write(
            source.join(r"ue4ss\Mods\TesSyncMapInjector\Scripts\main.lua"),
            b"injector-v2",
        )
        .unwrap();
        fs::write(
            source.join(r"ue4ss\Mods\TesSyncMapInjector\enabled.txt"),
            b"enabled",
        )
        .unwrap();
        let old_proxy = game.join(r"OblivionRemastered\Binaries\Win64\dwmapi.dll");
        fs::create_dir_all(old_proxy.parent().unwrap()).unwrap();
        fs::write(&old_proxy, b"proxy-v1").unwrap();

        let candidates = scan_dependencies(std::slice::from_ref(&source), None);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].kinds.contains(&DependencyKind::UE4SS));
        assert!(
            candidates[0]
                .kinds
                .contains(&DependencyKind::TesSyncMapInjector)
        );
        let report = check_or_install(&game, candidates.clone(), true).unwrap();
        assert!(report.ready);
        assert!(report.backup_root.is_some());
        assert_eq!(fs::read(old_proxy).unwrap(), b"proxy-v2");
        assert!(
            report
                .installed_files
                .iter()
                .any(|row| row.action == "replaced-with-backup")
        );

        let second = check_or_install(&game, candidates, true).unwrap();
        assert!(second.ready);
        assert!(second.installed_files.is_empty());
        assert!(second.backup_root.is_none());
    }
}
