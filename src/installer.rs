use crate::archive::sha256_file;
use crate::dependencies::game_is_running;
use crate::game::validate_game_install;
use crate::install_plan::{
    MappingScope, nested_logical_install_adapter, resolve_staged_install_view,
    supports_logical_install_publication,
};
use crate::replacement::{
    ADDITIVE_STATIC_MESH_ADAPTER, ARMOR_REPLACEMENT_ADAPTER, HETEROGENEOUS_REPLACEMENT_ADAPTER,
    MIXED_ARMOR_REPLACEMENT_ADAPTER, TEXTURE_REPLACEMENT_ADAPTER,
};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

const ADDITIVE_SYNCMAP_ADAPTER: &str = "native-additive-syncmap-v1";
const MAGICLOADER_WORLDSPACE_ADAPTER: &str = "native-magicloader-worldspace-syncmap-v1";

#[derive(Clone, Debug)]
pub struct CandidateInstallRequest {
    pub adapter: String,
    pub candidate_root: PathBuf,
    pub game_root: PathBuf,
    pub backup_parent: PathBuf,
}

#[derive(Clone, Debug)]
pub struct CandidateInstallOutcome {
    pub installed_file_count: usize,
    pub replaced_file_count: usize,
    pub unchanged_file_count: usize,
    pub backup_directory: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct InstallFile {
    source: PathBuf,
    logical_destination: PathBuf,
}

#[derive(Debug)]
struct PreparedCandidate {
    files: Vec<InstallFile>,
    _logical_view: Option<crate::install_plan::ResolvedStagedInstallView>,
}

fn is_direct_container_adapter(adapter: &str) -> bool {
    matches!(
        adapter,
        ARMOR_REPLACEMENT_ADAPTER
            | MIXED_ARMOR_REPLACEMENT_ADAPTER
            | TEXTURE_REPLACEMENT_ADAPTER
            | ADDITIVE_STATIC_MESH_ADAPTER
            | HETEROGENEOUS_REPLACEMENT_ADAPTER
    )
}

fn prepare_structured_candidate(candidate_root: &Path) -> Result<PreparedCandidate> {
    let resolved = resolve_staged_install_view(candidate_root)?;
    if !supports_logical_install_publication(&resolved.plan) {
        bail!("the confirmed candidate does not have one choice-free install layout");
    }
    let files = resolved
        .plan
        .mappings
        .iter()
        .map(|mapping| {
            if mapping.scope != MappingScope::Required {
                bail!("the confirmed candidate still requires an install choice");
            }
            Ok(InstallFile {
                source: resolved.view.root().join(&mapping.logical_destination),
                logical_destination: mapping.logical_destination.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PreparedCandidate {
        files,
        _logical_view: Some(resolved),
    })
}

fn prepare_direct_container_candidate(candidate_root: &Path) -> Result<PreparedCandidate> {
    let mut triples = BTreeMap::<String, BTreeMap<String, PathBuf>>::new();
    for entry in WalkDir::new(candidate_root).follow_links(false) {
        let entry = entry.context("walking the confirmed candidate")?;
        if entry.file_type().is_symlink() {
            bail!(
                "the confirmed candidate contains a filesystem link: {}",
                entry.path().display()
            );
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let extension = entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "pak" | "ucas" | "utoc") {
            continue;
        }
        let stem = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .context("candidate container has no valid filename")?
            .to_ascii_lowercase();
        let parent = entry.path().parent().unwrap_or(candidate_root);
        let key = format!("{}|{stem}", parent.to_string_lossy().to_ascii_lowercase());
        if triples
            .entry(key)
            .or_default()
            .insert(extension.clone(), entry.path().to_path_buf())
            .is_some()
        {
            bail!("the confirmed candidate repeats a {extension} container sibling");
        }
    }
    if triples.is_empty() {
        bail!("the confirmed candidate contains no installable container triples");
    }
    if triples.values().any(|triple| {
        triple.len() != 3
            || !triple.contains_key("pak")
            || !triple.contains_key("ucas")
            || !triple.contains_key("utoc")
    }) {
        bail!("the confirmed candidate contains an incomplete PAK/UCAS/UTOC triple");
    }

    let mut destinations = BTreeSet::new();
    let mut files = Vec::new();
    for triple in triples.values() {
        for source in triple.values() {
            let file_name = source
                .file_name()
                .context("candidate container has no filename")?;
            let destination = PathBuf::from("Content")
                .join("Paks")
                .join("~mods")
                .join(file_name);
            let key = destination.to_string_lossy().to_ascii_lowercase();
            if !destinations.insert(key) {
                bail!(
                    "multiple candidate containers resolve to {}",
                    destination.display()
                );
            }
            files.push(InstallFile {
                source: source.clone(),
                logical_destination: destination,
            });
        }
    }
    Ok(PreparedCandidate {
        files,
        _logical_view: None,
    })
}

fn prepare_candidate(adapter: &str, candidate_root: &Path) -> Result<PreparedCandidate> {
    if adapter == ADDITIVE_SYNCMAP_ADAPTER
        || adapter == MAGICLOADER_WORLDSPACE_ADAPTER
        || nested_logical_install_adapter(adapter).is_some()
    {
        prepare_structured_candidate(candidate_root)
    } else if is_direct_container_adapter(adapter) {
        prepare_direct_container_candidate(candidate_root)
    } else {
        bail!("the confirmed adapter does not expose an automatic install layout");
    }
}

fn checked_destination(game_content_root: &Path, logical: &Path) -> Result<PathBuf> {
    let first = logical
        .components()
        .next()
        .context("empty install destination")?;
    let Component::Normal(first) = first else {
        bail!("install destination is not relative: {}", logical.display());
    };
    let first = first.to_string_lossy();
    if !first.eq_ignore_ascii_case("Content") && !first.eq_ignore_ascii_case("Binaries") {
        bail!(
            "install destination is outside Content or Binaries: {}",
            logical.display()
        );
    }
    let destination = game_content_root.join(logical);
    if destination.exists() {
        let metadata = fs::symlink_metadata(&destination)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "install destination is not a regular file: {}",
                destination.display()
            );
        }
    }
    Ok(destination)
}

fn rollback(committed: &[(PathBuf, Option<PathBuf>)]) -> Vec<String> {
    let mut errors = Vec::new();
    for (destination, backup) in committed.iter().rev() {
        let result = if let Some(backup) = backup {
            fs::copy(backup, destination).map(|_| ())
        } else if destination.exists() {
            fs::remove_file(destination)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            errors.push(format!("{}: {error}", destination.display()));
        }
    }
    errors
}

pub fn install_candidate(request: CandidateInstallRequest) -> Result<CandidateInstallOutcome> {
    let game = validate_game_install(&request.game_root, "confirmed candidate install");
    if !game.valid {
        bail!(
            "game folder is incomplete. Missing: {}",
            game.missing.join(", ")
        );
    }
    if game_is_running() {
        bail!("close Oblivion Remastered and its script extender before installing the mod");
    }
    if !request.candidate_root.is_dir() {
        bail!(
            "confirmed candidate folder is missing: {}",
            request.candidate_root.display()
        );
    }
    if !request.backup_parent.is_dir() {
        bail!(
            "backup parent does not exist: {}",
            request.backup_parent.display()
        );
    }

    let prepared = prepare_candidate(&request.adapter, &request.candidate_root)?;
    let inner_game_root = game.root.join("OblivionRemastered");
    let mut changed = Vec::new();
    let mut unchanged_file_count = 0_usize;
    for file in &prepared.files {
        let destination = checked_destination(&inner_game_root, &file.logical_destination)?;
        let source_sha256 = sha256_file(&file.source)?;
        if destination.is_file() && sha256_file(&destination)? == source_sha256 {
            unchanged_file_count += 1;
        } else {
            changed.push((file, destination, source_sha256));
        }
    }

    let replaced_file_count = changed
        .iter()
        .filter(|(_, destination, _)| destination.is_file())
        .count();
    let backup_directory = if replaced_file_count == 0 {
        None
    } else {
        let directory = request.backup_parent.join(format!(
            "OBR-Mod-Updater-install-backup-{}",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ));
        fs::create_dir(&directory).with_context(|| {
            format!("creating install backup directory {}", directory.display())
        })?;
        Some(directory)
    };

    let mut backup_by_destination = BTreeMap::<PathBuf, PathBuf>::new();
    if let Some(backup_directory) = &backup_directory {
        for (file, destination, _) in &changed {
            if !destination.is_file() {
                continue;
            }
            let backup = backup_directory.join(&file.logical_destination);
            fs::create_dir_all(backup.parent().context("backup file has no parent")?)?;
            fs::copy(destination, &backup)
                .with_context(|| format!("backing up installed file {}", destination.display()))?;
            if sha256_file(destination)? != sha256_file(&backup)? {
                bail!(
                    "install backup verification failed for {}",
                    destination.display()
                );
            }
            backup_by_destination.insert(destination.clone(), backup);
        }
    }

    let mut committed = Vec::new();
    for (file, destination, expected_sha256) in &changed {
        let attempt = (|| -> Result<()> {
            fs::create_dir_all(
                destination
                    .parent()
                    .context("install destination has no parent")?,
            )?;
            committed.push((
                destination.clone(),
                backup_by_destination.get(destination).cloned(),
            ));
            fs::copy(&file.source, destination)
                .with_context(|| format!("installing {}", file.logical_destination.display()))?;
            if sha256_file(destination)? != *expected_sha256 {
                bail!(
                    "installed file verification failed for {}",
                    file.logical_destination.display()
                );
            }
            Ok(())
        })();
        if let Err(error) = attempt {
            let rollback_errors = rollback(&committed);
            bail!(
                "{error:#}; rollback errors: {}",
                if rollback_errors.is_empty() {
                    "none".to_owned()
                } else {
                    rollback_errors.join("; ")
                }
            );
        }
    }

    Ok(CandidateInstallOutcome {
        installed_file_count: changed.len(),
        replaced_file_count,
        unchanged_file_count,
        backup_directory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::game::REQUIRED_GAME_FILES;

    fn fake_game(root: &Path) {
        for (_, relative) in REQUIRED_GAME_FILES {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }
    }

    #[test]
    fn confirmed_container_candidate_installs_and_backs_up_replaced_files() {
        let temporary = tempfile::tempdir().unwrap();
        let game = temporary.path().join("game");
        let candidate = temporary.path().join("candidate");
        let backups = temporary.path().join("backups");
        fake_game(&game);
        fs::create_dir_all(&candidate).unwrap();
        fs::create_dir_all(&backups).unwrap();
        for extension in ["pak", "ucas", "utoc"] {
            fs::write(
                candidate.join(format!("weapon_p.{extension}")),
                format!("new-{extension}"),
            )
            .unwrap();
        }
        let installed_pak = game.join(r"OblivionRemastered\Content\Paks\~mods\weapon_p.pak");
        fs::create_dir_all(installed_pak.parent().unwrap()).unwrap();
        fs::write(&installed_pak, b"old-pak").unwrap();

        let outcome = install_candidate(CandidateInstallRequest {
            adapter: HETEROGENEOUS_REPLACEMENT_ADAPTER.to_owned(),
            candidate_root: candidate,
            game_root: game.clone(),
            backup_parent: backups,
        })
        .unwrap();

        assert_eq!(outcome.installed_file_count, 3);
        assert_eq!(outcome.replaced_file_count, 1);
        assert_eq!(outcome.unchanged_file_count, 0);
        assert_eq!(fs::read(&installed_pak).unwrap(), b"new-pak");
        let backup = outcome
            .backup_directory
            .unwrap()
            .join(r"Content\Paks\~mods\weapon_p.pak");
        assert_eq!(fs::read(backup).unwrap(), b"old-pak");
    }
}
