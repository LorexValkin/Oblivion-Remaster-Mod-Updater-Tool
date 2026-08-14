use crate::archive::{MAX_ARCHIVE_ENTRIES, extract_archive_files_with_extensions, sha256_file};
use crate::fixes::{DependencyDiagnosticReport, diagnose_package_dependencies};
use crate::game::normalize_install_root;
use crate::retoc::{PackageStoreEntry, RetocTool};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;

pub const MIXED_IOSTORE_DEPENDENCY_PROBE_API: &str = "zen-mixed-iostore-dependency-probe-v1";
const MAX_SELECTED_IOSTORE_PROBE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DEPENDENCY_EDGES: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MixedContainerInventory {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub package_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MixedPackageCollision {
    pub source_package_id: u64,
    pub source_package_path: String,
    pub current_package_id: u64,
    pub current_package_path: String,
    pub package_id_collision: bool,
    pub package_path_collision: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MixedIoStoreDependencyReport {
    pub api: String,
    pub status: String,
    pub mutation_policy: String,
    pub container_count: usize,
    pub source_package_count: usize,
    pub current_game_package_count: usize,
    pub additive_package_count: usize,
    pub collision_count: usize,
    pub containers: Vec<MixedContainerInventory>,
    pub collisions: Vec<MixedPackageCollision>,
    pub dependencies: DependencyDiagnosticReport,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

struct StagedIoStoreRoot {
    _temporary: Option<TempDir>,
    root: PathBuf,
}

fn safe_candidate_root(candidate_root: Option<&str>) -> Result<PathBuf> {
    let raw = candidate_root.context("mixed IoStore probe requires one candidate mod root")?;
    let path = Path::new(raw);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        bail!("candidate mod root is not a safe relative path");
    }
    Ok(if raw == "." {
        PathBuf::new()
    } else {
        path.to_path_buf()
    })
}

fn stage_iostore_probe_files(
    input: &Path,
    candidate_root: Option<&str>,
) -> Result<StagedIoStoreRoot> {
    let candidate_root = safe_candidate_root(candidate_root)?;
    if input.is_dir() {
        let input_metadata =
            fs::symlink_metadata(input).context("reading the selected mixed IoStore directory")?;
        if input_metadata.file_type().is_symlink() {
            bail!("mixed IoStore input directory cannot be a filesystem link");
        }
        let canonical_input = input
            .canonicalize()
            .context("canonicalizing the selected mixed IoStore directory")?;
        let mut selected_root = input.to_path_buf();
        for component in candidate_root.components() {
            selected_root.push(component);
            let metadata = fs::symlink_metadata(&selected_root).with_context(|| {
                format!(
                    "reading mixed IoStore candidate path {}",
                    candidate_root.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                bail!("mixed IoStore candidate root contains a filesystem link");
            }
        }
        let selected_root = selected_root
            .canonicalize()
            .context("canonicalizing the mixed IoStore candidate root")?;
        if !selected_root.starts_with(&canonical_input) {
            bail!("mixed IoStore candidate root escapes the selected input");
        }
        return Ok(StagedIoStoreRoot {
            _temporary: None,
            root: selected_root,
        });
    }
    if !input.is_file() {
        bail!("mixed IoStore input is not a file or directory");
    }
    let temporary = tempfile::Builder::new()
        .prefix("obr-mixed-iostore-probe-")
        .tempdir()?;
    let selected = extract_archive_files_with_extensions(
        input,
        temporary.path(),
        &["utoc", "ucas"],
        MAX_SELECTED_IOSTORE_PROBE_BYTES,
    )?;
    if selected == 0 {
        bail!("mixed IoStore input contains no selected UTOC/UCAS probe files");
    }
    let root = temporary.path().join(candidate_root);
    Ok(StagedIoStoreRoot {
        _temporary: Some(temporary),
        root,
    })
}

fn selected_utoc_files(root: &Path) -> Result<Vec<PathBuf>> {
    let directory = root.join(r"Content\Paks\~mods");
    let directory_metadata = fs::symlink_metadata(&directory)
        .context("reading the selected mod Content/Paks/~mods directory")?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        bail!("selected mod root has no Content/Paks/~mods directory");
    }
    let mut files = Vec::new();
    for (index, entry) in WalkDir::new(&directory)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        if index >= MAX_ARCHIVE_ENTRIES {
            bail!("mixed IoStore tree exceeds the bounded entry limit");
        }
        let entry = entry.context("walking the mixed IoStore tree")?;
        let file_type = entry.file_type();
        if file_type.is_symlink() {
            bail!("mixed IoStore tree contains a filesystem link");
        }
        if file_type.is_file()
            && entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("utoc"))
        {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort_by_key(|path| path.to_string_lossy().to_ascii_lowercase());
    if files.is_empty() {
        bail!("selected mod root contains no UTOC files under Content/Paks/~mods");
    }
    let mut selected_bytes = 0_u64;
    for utoc in &files {
        let ucas = utoc.with_extension("ucas");
        let ucas_metadata = fs::symlink_metadata(&ucas).with_context(|| {
            format!(
                "selected mod UTOC has no matching UCAS file: {}",
                utoc.file_name().unwrap_or_default().to_string_lossy()
            )
        })?;
        if ucas_metadata.file_type().is_symlink() || !ucas_metadata.is_file() {
            bail!("selected mod UTOC has an unsafe or non-file UCAS sibling");
        }
        selected_bytes = selected_bytes
            .checked_add(fs::metadata(utoc)?.len())
            .and_then(|value| value.checked_add(ucas_metadata.len()))
            .context("mixed IoStore probe byte count overflow")?;
        if selected_bytes > MAX_SELECTED_IOSTORE_PROBE_BYTES {
            bail!("mixed IoStore probe files exceed the bounded byte limit");
        }
    }
    Ok(files)
}

fn normalized_package_path(path: &str) -> Result<String> {
    if path.is_empty() || path.contains('\0') || path.contains(':') {
        bail!("package path is empty or unsafe");
    }
    let replaced = path.replace('\\', "/");
    if replaced.starts_with('/') {
        bail!("package path is absolute");
    }
    let mut parts = Vec::new();
    let mut leading_parent_count = 0_usize;
    for part in replaced.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if !parts.is_empty() {
                bail!("package path traverses after its logical root");
            }
            leading_parent_count += 1;
            if leading_parent_count > 3 {
                bail!("package path traverses beyond the bounded Retoc mount prefix");
            }
            continue;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        bail!("package path is empty after normalization");
    }
    Ok(parts.join("/").to_ascii_lowercase())
}

fn build_report(
    containers: Vec<MixedContainerInventory>,
    source: Vec<PackageStoreEntry>,
    current: Vec<PackageStoreEntry>,
) -> Result<MixedIoStoreDependencyReport> {
    let dependency_edge_count = source.iter().try_fold(0_usize, |count, package| {
        count
            .checked_add(package.imported_package_ids.len())
            .context("mixed dependency edge count overflow")
    })?;
    if dependency_edge_count > MAX_DEPENDENCY_EDGES {
        bail!("mixed dependency graph exceeds the bounded edge limit");
    }
    let mut source_ids = BTreeSet::new();
    let mut source_paths = BTreeSet::new();
    for package in &source {
        if !source_ids.insert(package.package_id) {
            bail!("source package store repeats a package ID");
        }
        if !source_paths.insert(normalized_package_path(&package.path)?) {
            bail!("source package store repeats a package path");
        }
    }
    let dependencies = diagnose_package_dependencies(&source, &current)?;
    let mut current_by_id = BTreeMap::new();
    let mut current_by_path = BTreeMap::new();
    for package in &current {
        if current_by_id.insert(package.package_id, package).is_some() {
            bail!("current package store repeats a package ID");
        }
        let package_path = normalized_package_path(&package.path)?;
        if current_by_path.insert(package_path, package).is_some() {
            bail!("current package store repeats a package path");
        }
    }
    let mut collision_rows = BTreeMap::<(u64, u64), MixedPackageCollision>::new();
    let mut colliding_source_ids = BTreeSet::new();
    for package in &source {
        let source_path = normalized_package_path(&package.path)?;
        if let Some(current_package) = current_by_id.get(&package.package_id) {
            let package_path_collision =
                source_path == normalized_package_path(&current_package.path)?;
            colliding_source_ids.insert(package.package_id);
            collision_rows
                .entry((package.package_id, current_package.package_id))
                .and_modify(|collision| collision.package_id_collision = true)
                .or_insert_with(|| MixedPackageCollision {
                    source_package_id: package.package_id,
                    source_package_path: package.path.clone(),
                    current_package_id: current_package.package_id,
                    current_package_path: current_package.path.clone(),
                    package_id_collision: true,
                    package_path_collision,
                });
        }
        if let Some(current_package) = current_by_path.get(&source_path) {
            colliding_source_ids.insert(package.package_id);
            collision_rows
                .entry((package.package_id, current_package.package_id))
                .and_modify(|collision| collision.package_path_collision = true)
                .or_insert_with(|| MixedPackageCollision {
                    source_package_id: package.package_id,
                    source_package_path: package.path.clone(),
                    current_package_id: current_package.package_id,
                    current_package_path: current_package.path.clone(),
                    package_id_collision: package.package_id == current_package.package_id,
                    package_path_collision: true,
                });
        }
    }
    let collisions = collision_rows.into_values().collect::<Vec<_>>();
    let mut blockers = Vec::new();
    if !collisions.is_empty() {
        blockers.push(format!(
            "source-packages-collide-with-current-game:found-{}",
            collisions.len()
        ));
    }
    if dependencies.unresolved_edge_count > 0 {
        blockers.push(format!(
            "unresolved-source-package-dependencies:found-{}",
            dependencies.unresolved_edge_count
        ));
    }
    let source_package_count = source.len();
    let current_game_package_count = current.len();
    Ok(MixedIoStoreDependencyReport {
        api: MIXED_IOSTORE_DEPENDENCY_PROBE_API.to_owned(),
        status: if blockers.is_empty() {
            "complete-report-only"
        } else {
            "blocked"
        }
        .to_owned(),
        mutation_policy: "report-only".to_owned(),
        container_count: containers.len(),
        source_package_count,
        current_game_package_count,
        additive_package_count: source_package_count.saturating_sub(colliding_source_ids.len()),
        collision_count: collisions.len(),
        containers,
        collisions,
        dependencies,
        blockers,
        warnings: vec![
            "This metadata probe proves package identity and dependency closure only; it does not prove export-class conversion, shader compatibility, or runtime behavior."
                .to_owned(),
        ],
    })
}

pub fn probe_mixed_iostore_dependencies(
    mod_input: &Path,
    candidate_root: Option<&str>,
    current_game_root: &Path,
) -> Result<MixedIoStoreDependencyReport> {
    let staged = stage_iostore_probe_files(mod_input, candidate_root)?;
    let utocs = selected_utoc_files(&staged.root)?;
    let retoc = RetocTool::materialize()?;
    let mut containers = Vec::new();
    let mut source = Vec::new();
    for utoc in utocs {
        retoc.verify(&utoc, "retoc verify mixed IoStore source")?;
        let (_, mut packages) = retoc.package_store_entries(&utoc)?;
        let relative_path = utoc
            .strip_prefix(&staged.root)
            .context("mixed replacement UTOC escaped the selected mod root")?
            .to_string_lossy()
            .replace('\\', "/");
        containers.push(MixedContainerInventory {
            relative_path,
            bytes: fs::metadata(&utoc)?.len(),
            sha256: sha256_file(&utoc)?,
            package_count: packages.len(),
        });
        source.append(&mut packages);
    }
    if source.len() > MAX_ARCHIVE_ENTRIES {
        bail!("mixed source package inventory exceeds the bounded package limit");
    }
    let game_root = normalize_install_root(current_game_root);
    let stock_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    if !stock_utoc.is_file() {
        bail!("current game stock UTOC is unavailable");
    }
    let (_, current) = retoc.package_store_entries(&stock_utoc)?;
    build_report(containers, source, current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(id: u64, path: &str, dependencies: &[u64]) -> PackageStoreEntry {
        PackageStoreEntry {
            package_id: id,
            path: path.to_owned(),
            imported_package_ids: dependencies.to_vec(),
        }
    }

    #[test]
    fn rejects_unsafe_or_missing_candidate_roots() {
        assert!(safe_candidate_root(None).is_err());
        assert!(safe_candidate_root(Some(r"..\escape")).is_err());
        assert!(safe_candidate_root(Some(r"C:\absolute")).is_err());
        assert_eq!(safe_candidate_root(Some(".")).unwrap(), PathBuf::new());
        assert_eq!(
            safe_candidate_root(Some("OblivionRemastered")).unwrap(),
            PathBuf::from("OblivionRemastered")
        );
    }

    #[test]
    fn requires_a_matching_ucas_for_every_selected_utoc() {
        let temporary = tempfile::tempdir().unwrap();
        let mods = temporary.path().join(r"Content\Paks\~mods");
        fs::create_dir_all(&mods).unwrap();
        fs::write(mods.join("Fixture.utoc"), b"utoc").unwrap();
        assert!(selected_utoc_files(temporary.path()).is_err());
        fs::write(mods.join("Fixture.ucas"), b"ucas").unwrap();
        assert_eq!(selected_utoc_files(temporary.path()).unwrap().len(), 1);
    }

    #[test]
    fn discovers_nested_container_sets_under_the_selected_mods_root() {
        let temporary = tempfile::tempdir().unwrap();
        let nested = temporary
            .path()
            .join(r"Content\Paks\~mods\WeaponPack\Containers");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("Fixture.utoc"), b"utoc").unwrap();
        fs::write(nested.join("Fixture.ucas"), b"ucas").unwrap();

        let files = selected_utoc_files(temporary.path()).unwrap();
        assert_eq!(files, vec![nested.join("Fixture.utoc")]);
    }

    #[test]
    fn reports_additions_collisions_and_unresolved_edges_deterministically() {
        let containers = vec![MixedContainerInventory {
            relative_path: "Content/Paks/~mods/Fixture.utoc".to_owned(),
            bytes: 10,
            sha256: "fixture".to_owned(),
            package_count: 3,
        }];
        let source = vec![
            package(
                30,
                "../../../OblivionRemastered/Content/Mod/C.uasset",
                &[99],
            ),
            package(
                20,
                "../../../OblivionRemastered/Content/Stock/B.uasset",
                &[],
            ),
            package(
                10,
                "../../../OblivionRemastered/Content/Mod/A.uasset",
                &[40],
            ),
        ];
        let current = vec![
            package(
                20,
                "../../../OblivionRemastered/Content/Other/ById.uasset",
                &[],
            ),
            package(
                25,
                "../../../OblivionRemastered/Content/Stock/B.uasset",
                &[],
            ),
            package(40, "../../../OblivionRemastered/Content/Base/D.uasset", &[]),
        ];
        let report = build_report(containers, source, current).unwrap();
        assert_eq!(report.api, MIXED_IOSTORE_DEPENDENCY_PROBE_API);
        assert_eq!(report.status, "blocked");
        assert_eq!(report.container_count, 1);
        assert_eq!(report.source_package_count, 3);
        assert_eq!(report.additive_package_count, 2);
        assert_eq!(report.collision_count, 2);
        assert_eq!(report.dependencies.resolved_edge_count, 1);
        assert_eq!(report.dependencies.unresolved_edge_count, 1);
        assert_eq!(
            report.dependencies.unresolved_edges[0].missing_dependency_package_id,
            99
        );
        assert!(report.collisions.iter().any(|collision| {
            collision.source_package_id == 20 && collision.package_id_collision
        }));
        assert!(report.collisions.iter().any(|collision| {
            collision.source_package_id == 20 && collision.package_path_collision
        }));
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_package_store_paths() {
        let containers = vec![MixedContainerInventory {
            relative_path: "Content/Paks/~mods/Fixture.utoc".to_owned(),
            bytes: 10,
            sha256: "fixture".to_owned(),
            package_count: 1,
        }];
        let unsafe_source = vec![package(1, "Game/../Escape.uasset", &[])];
        assert!(build_report(containers.clone(), unsafe_source, Vec::new()).is_err());

        let duplicate_current = vec![
            package(10, "Game/First.uasset", &[]),
            package(10, "Game/Second.uasset", &[]),
        ];
        assert!(
            build_report(
                containers,
                vec![package(1, "Game/Selected.uasset", &[])],
                duplicate_current,
            )
            .is_err()
        );
    }
}
