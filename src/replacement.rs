use crate::archive::{copy_tree, extract_archive};
use crate::retoc::{PackageEntry, PackageStoreEntry, RetocTool};
use crate::uasset::{TextureAssetDiagnostic, inspect_static_mesh_asset, inspect_texture_asset};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const ARMOR_REPLACEMENT_ADAPTER: &str = "native-armor-replacement-v1";
pub const MIXED_ARMOR_REPLACEMENT_ADAPTER: &str = "native-mixed-armor-expansion-v1";
pub const TEXTURE_REPLACEMENT_ADAPTER: &str = "native-texture-replacement-v1";
pub const ADDITIVE_STATIC_MESH_ADAPTER: &str = "native-additive-static-mesh-v1";
const MAX_REPLACEMENT_PACKAGES: usize = 4096;
const ARMOR_PATH_PREFIX: &str = "oblivionremastered/content/art/armor/";
const ARMOR_FORM_PATH_PREFIX: &str = "oblivionremastered/content/forms/items/armor/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementScope {
    Armor,
    MixedArmor,
    Texture,
    AdditiveStaticMesh,
}

#[derive(Clone, Debug)]
pub struct ReplacementContainer {
    pub name: String,
    pub utoc: PathBuf,
    pub ucas: PathBuf,
    pub pak: PathBuf,
    pub relative_utoc: PathBuf,
    pub packages: Vec<PackageEntry>,
    pub package_store: Vec<PackageStoreEntry>,
}

#[derive(Clone, Debug)]
pub struct ReplacementInspection {
    pub containers: Vec<ReplacementContainer>,
    pub packages: Vec<PackageEntry>,
    pub target_utoc: PathBuf,
    pub target_dependencies: HashMap<u64, PackageEntry>,
    pub target_package_imports: HashMap<u64, Vec<u64>>,
}

#[derive(Clone, Debug)]
pub struct MixedArmorInspection {
    pub mesh: ReplacementInspection,
    pub companion_containers: Vec<ReplacementContainer>,
    pub packages: Vec<PackageEntry>,
    pub donor_packages: HashMap<u64, PackageEntry>,
    pub companion_dependency_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementProbeSummary {
    pub container_count: usize,
    pub package_count: usize,
    pub asset_kind: String,
    pub package_paths: Vec<String>,
    pub texture_assets: Vec<TextureAssetDiagnostic>,
}

pub fn stage_input(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    if source.is_dir() {
        copy_tree(source, destination)
    } else {
        extract_archive(source, destination)
    }
}

pub(crate) fn canonical_package_path(raw: &str) -> Result<String> {
    let path = raw.replace('\\', "/");
    let lower = path.to_ascii_lowercase();
    let marker = "oblivionremastered/content/";
    let offset = lower
        .find(marker)
        .with_context(|| format!("package path is outside OblivionRemastered content: {raw}"))?;
    let canonical = path[offset..].trim_matches('/').to_owned();
    if canonical.split('/').any(|segment| segment == "..") {
        bail!("package path contains traversal after normalization: {raw}");
    }
    Ok(canonical)
}
pub(crate) fn canonical_additive_static_mesh_path(raw: &str) -> Result<String> {
    let normalized = raw.replace('\\', "/");
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .skip_while(|part| *part == "..")
        .collect::<Vec<_>>();
    if parts.len() < 3
        || !parts[1].eq_ignore_ascii_case("Content")
        || parts.iter().any(|part| *part == "..")
        || parts[0].eq_ignore_ascii_case("OblivionRemastered")
    {
        bail!(
            "additive static-mesh package must use a custom <Project>/Content path without traversal: {raw}"
        );
    }
    let path = parts.join("/");
    let leaf = path.rsplit('/').next().unwrap_or_default();
    if !leaf.to_ascii_lowercase().starts_with("sm_") || !leaf.ends_with(".uasset") {
        bail!("additive static-mesh package must be an SM_ UAsset: {raw}");
    }
    Ok(path)
}

fn package_key(path: &str) -> Result<String> {
    Ok(canonical_package_path(path)?.to_ascii_lowercase())
}

fn is_armor_skeletal_mesh(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.starts_with(ARMOR_PATH_PREFIX) || !lower.ends_with(".uasset") {
        return false;
    }
    lower
        .rsplit('/')
        .next()
        .is_some_and(|leaf| leaf.starts_with("sk_"))
}

fn is_texture_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("oblivionremastered/content/") && lower.ends_with(".uasset")
}

fn is_armor_form_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with(ARMOR_FORM_PATH_PREFIX) && lower.ends_with(".uasset")
}

fn discover_containers(
    root: &Path,
    retoc: &RetocTool,
    scope: ReplacementScope,
) -> Result<Vec<ReplacementContainer>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "replacement input contains a filesystem link: {}",
                entry.path().display()
            );
        }
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    if files.is_empty() {
        bail!("replacement input contains no files");
    }
    for file in &files {
        let extension = file
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "pak" | "ucas" | "utoc") {
            bail!(
                "armor replacement adapter accepts only complete PAK/UCAS/UTOC triples; found {}",
                file.display()
            );
        }
    }

    let mut utocs = files
        .iter()
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("utoc"))
        })
        .cloned()
        .collect::<Vec<_>>();
    utocs.sort();
    if utocs.is_empty() || files.len() != utocs.len() * 3 {
        bail!("armor replacement input does not contain only complete container triples");
    }

    let mut names = HashSet::new();
    let mut containers = Vec::new();
    for utoc in utocs {
        let name = utoc
            .file_stem()
            .and_then(|value| value.to_str())
            .context("replacement UTOC filename is not UTF-8")?
            .to_owned();
        if !name.to_ascii_lowercase().ends_with("_p") {
            bail!("replacement container must use an override _P suffix: {name}");
        }
        if !names.insert(name.to_ascii_lowercase()) {
            bail!("duplicate replacement container name: {name}");
        }
        let ucas = utoc.with_extension("ucas");
        let pak = utoc.with_extension("pak");
        if !ucas.is_file() || !pak.is_file() {
            bail!("replacement container {name} is missing its UCAS or PAK partner");
        }
        retoc.verify(&utoc, &format!("retoc verify replacement source {name}"))?;
        let (_, mut package_store) = retoc.package_store_entries(&utoc)?;
        for package in &mut package_store {
            package.path = match scope {
                ReplacementScope::AdditiveStaticMesh => {
                    canonical_additive_static_mesh_path(&package.path)?
                }
                _ => canonical_package_path(&package.path)?,
            };
            match scope {
                ReplacementScope::Armor if !is_armor_skeletal_mesh(&package.path) => {
                    bail!(
                        "armor replacement adapter only accepts existing SK_ skeletal-mesh packages under /Content/Art/armor: {}",
                        package.path
                    );
                }
                ReplacementScope::MixedArmor
                    if !is_armor_skeletal_mesh(&package.path)
                        && !is_armor_form_candidate(&package.path) =>
                {
                    bail!(
                        "mixed armor adapter accepts only SK_ mesh packages under /Content/Art/armor and companion packages under /Content/Forms/items/armor: {}",
                        package.path
                    );
                }
                ReplacementScope::Texture if !is_texture_candidate(&package.path) => {
                    bail!(
                        "texture replacement adapter accepts only UAsset packages under /Content pending structural Texture2D verification: {}",
                        package.path
                    );
                }
                ReplacementScope::AdditiveStaticMesh => {}
                _ => {}
            }
        }
        let packages = package_store
            .iter()
            .map(|entry| PackageEntry {
                package_id: entry.package_id,
                path: entry.path.clone(),
            })
            .collect();
        containers.push(ReplacementContainer {
            relative_utoc: utoc.strip_prefix(root)?.to_path_buf(),
            name,
            utoc,
            ucas,
            pak,
            packages,
            package_store,
        });
    }
    Ok(containers)
}

fn inspect_staged_for_scope(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
    scope: ReplacementScope,
) -> Result<ReplacementInspection> {
    let containers = discover_containers(root, retoc, scope)?;
    let mut packages = containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    if packages.len() > MAX_REPLACEMENT_PACKAGES {
        bail!(
            "armor replacement contains {} packages; adapter limit is {}",
            packages.len(),
            MAX_REPLACEMENT_PACKAGES
        );
    }
    packages.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
    });
    for pair in packages.windows(2) {
        if pair[0].path.eq_ignore_ascii_case(&pair[1].path) {
            bail!(
                "armor replacement package appears in multiple containers: {}",
                pair[0].path
            );
        }
    }

    let target_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    if !target_utoc.is_file() {
        bail!(
            "current game package inventory is missing: {}",
            target_utoc.display()
        );
    }
    let (_, target_entries) = retoc.package_store_entries(&target_utoc)?;
    let target_packages = target_entries
        .iter()
        .cloned()
        .into_iter()
        .filter_map(|entry| package_key(&entry.path).ok().map(|key| (key, entry)))
        .collect::<HashMap<_, _>>();
    let target_by_id = target_entries
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let mut target_package_imports = HashMap::new();
    let mut required_dependency_ids = containers
        .iter()
        .flat_map(|container| container.package_store.iter())
        .flat_map(|entry| entry.imported_package_ids.iter().copied())
        .collect::<HashSet<_>>();
    for package in &packages {
        let key = package_key(&package.path)?;
        let target = target_packages.get(&key).with_context(|| {
            format!(
                "armor package is an addition, not a replacement: {}",
                package.path
            )
        })?;
        if target.package_id != package.package_id {
            bail!(
                "current game package ID changed for {}: mod {}, game {}",
                package.path,
                package.package_id,
                target.package_id
            );
        }
        target_package_imports.insert(package.package_id, target.imported_package_ids.clone());
        required_dependency_ids.extend(target.imported_package_ids.iter().copied());
    }
    let target_dependencies = required_dependency_ids
        .into_iter()
        .filter_map(|package_id| {
            target_by_id.get(&package_id).map(|entry| {
                (
                    package_id,
                    PackageEntry {
                        package_id,
                        path: entry.path.clone(),
                    },
                )
            })
        })
        .collect();

    Ok(ReplacementInspection {
        containers,
        packages,
        target_utoc,
        target_dependencies,
        target_package_imports,
    })
}

pub fn inspect_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<ReplacementInspection> {
    inspect_staged_for_scope(root, game_root, retoc, ReplacementScope::Armor)
}

fn sibling_donor_paths(path: &str) -> Result<Vec<String>> {
    let canonical = canonical_package_path(path)?;
    let lower = canonical.to_ascii_lowercase();
    if !lower.ends_with("_f.uasset") {
        bail!(
            "additive armor package has no guarded current-game donor rule (expected an _f skeletal mesh): {canonical}"
        );
    }
    let base = canonical[..canonical.len() - "_f.uasset".len()].to_owned();
    Ok(vec![format!("{base}_m.uasset"), format!("{base}.uasset")])
}

pub fn inspect_mixed_armor_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<MixedArmorInspection> {
    let containers = discover_containers(root, retoc, ReplacementScope::MixedArmor)?;
    let mut packages = containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    if packages.len() > MAX_REPLACEMENT_PACKAGES {
        bail!(
            "mixed armor input contains {} packages; adapter limit is {}",
            packages.len(),
            MAX_REPLACEMENT_PACKAGES
        );
    }
    packages.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
    });
    for pair in packages.windows(2) {
        if pair[0].path.eq_ignore_ascii_case(&pair[1].path) {
            bail!(
                "mixed armor package appears in multiple containers: {}",
                pair[0].path
            );
        }
    }

    let mut mesh_containers = Vec::new();
    let mut companion_containers = Vec::new();
    for container in containers {
        let mesh_count = container
            .packages
            .iter()
            .filter(|package| is_armor_skeletal_mesh(&package.path))
            .count();
        let companion_count = container
            .packages
            .iter()
            .filter(|package| is_armor_form_candidate(&package.path))
            .count();
        if mesh_count == container.packages.len() {
            mesh_containers.push(container);
        } else if companion_count == container.packages.len() {
            companion_containers.push(container);
        } else {
            bail!(
                "mixed armor container {} combines mesh and companion packages; this layout remains report-only",
                container.name
            );
        }
    }
    if mesh_containers.is_empty() || companion_containers.is_empty() {
        bail!(
            "mixed armor adapter requires separate mesh and /Forms/items/armor companion containers"
        );
    }

    let target_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    if !target_utoc.is_file() {
        bail!(
            "current game package inventory is missing: {}",
            target_utoc.display()
        );
    }
    let (_, target_entries) = retoc.package_store_entries(&target_utoc)?;
    let target_packages = target_entries
        .iter()
        .cloned()
        .filter_map(|entry| package_key(&entry.path).ok().map(|key| (key, entry)))
        .collect::<HashMap<_, _>>();
    let target_by_id = target_entries
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let mod_package_ids = packages
        .iter()
        .map(|package| package.package_id)
        .collect::<HashSet<_>>();

    let mut companion_dependency_ids = HashSet::new();
    for container in &companion_containers {
        for package in &container.package_store {
            let current = target_packages
                .get(&package_key(&package.path)?)
                .with_context(|| {
                    format!(
                        "companion armor package is an addition, not a current form replacement: {}",
                        package.path
                    )
                })?;
            if current.package_id != package.package_id {
                bail!(
                    "current game package ID changed for companion {}: mod {}, game {}",
                    package.path,
                    package.package_id,
                    current.package_id
                );
            }
            for dependency in &package.imported_package_ids {
                if !mod_package_ids.contains(dependency) && !target_by_id.contains_key(dependency) {
                    bail!(
                        "companion package {} has unresolved external dependency {}; custom companion dependencies must be bundled or present in the current game",
                        package.path,
                        dependency
                    );
                }
                companion_dependency_ids.insert(*dependency);
            }
        }
    }

    let mesh_packages = mesh_containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    let mut donor_packages = HashMap::new();
    let mut target_package_imports = HashMap::new();
    let mut required_dependency_ids = HashSet::new();
    for package in &mesh_packages {
        let source_key = package_key(&package.path)?;
        let donor = if let Some(current) = target_packages.get(&source_key) {
            if current.package_id != package.package_id {
                bail!(
                    "current game package ID changed for {}: mod {}, game {}",
                    package.path,
                    package.package_id,
                    current.package_id
                );
            }
            current.clone()
        } else {
            let candidates = sibling_donor_paths(&package.path)?
                .into_iter()
                .filter_map(|candidate| {
                    package_key(&candidate)
                        .ok()
                        .and_then(|key| target_packages.get(&key).cloned())
                })
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                bail!(
                    "additive armor package {} requires exactly one current-game sibling donor (_m or unsuffixed); found {}",
                    package.path,
                    candidates.len()
                );
            }
            candidates[0].clone()
        };
        target_package_imports.insert(package.package_id, donor.imported_package_ids.clone());
        required_dependency_ids.extend(donor.imported_package_ids.iter().copied());
        let donor_path = canonical_package_path(&donor.path)?.to_ascii_lowercase();
        let donor_directory = donor_path
            .rsplit_once('/')
            .map(|(directory, _)| directory)
            .context("current armor donor path has no package directory")?;
        required_dependency_ids.extend(target_entries.iter().filter_map(|entry| {
            let path = canonical_package_path(&entry.path)
                .ok()?
                .to_ascii_lowercase();
            let (directory, leaf) = path.rsplit_once('/')?;
            (directory == donor_directory && leaf.starts_with("mic_") && leaf.ends_with(".uasset"))
                .then_some(entry.package_id)
        }));
        donor_packages.insert(
            package.package_id,
            PackageEntry {
                package_id: donor.package_id,
                path: donor.path.clone(),
            },
        );
    }
    let target_dependencies = required_dependency_ids
        .into_iter()
        .filter_map(|package_id| {
            target_by_id.get(&package_id).map(|entry| {
                (
                    package_id,
                    PackageEntry {
                        package_id,
                        path: entry.path.clone(),
                    },
                )
            })
        })
        .collect();

    Ok(MixedArmorInspection {
        mesh: ReplacementInspection {
            containers: mesh_containers,
            packages: mesh_packages,
            target_utoc,
            target_dependencies,
            target_package_imports,
        },
        companion_containers,
        packages,
        donor_packages,
        companion_dependency_count: companion_dependency_ids.len(),
    })
}

pub fn inspect_texture_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<ReplacementInspection> {
    let inspection = inspect_staged_for_scope(root, game_root, retoc, ReplacementScope::Texture)?;
    for container in &inspection.containers {
        for package in &container.package_store {
            if !package.imported_package_ids.is_empty() {
                bail!(
                    "Texture2D replacement {} declares imported packages; mixed material/blueprint dependency closures remain report-only",
                    package.path
                );
            }
        }
    }
    for package in &inspection.packages {
        let current_imports = inspection
            .target_package_imports
            .get(&package.package_id)
            .with_context(|| {
                format!(
                    "current texture import inventory is missing {}",
                    package.path
                )
            })?;
        if !current_imports.is_empty() {
            bail!(
                "current Texture2D target {} declares imported packages; this is not a pure texture payload",
                package.path
            );
        }
    }
    Ok(inspection)
}

pub fn inspect_additive_static_mesh_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<ReplacementInspection> {
    let containers = discover_containers(root, retoc, ReplacementScope::AdditiveStaticMesh)?;
    let mut packages = containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    if packages.is_empty() || packages.len() > MAX_REPLACEMENT_PACKAGES {
        bail!("additive static-mesh input must contain 1..={MAX_REPLACEMENT_PACKAGES} packages");
    }
    packages.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
    });
    for pair in packages.windows(2) {
        if pair[0].path.eq_ignore_ascii_case(&pair[1].path)
            || pair[0].package_id == pair[1].package_id
        {
            bail!("additive static-mesh packages must have unique paths and package IDs");
        }
    }
    let target_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    let (_, target_entries) = retoc.package_store_entries(&target_utoc)?;
    let target_by_id = target_entries
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let source_ids = packages
        .iter()
        .map(|package| package.package_id)
        .collect::<HashSet<_>>();
    let mut target_dependencies = HashMap::new();
    for package in containers
        .iter()
        .flat_map(|container| &container.package_store)
    {
        for dependency in &package.imported_package_ids {
            if source_ids.contains(dependency) {
                continue;
            };
            let target = target_by_id.get(dependency).with_context(|| {
                format!(
                    "additive static-mesh package {} has unresolved external dependency {}",
                    package.path, dependency
                )
            })?;
            target_dependencies.insert(
                *dependency,
                PackageEntry {
                    package_id: *dependency,
                    path: target.path.clone(),
                },
            );
        }
    }
    Ok(ReplacementInspection {
        containers,
        packages,
        target_utoc,
        target_dependencies,
        target_package_imports: HashMap::new(),
    })
}
pub fn probe_input(mod_input: &Path, game_root: &Path) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-armor-replacement-probe-")
        .tempdir()?;
    let staged = work.path().join("input");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_staged(&staged, game_root, &retoc)?;
    Ok(ReplacementProbeSummary {
        container_count: inspection.containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: "skeletal-mesh-armor".to_owned(),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets: Vec::new(),
    })
}

pub fn probe_mixed_armor_input(
    mod_input: &Path,
    game_root: &Path,
) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-mixed-armor-probe-")
        .tempdir()?;
    let staged = work.path().join("input");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_mixed_armor_staged(&staged, game_root, &retoc)?;
    Ok(ReplacementProbeSummary {
        container_count: inspection.mesh.containers.len() + inspection.companion_containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: "mixed-armor-expansion-and-form-replacements".to_owned(),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets: Vec::new(),
    })
}

fn copy_probe_file(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(
        destination
            .parent()
            .context("probe copy destination has no parent")?,
    )?;
    fs::copy(source, destination)
        .with_context(|| format!("copying probe input {}", source.display()))?;
    Ok(())
}

fn find_extracted_asset(root: &Path, package_path: &str) -> Result<PathBuf> {
    let expected = canonical_package_path(package_path)?.to_ascii_lowercase();
    let matches = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
        })
        .filter(|path| {
            path.strip_prefix(root)
                .ok()
                .and_then(|relative| canonical_package_path(&relative.to_string_lossy()).ok())
                .is_some_and(|candidate| candidate.to_ascii_lowercase() == expected)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "expected one extracted Texture2D asset for {package_path}; found {}",
            matches.len()
        );
    }
    Ok(matches[0].clone())
}

fn extract_texture_package(
    retoc: &RetocTool,
    input: &Path,
    output: &Path,
    package: &PackageEntry,
    label: &str,
) -> Result<PathBuf> {
    fs::create_dir_all(output)?;
    let filter = canonical_package_path(&package.path)?
        .trim_end_matches(".uasset")
        .to_owned();
    let result = retoc.run([
        OsString::from("to-legacy"),
        input.as_os_str().to_owned(),
        output.as_os_str().to_owned(),
        OsString::from("--version"),
        OsString::from("UE5_3"),
        OsString::from("--no-shaders"),
        OsString::from("--no-script-objects"),
        OsString::from("--no-parallel"),
        OsString::from("--filter"),
        OsString::from(filter),
    ])?;
    let (extracted, failed) = RetocTool::extraction_summary(&result, label)?;
    if failed != 0 || extracted != 1 {
        bail!("{label} expected one Texture2D asset; extracted {extracted}, failed {failed}");
    }
    find_extracted_asset(output, &package.path)
}

fn find_extracted_additive_static_mesh(root: &Path, package_path: &str) -> Result<PathBuf> {
    let expected = canonical_additive_static_mesh_path(package_path)?.to_ascii_lowercase();
    let matches = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
        })
        .filter(|path| {
            path.strip_prefix(root)
                .ok()
                .and_then(|relative| {
                    canonical_additive_static_mesh_path(&relative.to_string_lossy()).ok()
                })
                .is_some_and(|path| path.to_ascii_lowercase() == expected)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "expected one extracted additive static mesh for {package_path}; found {}",
            matches.len()
        );
    }
    Ok(matches[0].clone())
}

pub fn probe_additive_static_mesh_input(
    mod_input: &Path,
    game_root: &Path,
) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-additive-static-mesh-probe-")
        .tempdir()?;
    let staged = work.path().join("source");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_additive_static_mesh_staged(&staged, game_root, &retoc)?;
    let paks = game_root.join(r"OblivionRemastered\Content\Paks");
    let global_utoc = paks.join("global.utoc");
    let global_ucas = paks.join("global.ucas");
    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let input = root.join("input");
        let legacy = root.join("legacy");
        fs::create_dir_all(&input)?;
        for source in [
            &global_utoc,
            &global_ucas,
            &container.utoc,
            &container.ucas,
            &container.pak,
        ] {
            copy_probe_file(source, &input.join(source.file_name().unwrap()))?;
        }
        let result = retoc.run([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ])?;
        let (extracted, failed) =
            RetocTool::extraction_summary(&result, "additive static-mesh source extraction")?;
        if failed != 0 || extracted != container.packages.len() {
            bail!(
                "additive static-mesh source extraction expected {} assets, extracted {extracted}, failed {failed}",
                container.packages.len()
            );
        }
        for package in &container.packages {
            inspect_static_mesh_asset(&find_extracted_additive_static_mesh(
                &legacy,
                &package.path,
            )?)
            .map_err(|_| {
                anyhow::anyhow!(
                    "{} did not pass structural StaticMesh inspection",
                    package.path
                )
            })?;
        }
    }
    Ok(ReplacementProbeSummary {
        container_count: inspection.containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: "additive-custom-static-mesh".to_owned(),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets: Vec::new(),
    })
}
pub fn probe_texture_input(mod_input: &Path, game_root: &Path) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-texture-replacement-probe-")
        .tempdir()?;
    let staged = work.path().join("source");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_texture_staged(&staged, game_root, &retoc)?;
    let game_paks = game_root.join(r"OblivionRemastered\Content\Paks");
    let global_utoc = game_paks.join("global.utoc");
    let global_ucas = game_paks.join("global.ucas");
    let mut texture_assets = Vec::new();

    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let input = root.join("input");
        let legacy = root.join("legacy");
        fs::create_dir_all(&input)?;
        for source in [
            &global_utoc,
            &global_ucas,
            &container.utoc,
            &container.ucas,
            &container.pak,
        ] {
            copy_probe_file(source, &input.join(source.file_name().unwrap()))?;
        }
        let result = retoc.run([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ])?;
        let (extracted, failed) =
            RetocTool::extraction_summary(&result, "texture source extraction")?;
        if failed != 0 || extracted != container.packages.len() {
            bail!(
                "texture source extraction expected {} assets; extracted {extracted}, failed {failed}",
                container.packages.len()
            );
        }
        for package in &container.packages {
            let source_asset = find_extracted_asset(&legacy, &package.path)?;
            let mut source = inspect_texture_asset(&source_asset).map_err(|_| {
                anyhow::anyhow!(
                    "{} did not pass structural Texture2D inspection",
                    package.path
                )
            })?;
            source.asset = package.path.clone();

            let current_root = work
                .path()
                .join("current")
                .join(package.package_id.to_string());
            let current_asset = extract_texture_package(
                &retoc,
                &game_paks,
                &current_root,
                package,
                "current Texture2D extraction",
            )?;
            let current = inspect_texture_asset(&current_asset).map_err(|_| {
                anyhow::anyhow!(
                    "current target {} did not pass structural Texture2D inspection",
                    package.path
                )
            })?;
            if !source
                .object_name
                .eq_ignore_ascii_case(&current.object_name)
            {
                bail!(
                    "Texture2D object identity changed for {}: source {}, current {}",
                    package.path,
                    source.object_name,
                    current.object_name
                );
            }
            if !source
                .pixel_format
                .eq_ignore_ascii_case(&current.pixel_format)
            {
                bail!(
                    "Texture2D pixel format differs from the current target for {}: source {}, current {}",
                    package.path,
                    source.pixel_format,
                    current.pixel_format
                );
            }
            if source.use_separate_bulk_data_files != current.use_separate_bulk_data_files {
                source.warnings.push(format!(
                    "Bulk streaming layout differs from the current target (source separate={}, current separate={}); sidecars will be preserved and runtime testing is required",
                    source.use_separate_bulk_data_files,
                    current.use_separate_bulk_data_files
                ));
            }
            texture_assets.push(source);
        }
    }
    texture_assets.sort_by_key(|asset| asset.asset.to_ascii_lowercase());
    Ok(ReplacementProbeSummary {
        container_count: inspection.containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: "texture2d".to_owned(),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_safe_custom_static_mesh_content_paths() {
        assert_eq!(
            canonical_additive_static_mesh_path(
                "../../../BackpackQuivers/Content/Art/Equipment/Weapons/Ebony/SM_Ebony_Quiver.uasset"
            )
            .unwrap(),
            "BackpackQuivers/Content/Art/Equipment/Weapons/Ebony/SM_Ebony_Quiver.uasset"
        );
        assert!(
            canonical_additive_static_mesh_path(
                "BackpackQuivers/Content/Art/Equipment/Weapons/Ebony/BP_Quiver.uasset"
            )
            .is_err()
        );
        assert!(
            canonical_additive_static_mesh_path(
                "OblivionRemastered/Content/Art/SM_NotCustom.uasset"
            )
            .is_err()
        );
        assert!(
            canonical_additive_static_mesh_path("BackpackQuivers/Content/../SM_Traversal.uasset")
                .is_err()
        );
    }
    #[test]
    fn canonicalizes_retoc_paths_case_insensitively() {
        assert_eq!(
            canonical_package_path(
                "../../../OblivionRemastered/Content/Art/armor/Daedric/SK_Test.uasset"
            )
            .unwrap(),
            "OblivionRemastered/Content/Art/armor/Daedric/SK_Test.uasset"
        );
        assert!(is_armor_skeletal_mesh(
            "OblivionRemastered/Content/Art/armor/Daedric/SK_Test.uasset"
        ));
        assert!(!is_armor_skeletal_mesh(
            "OblivionRemastered/Content/Maps/SK_Test.uasset"
        ));
        assert!(is_texture_candidate(
            "OblivionRemastered/Content/Art/armor/Test/T_Test_NNRM.uasset"
        ));
        assert!(!is_texture_candidate(
            "OblivionRemastered/Content/Art/armor/Test/T_Test_NNRM.umap"
        ));
    }
}
