use crate::archive::{
    copy_input_tree, copy_tree, create_zip_from_paths, sha256_directory, sha256_file,
};
use crate::container::lint_equal_order_overrides;
use crate::dependencies::{DependencyReport, check_or_install, game_is_running, scan_dependencies};
use crate::game::{save_settings, validate_game_install};
use crate::replacement::{
    ADDITIVE_STATIC_MESH_ADAPTER, ARMOR_REPLACEMENT_ADAPTER, MIXED_ARMOR_REPLACEMENT_ADAPTER,
    TEXTURE_REPLACEMENT_ADAPTER, canonical_additive_static_mesh_path, canonical_package_path,
    inspect_additive_static_mesh_staged, inspect_mixed_armor_staged, inspect_staged,
    inspect_texture_staged, stage_input,
};
use crate::retoc::{PackageEntry, RetocTool};
use crate::tes4::{
    package_to_game_path, read_plugin, read_sync_map, read_target_records, sorted_form_ids,
    validate_container_addition,
};
use crate::uasset::{
    BodySetupRepair, MaterialImportRepair, PayloadEquivalenceReport, SkeletalCompatibilityProfile,
    TextureAssetDiagnostic, derive_skeletal_compatibility_profile, inspect_static_mesh_asset,
    inspect_texture_asset, repair_legacy_body_setups, repair_skeletal_mesh_imports,
    verify_preserved_export_payloads, verify_rebased_payloads,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Clone, Debug)]
pub struct UpdateRequest {
    pub adapter: String,
    pub mod_input: PathBuf,
    pub game_root: PathBuf,
    pub output_parent: PathBuf,
    pub dependency_inputs: Vec<PathBuf>,
    pub installed_collision_exclusions: Vec<PathBuf>,
    pub persist_settings: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOutcome {
    pub adapter: String,
    pub output_directory: PathBuf,
    pub output_archive: PathBuf,
    pub report_path: PathBuf,
    pub package_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContainerHashes {
    utoc_sha256: String,
    ucas_sha256: String,
    pak_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RebuiltHashes {
    utoc_sha256: String,
    ucas_sha256: String,
    pak_sha256: String,
    retoc_verified: bool,
    inventory_preserved: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContainerResult {
    name: String,
    package_count: usize,
    packages: Vec<String>,
    source: ContainerHashes,
    rebuilt: RebuiltHashes,
    body_setup_repairs: Vec<BodySetupRepair>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementContainerResult {
    name: String,
    package_count: usize,
    packages: Vec<PackageEntry>,
    source: ContainerHashes,
    rebuilt: RebuiltHashes,
    material_import_repairs: Vec<MaterialImportRepair>,
    payload_equivalence: PayloadEquivalenceReport,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TextureContainerResult {
    name: String,
    package_count: usize,
    packages: Vec<PackageEntry>,
    source: ContainerHashes,
    rebuilt: RebuiltHashes,
    texture_assets: Vec<TextureAssetDiagnostic>,
    payload_equivalence: PayloadEquivalenceReport,
}

#[derive(Clone, Debug)]
struct ContainerInput {
    name: String,
    utoc: PathBuf,
    ucas: PathBuf,
    pak: PathBuf,
    packages: Vec<String>,
}

pub type ProgressCallback<'a> = dyn FnMut(usize, usize, &str) + Send + 'a;

fn stage(callback: &mut ProgressCallback<'_>, step: usize, message: &str) {
    callback(step, 7, message);
}

fn files_with_extension(directory: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut rows = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case(extension))
        })
        .collect::<Vec<_>>();
    rows.sort();
    Ok(rows)
}

fn find_mod_root(extracted: &Path) -> Result<PathBuf> {
    let roots = WalkDir::new(extracted)
        .max_depth(8)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_dir())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| {
            path.join(r"Content\Dev\ObvData\Data").is_dir()
                && path.join(r"Content\Paks\~mods").is_dir()
        })
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        bail!(
            "expected exactly one extracted mod root containing Content\\Dev and Content\\Paks\\~mods; found {}",
            roots.len()
        );
    }
    Ok(roots[0].clone())
}

fn ensure_same_set(expected: &[String], actual: &[String], label: &str) -> Result<()> {
    let mut expected = expected.to_vec();
    let mut actual = actual.to_vec();
    expected.sort();
    expected.dedup();
    actual.sort();
    actual.dedup();
    if expected != actual {
        bail!(
            "{label} changed. Expected:\n{}\nActual:\n{}",
            expected.join("\n"),
            actual.join("\n")
        );
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(
        destination
            .parent()
            .context("copy destination has no parent")?,
    )?;
    fs::copy(source, destination)
        .with_context(|| format!("copying {} to {}", source.display(), destination.display()))?;
    Ok(())
}

fn args(values: impl IntoIterator<Item = impl Into<OsString>>) -> Vec<OsString> {
    values.into_iter().map(Into::into).collect()
}

fn find_legacy_asset(root: &Path, package_path: &str) -> Result<PathBuf> {
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
            "expected one extracted legacy asset for {package_path}; found {}",
            matches.len()
        );
    }
    Ok(matches[0].clone())
}

fn ensure_no_installed_replacement_collisions(
    game_paks: &Path,
    packages: &[PackageEntry],
    retoc: &RetocTool,
    exclusions: &[PathBuf],
) -> Result<()> {
    let mods = game_paks.join("~mods");
    if !mods.is_dir() {
        return Ok(());
    }
    let expected = packages
        .iter()
        .map(|package| {
            Ok((
                canonical_package_path(&package.path)?.to_ascii_lowercase(),
                package.path.clone(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_keys = expected
        .iter()
        .map(|(key, _)| key.as_str())
        .collect::<HashSet<_>>();
    let exclusions = exclusions
        .iter()
        .map(|path| {
            fs::canonicalize(path)
                .unwrap_or_else(|_| path.to_path_buf())
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase()
        })
        .collect::<HashSet<_>>();
    let mut collisions = Vec::new();
    let mut utocs = WalkDir::new(&mods)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("utoc"))
        })
        .collect::<Vec<_>>();
    utocs.sort();
    for utoc in utocs {
        let normalized_utoc = fs::canonicalize(&utoc)
            .unwrap_or_else(|_| utoc.clone())
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if exclusions.contains(&normalized_utoc) {
            continue;
        }
        let (_, installed) = retoc
            .package_entries(&utoc)
            .with_context(|| format!("inspecting installed override {}", utoc.display()))?;
        for package in installed {
            let Ok(key) = canonical_package_path(&package.path) else {
                continue;
            };
            let key = key.to_ascii_lowercase();
            if expected_keys.contains(key.as_str()) {
                collisions.push(format!("{} in {}", package.path, utoc.display()));
            }
        }
    }
    if !collisions.is_empty() {
        bail!(
            "a replacement of the same armor is installed in the game ~mods directory. Remove it before updating so the current stock assets can be used as clean material donors:\n{}",
            collisions.join("\n")
        );
    }
    Ok(())
}

fn extract_current_package(
    retoc: &RetocTool,
    stock_utoc: &Path,
    destination: &Path,
    package: &PackageEntry,
) -> Result<PathBuf> {
    fs::create_dir_all(destination)?;
    let filter = canonical_package_path(&package.path)?
        .trim_end_matches(".uasset")
        .to_owned();
    let result = retoc.run(args([
        OsString::from("to-legacy"),
        stock_utoc.as_os_str().to_owned(),
        destination.as_os_str().to_owned(),
        OsString::from("--version"),
        OsString::from("UE5_3"),
        OsString::from("--no-shaders"),
        OsString::from("--no-script-objects"),
        OsString::from("--no-parallel"),
        OsString::from("--filter"),
        OsString::from(filter),
    ]))?;
    let (extracted, failed) = RetocTool::extraction_summary(
        &result,
        &format!("current stock donor extraction {}", package.path),
    )?;
    if failed != 0 || extracted == 0 {
        bail!(
            "current stock donor extraction expected at least the exact asset for {}; extracted {extracted}, failed {failed}",
            package.path
        );
    }
    find_legacy_asset(destination, &package.path)
}

fn create_isolated_stock_view(game_root: &Path) -> Result<tempfile::TempDir> {
    // Rebuild against stock data only so an installed override can never become an accidental donor.
    if game_is_running() {
        bail!(
            "Oblivion Remastered or OBSE appears to be running. Close the game before rebuilding an installed mod."
        );
    }
    let game_paks = game_root.join(r"OblivionRemastered\Content\Paks");
    let view = tempfile::Builder::new()
        .prefix(".obr-stock-view-")
        .tempdir_in(game_root)
        .context("creating an isolated stock-container view beside the game")?;
    for name in [
        "global.utoc",
        "global.ucas",
        "OblivionRemastered-Windows.utoc",
        "OblivionRemastered-Windows.ucas",
        "OblivionRemastered-Windows.pak",
    ] {
        let source = game_paks.join(name);
        if !source.is_file() {
            bail!("required stock container file is missing: {name}");
        }
        fs::hard_link(&source, view.path().join(name)).with_context(|| {
            format!(
                "creating a temporary hard link for {name}; the installed-mod batch requires a hard-link-capable game filesystem"
            )
        })?;
    }
    Ok(view)
}

#[derive(Clone, Debug)]
struct BodyProfileCandidate {
    source: String,
    utoc: PathBuf,
    body: PackageEntry,
    packages: Vec<PackageEntry>,
    installed: bool,
}

fn body_profile_candidates(
    root: &Path,
    source: &str,
    installed: bool,
    retoc: &RetocTool,
) -> Result<Vec<BodyProfileCandidate>> {
    let mut candidates = Vec::new();
    for entry in WalkDir::new(root).max_depth(14) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "compatibility source contains a filesystem link: {}",
                entry.path().display()
            );
        }
        if !entry.file_type().is_file()
            || !entry
                .path()
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("utoc"))
        {
            continue;
        }
        let utoc = entry.path().to_path_buf();
        if !utoc.with_extension("ucas").is_file() || !utoc.with_extension("pak").is_file() {
            continue;
        }
        let (_, packages) = retoc.package_entries(&utoc)?;
        let packages = packages
            .into_iter()
            .filter_map(|mut package| {
                package.path = canonical_package_path(&package.path).ok()?;
                Some(package)
            })
            .collect::<Vec<_>>();
        let body = packages.iter().find(|package| {
            package
                .path
                .to_ascii_lowercase()
                .ends_with("/content/art/character/imperial/sk_imperial_body_f.uasset")
        });
        let has_custom_skeleton = packages.iter().any(|package| {
            let lower = package.path.to_ascii_lowercase();
            lower.contains("/content/art/character/humanoid/skel_")
                && !lower.ends_with("/skel_humanoidskeleton.uasset")
        });
        if let Some(body) = body
            && has_custom_skeleton
        {
            retoc.verify(
                &utoc,
                &format!("retoc verify body compatibility source {source}"),
            )?;
            candidates.push(BodyProfileCandidate {
                source: source.to_owned(),
                utoc,
                body: body.clone(),
                packages,
                installed,
            });
        }
    }
    Ok(candidates)
}

fn discover_skeletal_compatibility_profile(
    dependency_inputs: &[PathBuf],
    game_root: &Path,
    stock_input: &Path,
    global_utoc: &Path,
    global_ucas: &Path,
    target_utoc: &Path,
    work: &Path,
    retoc: &RetocTool,
) -> Result<Option<(SkeletalCompatibilityProfile, Vec<PackageEntry>)>> {
    let mut candidates = Vec::new();
    let installed_root = game_root.join(r"OblivionRemastered\Content\Paks\~mods");
    if installed_root.is_dir() {
        candidates.extend(body_profile_candidates(
            &installed_root,
            "installed ~mods",
            true,
            retoc,
        )?);
    }
    let attached_root = work.join("attached-compatibility");
    fs::create_dir_all(&attached_root)?;
    for (index, input) in dependency_inputs.iter().enumerate() {
        if !input.exists() {
            continue;
        }
        let staged = attached_root.join(index.to_string());
        stage_input(input, &staged).with_context(|| {
            format!(
                "staging attached compatibility source {}",
                input.file_name().unwrap_or_default().to_string_lossy()
            )
        })?;
        let source = input
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("attached compatibility source");
        candidates.extend(body_profile_candidates(&staged, source, false, retoc)?);
    }
    if candidates.iter().any(|candidate| candidate.installed) {
        candidates.retain(|candidate| candidate.installed);
    }
    let mut seen_hashes = HashSet::new();
    candidates.retain(|candidate| {
        sha256_file(&candidate.utoc).is_ok_and(|hash| seen_hashes.insert(hash))
    });
    if candidates.is_empty() {
        return Ok(None);
    }
    if candidates.len() != 1 {
        bail!(
            "found {} different installed or attached female-body compatibility profiles; keep or attach exactly one body replacer while updating this mod",
            candidates.len()
        );
    }
    let candidate = candidates.remove(0);
    let profile_input = work.join("body-profile-input");
    let profile_legacy = work.join("body-profile-legacy");
    let profile_donor = work.join("body-profile-donor");
    for directory in [&profile_input, &profile_legacy, &profile_donor] {
        fs::create_dir_all(directory)?;
    }
    for source in [
        global_utoc,
        global_ucas,
        &candidate.utoc,
        &candidate.utoc.with_extension("ucas"),
        &candidate.utoc.with_extension("pak"),
    ] {
        copy_file(source, &profile_input.join(source.file_name().unwrap()))?;
    }
    let filter = canonical_package_path(&candidate.body.path)?
        .trim_end_matches(".uasset")
        .to_owned();
    let extraction = retoc.run(args([
        OsString::from("to-legacy"),
        profile_input.as_os_str().to_owned(),
        profile_legacy.as_os_str().to_owned(),
        OsString::from("--version"),
        OsString::from("UE5_3"),
        OsString::from("--no-shaders"),
        OsString::from("--no-script-objects"),
        OsString::from("--no-parallel"),
        OsString::from("--filter"),
        OsString::from(filter),
    ]))?;
    let (extracted, failed) =
        RetocTool::extraction_summary(&extraction, "attached body compatibility extraction")?;
    if extracted != 1 || failed != 0 {
        bail!(
            "attached body compatibility extraction expected one body mesh; extracted {extracted}, failed {failed}"
        );
    }
    let body_asset = find_legacy_asset(&profile_legacy, &candidate.body.path)?;

    let (_, stock_packages) = retoc.package_entries(target_utoc)?;
    let stock_packages = stock_packages
        .into_iter()
        .filter_map(|mut package| {
            package.path = canonical_package_path(&package.path).ok()?;
            Some(package)
        })
        .collect::<Vec<_>>();
    let body_key = canonical_package_path(&candidate.body.path)?.to_ascii_lowercase();
    let stock_body = stock_packages
        .iter()
        .find(|package| package.path.to_ascii_lowercase() == body_key)
        .context("current game has no stock donor for the attached female body mesh")?;
    let donor_asset = extract_current_package(retoc, stock_input, &profile_donor, stock_body)?;

    let mut combined = stock_packages
        .into_iter()
        .map(|package| (package.package_id, package))
        .collect::<HashMap<_, _>>();
    for package in &candidate.packages {
        if let Some(existing) = combined.get(&package.package_id)
            && !existing.path.eq_ignore_ascii_case(&package.path)
        {
            bail!(
                "attached body dependency package ID {} collides with current path {}",
                package.package_id,
                existing.path
            );
        }
        combined.insert(package.package_id, package.clone());
    }
    let profile = derive_skeletal_compatibility_profile(
        &candidate.source,
        &canonical_package_path(&candidate.body.path)?,
        &body_asset,
        &donor_asset,
        &combined,
        &work.join("body-profile-json"),
    )?;
    let required = [profile.skeleton_package_id, profile.material_package_id]
        .into_iter()
        .map(|package_id| {
            combined
                .get(&package_id)
                .cloned()
                .with_context(|| format!("body profile target package {package_id} disappeared"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some((profile, required)))
}

fn has_generic_body_material_name(asset: &Path) -> Result<bool> {
    let bytes = fs::read(asset)?;
    Ok(bytes
        .windows(b"material\0".len())
        .any(|window| window == b"material\0"))
}

fn safe_leaf(path: &Path) -> String {
    let raw = if path.is_file() {
        path.file_stem()
    } else {
        path.file_name()
    }
    .and_then(|value| value.to_str())
    .unwrap_or("mod");
    let mut result = String::with_capacity(raw.len());
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            result.push(character);
        } else if !result.ends_with('-') {
            result.push('-');
        }
    }
    result.trim_matches('-').to_owned()
}

fn portable_archive_path(output_directory: &Path) -> Result<PathBuf> {
    let parent = output_directory
        .parent()
        .context("candidate output directory has no parent")?;
    let name = output_directory
        .file_name()
        .context("candidate output directory has no name")?;
    Ok(parent.join(format!("{}.zip", name.to_string_lossy())))
}

pub fn run_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    // The adapter comes from preflight. Refuse unknown names instead of guessing which conversion is close enough.
    match request.adapter.as_str() {
        "native-additive-syncmap-v1" => run_additive_update(request, callback),
        ARMOR_REPLACEMENT_ADAPTER => run_armor_replacement_update(request, callback),
        MIXED_ARMOR_REPLACEMENT_ADAPTER => run_mixed_armor_replacement_update(request, callback),
        TEXTURE_REPLACEMENT_ADAPTER => run_texture_replacement_update(request, callback),
        ADDITIVE_STATIC_MESH_ADAPTER => run_additive_static_mesh_update(request, callback),
        adapter => bail!("preflight selected an unknown or empty update adapter: {adapter}"),
    }
}

fn run_additive_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    let mod_input = fs::canonicalize(&request.mod_input)
        .with_context(|| format!("mod input not found: {}", request.mod_input.display()))?;
    let input_type = if mod_input.is_file() {
        "archive"
    } else {
        "directory"
    };
    let input_hash = if mod_input.is_file() {
        sha256_file(&mod_input)?
    } else {
        sha256_directory(&mod_input)?
    };
    let game = validate_game_install(&request.game_root, "native UI");
    if !game.valid {
        bail!(
            "game folder is incomplete. Missing: {}",
            game.missing.join(", ")
        );
    }
    if !request.output_parent.is_dir() {
        bail!(
            "output parent does not exist: {}",
            request.output_parent.display()
        );
    }
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let output_directory = request.output_parent.join(format!(
        "{}-current-candidate-{stamp}",
        safe_leaf(&mod_input)
    ));
    let output_archive = portable_archive_path(&output_directory)?;
    if output_directory.exists() || output_archive.exists() {
        bail!("timestamped output already exists; wait one second and try again");
    }
    if request.persist_settings {
        save_settings(&game.root, &request.output_parent)?;
    }

    let game_paks = game.root.join(r"OblivionRemastered\Content\Paks");
    let game_data = game
        .root
        .join(r"OblivionRemastered\Content\Dev\ObvData\Data");
    let game_esm = game_data.join("Oblivion.esm");
    let global_utoc = game_paks.join("global.utoc");
    let global_ucas = game_paks.join("global.ucas");
    let work = tempfile::Builder::new()
        .prefix("obr-additive-update-")
        .tempdir()?;
    let extract_root = work.path().join("archive");
    let container_work = work.path().join("containers");
    fs::create_dir_all(&extract_root)?;
    fs::create_dir_all(&container_work)?;
    let retoc = RetocTool::materialize()?;

    stage(callback, 1, "Inspecting mod input and target game");
    copy_input_tree(&mod_input, &extract_root)?;
    let mod_root = find_mod_root(&extract_root)?;
    let mod_data = mod_root.join(r"Content\Dev\ObvData\Data");
    let mod_paks = mod_root.join(r"Content\Paks\~mods");
    let esp_files = files_with_extension(&mod_data, "esp")?;
    if esp_files.len() != 1 {
        bail!(
            "native additive scope requires exactly one ESP; found {}",
            esp_files.len()
        );
    }
    let sync_dir = mod_data.join("SyncMap");
    let sync_files = if sync_dir.is_dir() {
        files_with_extension(&sync_dir, "ini")?
    } else {
        Vec::new()
    };
    if sync_files.len() != 1 {
        bail!(
            "native additive scope requires exactly one SyncMap INI; found {}",
            sync_files.len()
        );
    }
    let utoc_files = files_with_extension(&mod_paks, "utoc")?;
    if utoc_files.is_empty() {
        bail!("mod contains no UTOC containers");
    }

    stage(
        callback,
        2,
        "Validating runtime tools, ESP, ESM override, and stable FormIDs",
    );
    let dependency_candidates = scan_dependencies(&request.dependency_inputs, Some(&mod_input));
    let dependency_report: DependencyReport =
        check_or_install(&game.root, dependency_candidates, true)?;
    if !dependency_report.ready {
        bail!(
            "SyncMap mod requires UE4SS and TesSyncMapInjector. Place their archives beside the mod or attach them in the app."
        );
    }
    let plugin = read_plugin(&esp_files[0])?;
    if plugin.masters != ["Oblivion.esm"] {
        bail!(
            "native additive scope supports one exact master, Oblivion.esm; found: {}",
            plugin.masters.join(", ")
        );
    }
    let plugin_index = plugin.masters.len() as u8;
    let owned_records = plugin
        .records
        .iter()
        .filter(|record| (record.form_id >> 24) as u8 == plugin_index)
        .collect::<Vec<_>>();
    let overrides = plugin
        .records
        .iter()
        .filter(|record| ((record.form_id >> 24) as u8) < plugin_index)
        .collect::<Vec<_>>();
    if plugin
        .records
        .iter()
        .any(|record| ((record.form_id >> 24) as u8) > plugin_index)
    {
        bail!("ESP contains records beyond its master/plugin index range");
    }
    let owned_ids = sorted_form_ids(owned_records.iter().map(|record| record.form_id));
    let override_ids = overrides
        .iter()
        .map(|record| record.form_id)
        .collect::<Vec<_>>();
    let current_records = read_target_records(&game_esm, &override_ids)?;
    let mut override_results = Vec::new();
    for override_record in overrides {
        let current = current_records
            .get(&override_record.form_id)
            .with_context(|| {
                format!(
                    "current Oblivion.esm has no override target 0x{:08X}",
                    override_record.form_id
                )
            })?;
        override_results.push(validate_container_addition(
            override_record,
            current,
            plugin_index,
        )?);
    }

    stage(callback, 3, "Checking that Unreal packages are additive");
    let mut container_inputs = Vec::new();
    let mut original_packages = Vec::new();
    for utoc in utoc_files {
        let name = utoc
            .file_stem()
            .and_then(|value| value.to_str())
            .context("UTOC has no filename")?
            .to_owned();
        let ucas = mod_paks.join(format!("{name}.ucas"));
        let pak = mod_paks.join(format!("{name}.pak"));
        if !ucas.is_file() {
            bail!("container is missing UCAS: {name}");
        }
        if !pak.is_file() {
            bail!("container is missing PAK: {name}");
        }
        retoc.verify(&utoc, &format!("retoc verify source {name}"))?;
        let (_, packages) = retoc.package_inventory(&utoc)?;
        original_packages.extend(packages.iter().cloned());
        container_inputs.push(ContainerInput {
            name,
            utoc,
            ucas,
            pak,
            packages,
        });
    }
    let container_precedence_warnings = lint_equal_order_overrides(
        container_inputs
            .iter()
            .map(|container| (container.name.as_str(), container.packages.as_slice())),
    );
    let container_precedence_warning_count = container_precedence_warnings.len();
    if let Some(warning) = container_precedence_warnings.first() {
        let message = format!(
            "Container precedence warning: {} ({} warning(s); full details will be written to the report)",
            warning.reason, container_precedence_warning_count
        );
        stage(callback, 3, &message);
    }
    original_packages.sort();
    original_packages.dedup();
    let target_probe = work.path().join("target-probe");
    fs::create_dir_all(&target_probe)?;
    let mut collisions = Vec::new();
    for package in &original_packages {
        let result = retoc.run(args([
            OsString::from("to-legacy"),
            game_paks.as_os_str().to_owned(),
            target_probe.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--dry-run"),
            OsString::from("--no-parallel"),
            OsString::from("--filter"),
            OsString::from(package),
        ]))?;
        let (extracted, failed) =
            RetocTool::extraction_summary(&result, &format!("target package probe {package}"))?;
        if failed != 0 {
            bail!("target package probe failed for {package}");
        }
        if extracted != 0 {
            collisions.push(package.clone());
        }
    }
    if !collisions.is_empty() {
        bail!(
            "mod is not additive: {} Unreal package path(s) already exist: {}",
            collisions.len(),
            collisions.join(", ")
        );
    }

    stage(
        callback,
        4,
        "Rebuilding Unreal containers against the detected game",
    );
    fs::create_dir_all(&output_directory)?;
    let candidate_root = output_directory.join(
        mod_root
            .file_name()
            .context("mod root has no directory name")?,
    );
    copy_tree(&mod_root, &candidate_root)?;
    let candidate_paks = candidate_root.join(r"Content\Paks\~mods");
    let mut container_results = Vec::new();
    for container in &container_inputs {
        let root = container_work.join(&container.name);
        let input = root.join("input");
        let legacy = root.join("legacy");
        let rebuilt = root.join("rebuilt");
        fs::create_dir_all(&input)?;
        fs::create_dir_all(&legacy)?;
        fs::create_dir_all(&rebuilt)?;
        for source in [
            &global_utoc,
            &global_ucas,
            &container.utoc,
            &container.ucas,
            &container.pak,
        ] {
            copy_file(source, &input.join(source.file_name().unwrap()))?;
        }
        let to_legacy = retoc.run(args([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ]))?;
        let (extracted, failed) = RetocTool::extraction_summary(
            &to_legacy,
            &format!("retoc to-legacy {}", container.name),
        )?;
        if failed != 0 || extracted != container.packages.len() {
            bail!(
                "retoc to-legacy {} expected {} assets, extracted {extracted}, failed {failed}",
                container.name,
                container.packages.len()
            );
        }
        let body_setup_repairs = repair_legacy_body_setups(&legacy)?;
        let rebuilt_utoc = rebuilt.join(format!("{}.utoc", container.name));
        let to_zen = retoc.run(args([
            OsString::from("to-zen"),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            legacy.as_os_str().to_owned(),
            rebuilt_utoc.as_os_str().to_owned(),
        ]))?;
        RetocTool::assert_success(&to_zen, &format!("retoc to-zen {}", container.name))?;
        let rebuilt_ucas = rebuilt_utoc.with_extension("ucas");
        let rebuilt_pak = rebuilt_utoc.with_extension("pak");
        for path in [&rebuilt_utoc, &rebuilt_ucas, &rebuilt_pak] {
            if !path.is_file() {
                bail!("rebuilt container output missing: {}", path.display());
            }
        }
        retoc.verify(
            &rebuilt_utoc,
            &format!("retoc verify rebuilt {}", container.name),
        )?;
        let (_, rebuilt_inventory) = retoc.package_inventory(&rebuilt_utoc)?;
        ensure_same_set(
            &container.packages,
            &rebuilt_inventory,
            &format!("package inventory for {}", container.name),
        )?;
        for path in [&rebuilt_utoc, &rebuilt_ucas, &rebuilt_pak] {
            copy_file(path, &candidate_paks.join(path.file_name().unwrap()))?;
        }
        container_results.push(ContainerResult {
            name: container.name.clone(),
            package_count: container.packages.len(),
            packages: container.packages.clone(),
            source: ContainerHashes {
                utoc_sha256: sha256_file(&container.utoc)?,
                ucas_sha256: sha256_file(&container.ucas)?,
                pak_sha256: sha256_file(&container.pak)?,
            },
            rebuilt: RebuiltHashes {
                utoc_sha256: sha256_file(&candidate_paks.join(format!("{}.utoc", container.name)))?,
                ucas_sha256: sha256_file(&candidate_paks.join(format!("{}.ucas", container.name)))?,
                pak_sha256: sha256_file(&candidate_paks.join(format!("{}.pak", container.name)))?,
                retoc_verified: true,
                inventory_preserved: true,
            },
            body_setup_repairs,
        });
    }

    stage(
        callback,
        5,
        "Rechecking ESP bytes, IDs, SyncMap, and package inventories",
    );
    let candidate_esp = candidate_root
        .join(r"Content\Dev\ObvData\Data")
        .join(esp_files[0].file_name().unwrap());
    let source_esp_hash = sha256_file(&esp_files[0])?;
    let candidate_esp_hash = sha256_file(&candidate_esp)?;
    if source_esp_hash != candidate_esp_hash {
        bail!("ESP bytes changed during update");
    }
    let candidate_plugin = read_plugin(&candidate_esp)?;
    let candidate_owned_ids = sorted_form_ids(
        candidate_plugin
            .records
            .iter()
            .filter(|record| (record.form_id >> 24) as u8 == plugin_index)
            .map(|record| record.form_id),
    );
    ensure_same_set(&owned_ids, &candidate_owned_ids, "plugin-owned ESP FormIDs")?;
    if plugin.masters != candidate_plugin.masters {
        bail!("ESP master list changed");
    }
    let game_package_paths = original_packages
        .iter()
        .map(|path| package_to_game_path(path))
        .collect::<Result<HashSet<_>>>()?;
    let owned_local_ids = owned_records
        .iter()
        .map(|record| record.form_id & 0x00FF_FFFF)
        .collect::<HashSet<_>>();
    let sync_entries = read_sync_map(&sync_files[0])?;
    if sync_entries.is_empty() {
        bail!("SyncMap contains no [Meshes] entries");
    }
    for entry in &sync_entries {
        let local_id = u32::from_str_radix(entry.local_form_id.trim_start_matches("0x"), 16)?;
        if !owned_local_ids.contains(&local_id) {
            bail!(
                "SyncMap key {} has no matching plugin-owned ESP FormID",
                entry.key
            );
        }
        if !game_package_paths.contains(&entry.package_path) {
            bail!(
                "SyncMap path {} has no matching rebuilt Unreal package",
                entry.package_path
            );
        }
    }
    let body_setup_repair_count = container_results
        .iter()
        .map(|container| container.body_setup_repairs.len())
        .sum::<usize>();
    let report_path = output_directory.join("additive-update-report.json");
    let report = json!({
        "schema": "obr-additive-mod-update-report",
        "version": 4,
        "implementation": "native-rust",
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "status": "candidate_ready_for_runtime_test",
        "structurallyVerified": true,
        "runtimeVerified": false,
        "source": {
            "inputType": input_type,
            "inputPath": mod_input,
            "inputSha256": input_hash,
            "esp": esp_files[0].file_name().unwrap().to_string_lossy(),
            "espSha256": source_esp_hash,
            "syncMap": sync_files[0].file_name().unwrap().to_string_lossy(),
            "syncMapSha256": sha256_file(&sync_files[0])?,
        },
        "target": {
            "gameRoot": game.root,
            "esm": game_esm,
            "esmBytes": fs::metadata(&game_esm)?.len(),
            "esmSha256": sha256_file(&game_esm)?,
            "globalUtocSha256": sha256_file(&global_utoc)?,
            "globalUcasSha256": sha256_file(&global_ucas)?,
        },
        "identity": {
            "esmEdited": false,
            "espBytePreserved": true,
            "espSourceSha256": source_esp_hash,
            "espCandidateSha256": candidate_esp_hash,
            "mastersPreserved": true,
            "masters": plugin.masters,
            "declaredRecordCount": plugin.declared_record_count,
            "nextObjectId": format!("0x{:08X}", plugin.next_object_id),
            "pluginOwnedFormIds": owned_ids,
            "masterOverrides": override_results,
            "syncMapEntries": sync_entries,
        },
        "unreal": {
            "additivePackageCount": original_packages.len(),
            "targetPathCollisionCount": 0,
            "bodySetupRepairCount": body_setup_repair_count,
            "collisionPolicy": "For recognized /Art/Equipment StaticMesh BodySetup exports, the incompatible derived cooked-physics tail is normalized to the shipping game's accepted empty-cache boundary while the serialized property region (including AggGeom simple-collision source data) and BodySetupGuid are preserved. Until runtime gate E-B proves the shipping game rebuilds a Chaos body from AggGeom, each change remains disclosed as collisionRemoved: true. World assets fail closed.",
            "packagePaths": original_packages,
            "containers": container_results,
            "containerNaming": {
                "pSuffixCaseInsensitive": true,
                "equalOrderWinner": "alphabetically-first",
                "inPlaceRebuildNamesPreserved": true,
                "strongerSuffixExample": "_2_P => mount order 303 (source-derived; shipping coexistence experiments E-1/E-2 remain pending)",
                "warningCount": container_precedence_warning_count,
                "warnings": container_precedence_warnings,
            },
        },
        "output": {
            "directory": output_directory,
            "archive": output_archive,
        },
        "verification": {
            "sourceContainersVerified": true,
            "rebuiltContainersVerified": true,
            "packageInventoriesPreserved": true,
            "espReparsed": true,
            "syncMapLinksResolved": true,
            "runtimeDependenciesReady": dependency_report.ready,
            "productionRuntimeGateRequired": true,
            "note": "This candidate is not called repaired until an in-game production run proves the content and behavior."
        },
        "runtimeDependencies": dependency_report,
    });
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;

    stage(callback, 6, "Creating portable candidate archive");
    create_zip_from_paths(
        &output_archive,
        &output_directory,
        &[candidate_root.clone(), report_path.clone()],
    )?;
    if !output_archive.is_file() {
        bail!(
            "output archive was not created: {}",
            output_archive.display()
        );
    }
    stage(
        callback,
        7,
        "Structural update complete; shipping-game test still required",
    );
    Ok(UpdateOutcome {
        adapter: "native-additive-syncmap-v1".to_owned(),
        output_directory,
        output_archive,
        report_path,
        package_count: original_packages.len(),
    })
}

fn canonical_entries(entries: &[PackageEntry]) -> Result<Vec<PackageEntry>> {
    let mut canonical = entries
        .iter()
        .map(|entry| {
            Ok(PackageEntry {
                package_id: entry.package_id,
                path: canonical_package_path(&entry.path)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    canonical.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
            .then(left.package_id.cmp(&right.package_id))
    });
    Ok(canonical)
}

fn ensure_same_package_entries(
    expected: &[PackageEntry],
    actual: &[PackageEntry],
    label: &str,
) -> Result<()> {
    let expected = canonical_entries(expected)?;
    let actual = canonical_entries(actual)?;
    let expected_keys = expected
        .iter()
        .map(|entry| (entry.path.to_ascii_lowercase(), entry.package_id))
        .collect::<Vec<_>>();
    let actual_keys = actual
        .iter()
        .map(|entry| (entry.path.to_ascii_lowercase(), entry.package_id))
        .collect::<Vec<_>>();
    if expected_keys != actual_keys {
        bail!(
            "{label} changed package paths or IDs. Expected:\n{}\nActual:\n{}",
            expected
                .iter()
                .map(|entry| format!("{} {}", entry.package_id, entry.path))
                .collect::<Vec<_>>()
                .join("\n"),
            actual
                .iter()
                .map(|entry| format!("{} {}", entry.package_id, entry.path))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn run_armor_replacement_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    run_armor_update(request, callback, false)
}

fn run_mixed_armor_replacement_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    run_armor_update(request, callback, true)
}

fn run_armor_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
    mixed_armor: bool,
) -> Result<UpdateOutcome> {
    let adapter = if mixed_armor {
        MIXED_ARMOR_REPLACEMENT_ADAPTER
    } else {
        ARMOR_REPLACEMENT_ADAPTER
    };
    let mod_input = fs::canonicalize(&request.mod_input)
        .with_context(|| format!("mod input not found: {}", request.mod_input.display()))?;
    let input_type = if mod_input.is_file() {
        "archive"
    } else {
        "directory"
    };
    let input_hash = if mod_input.is_file() {
        sha256_file(&mod_input)?
    } else {
        sha256_directory(&mod_input)?
    };
    let game = validate_game_install(&request.game_root, "native UI");
    if !game.valid {
        bail!(
            "game folder is incomplete. Missing: {}",
            game.missing.join(", ")
        );
    }
    if !request.output_parent.is_dir() {
        bail!(
            "output parent does not exist: {}",
            request.output_parent.display()
        );
    }
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let output_directory = request.output_parent.join(format!(
        "{}-current-candidate-{stamp}",
        safe_leaf(&mod_input)
    ));
    let output_archive = portable_archive_path(&output_directory)?;
    if output_directory.exists() || output_archive.exists() {
        bail!("timestamped output already exists; wait one second and try again");
    }
    if request.persist_settings {
        save_settings(&game.root, &request.output_parent)?;
    }

    let game_paks = game.root.join(r"OblivionRemastered\Content\Paks");
    let global_utoc = game_paks.join("global.utoc");
    let global_ucas = game_paks.join("global.ucas");
    let work = tempfile::Builder::new()
        .prefix("obr-armor-replacement-update-")
        .tempdir()?;
    let staged = work.path().join("source");
    let container_work = work.path().join("containers");
    let retoc = RetocTool::materialize()?;

    stage(
        callback,
        1,
        "Classifying the mod and checking current game package IDs",
    );
    stage_input(&mod_input, &staged)?;
    let (
        mut inspection,
        all_packages,
        companion_containers,
        donor_packages,
        companion_dependency_count,
    ) = if mixed_armor {
        let mixed = inspect_mixed_armor_staged(&staged, &game.root, &retoc)?;
        (
            mixed.mesh,
            mixed.packages,
            mixed.companion_containers,
            mixed.donor_packages,
            mixed.companion_dependency_count,
        )
    } else {
        let inspection = inspect_staged(&staged, &game.root, &retoc)?;
        let donor_packages = inspection
            .packages
            .iter()
            .map(|package| (package.package_id, package.clone()))
            .collect::<HashMap<_, _>>();
        let all_packages = inspection.packages.clone();
        (inspection, all_packages, Vec::new(), donor_packages, 0)
    };
    if !mixed_armor {
        ensure_no_installed_replacement_collisions(
            &game_paks,
            &all_packages,
            &retoc,
            &request.installed_collision_exclusions,
        )?;
    }
    let stock_view = if mixed_armor || !request.installed_collision_exclusions.is_empty() {
        Some(create_isolated_stock_view(&game.root)?)
    } else {
        None
    };
    let stock_input = stock_view
        .as_ref()
        .map(|view| view.path())
        .unwrap_or(game_paks.as_path());
    let skeletal_compatibility = if mixed_armor {
        discover_skeletal_compatibility_profile(
            &request.dependency_inputs,
            &game.root,
            stock_input,
            &global_utoc,
            &global_ucas,
            &inspection.target_utoc,
            &work.path().join("skeletal-compatibility"),
            &retoc,
        )?
    } else {
        None
    };
    if let Some((_, required_dependencies)) = &skeletal_compatibility {
        for dependency in required_dependencies {
            inspection
                .target_dependencies
                .insert(dependency.package_id, dependency.clone());
        }
    }
    if let Some((profile, _)) = &skeletal_compatibility {
        stage(
            callback,
            2,
            &format!(
                "Detected custom body profile from {}; skeleton {}",
                profile.source, profile.skeleton_object_name
            ),
        );
    }

    stage(
        callback,
        2,
        if mixed_armor {
            "Verifying separated armor-mesh and companion form container triples"
        } else {
            "Verifying complete pure armor-replacement container triples"
        },
    );
    fs::create_dir_all(&output_directory)?;
    copy_tree(&staged, &output_directory)?;
    fs::create_dir_all(&container_work)?;

    let mut container_results = Vec::new();
    let mut metadata_rebased_count = 0_usize;
    for container in &inspection.containers {
        let root = container_work.join(&container.name);
        let input = root.join("input");
        let legacy = root.join("legacy");
        let original_legacy = root.join("original-legacy");
        let migrated_legacy = root.join("migrated-legacy");
        let current_stock = root.join("current-stock");
        let material_work = root.join("material-import-repairs");
        let rebuilt = root.join("rebuilt");
        let roundtrip_input = root.join("roundtrip-input");
        let roundtrip_legacy = root.join("roundtrip-legacy");
        let json_work = root.join("payload-verification");
        for directory in [
            &input,
            &legacy,
            &original_legacy,
            &migrated_legacy,
            &current_stock,
            &material_work,
            &rebuilt,
            &roundtrip_input,
            &roundtrip_legacy,
            &json_work,
        ] {
            fs::create_dir_all(directory)?;
        }
        for source in [
            &global_utoc,
            &global_ucas,
            &container.utoc,
            &container.ucas,
            &container.pak,
        ] {
            copy_file(source, &input.join(source.file_name().unwrap()))?;
        }

        stage(
            callback,
            3,
            &format!("Extracting preserved payloads from {}", container.name),
        );
        let to_legacy = retoc.run(args([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ]))?;
        let (extracted, failed) = RetocTool::extraction_summary(
            &to_legacy,
            &format!("retoc to-legacy {}", container.name),
        )?;
        if failed != 0 || extracted != container.packages.len() {
            bail!(
                "retoc to-legacy {} expected {} assets, extracted {extracted}, failed {failed}",
                container.name,
                container.packages.len()
            );
        }
        copy_tree(&legacy, &original_legacy)?;

        let uses_generic_body_material = container
            .packages
            .iter()
            .map(|package| find_legacy_asset(&legacy, &package.path))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .map(|asset| has_generic_body_material_name(asset))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .any(|uses_alias| uses_alias);
        let compatibility_profile = if uses_generic_body_material {
            Some(
                &skeletal_compatibility
                    .as_ref()
                    .context(
                        "this armor uses generic body-material slots but no unique custom female-body dependency was found. Install its required body replacer in ~mods or connect that body archive under Dependencies, then run the update again",
                    )?
                    .0,
            )
        } else {
            None
        };

        stage(
            callback,
            4,
            &format!(
                "Migrating {} material and skeleton references to the current game",
                container.name
            ),
        );
        let mut material_import_repairs = Vec::new();
        for package in &container.packages {
            let source_store = container
                .package_store
                .iter()
                .find(|entry| entry.package_id == package.package_id)
                .with_context(|| {
                    format!("source package store is missing {}", package.package_id)
                })?;
            let expected_current_imports = inspection
                .target_package_imports
                .get(&package.package_id)
                .with_context(|| {
                    format!(
                        "current target import inventory is missing {}",
                        package.package_id
                    )
                })?;
            for dependency in expected_current_imports {
                if !inspection.target_dependencies.contains_key(dependency) {
                    bail!(
                        "current target dependency {dependency} for {} could not be resolved",
                        package.path
                    );
                }
            }
            let source_asset = find_legacy_asset(&legacy, &package.path)?;
            let donor = donor_packages
                .get(&package.package_id)
                .with_context(|| format!("current donor is missing for {}", package.path))?;
            let donor_root = current_stock.join(donor.package_id.to_string());
            let donor_asset = extract_current_package(&retoc, stock_input, &donor_root, donor)?;
            let mut repair = repair_skeletal_mesh_imports(
                &source_asset,
                &donor_asset,
                source_store,
                expected_current_imports,
                &inspection.target_dependencies,
                compatibility_profile,
                &material_work.join(package.package_id.to_string()),
            )
            .with_context(|| format!("repairing armor mesh imports for {}", package.path))?;
            repair.asset = package.path.clone();
            material_import_repairs.push(repair);
        }
        copy_tree(&legacy, &migrated_legacy)?;

        stage(
            callback,
            4,
            &format!("Rebuilding {} against current Zen metadata", container.name),
        );
        let rebuilt_utoc = rebuilt.join(format!("{}.utoc", container.name));
        let to_zen = retoc.run(args([
            OsString::from("to-zen"),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            legacy.as_os_str().to_owned(),
            rebuilt_utoc.as_os_str().to_owned(),
        ]))?;
        RetocTool::assert_success(&to_zen, &format!("retoc to-zen {}", container.name))?;
        let rebuilt_ucas = rebuilt_utoc.with_extension("ucas");
        let rebuilt_pak = rebuilt_utoc.with_extension("pak");
        for path in [&rebuilt_utoc, &rebuilt_ucas, &rebuilt_pak] {
            if !path.is_file() {
                bail!("rebuilt container output missing: {}", path.display());
            }
        }
        retoc.verify(
            &rebuilt_utoc,
            &format!("retoc verify rebuilt {}", container.name),
        )?;
        let (_, rebuilt_packages) = retoc.package_entries(&rebuilt_utoc)?;
        ensure_same_package_entries(
            &container.packages,
            &rebuilt_packages,
            &format!("package inventory for {}", container.name),
        )?;
        let (_, rebuilt_store) = retoc.package_store_entries(&rebuilt_utoc)?;
        for repair in &material_import_repairs {
            let entry = rebuilt_store
                .iter()
                .find(|entry| entry.package_id == repair.package_id)
                .with_context(|| {
                    format!(
                        "rebuilt package store is missing repaired package {}",
                        repair.package_id
                    )
                })?;
            let actual = entry
                .imported_package_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            let expected = repair
                .target_imported_package_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            if actual != expected {
                bail!(
                    "rebuilt dependency store for {} does not match the proven current material and skeleton targets. Expected {:?}; actual {:?}",
                    repair.asset,
                    expected,
                    actual
                );
            }
        }

        for source in [
            &global_utoc,
            &global_ucas,
            &rebuilt_utoc,
            &rebuilt_ucas,
            &rebuilt_pak,
        ] {
            copy_file(source, &roundtrip_input.join(source.file_name().unwrap()))?;
        }
        let roundtrip = retoc.run(args([
            OsString::from("to-legacy"),
            roundtrip_input.as_os_str().to_owned(),
            roundtrip_legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ]))?;
        let (roundtrip_extracted, roundtrip_failed) = RetocTool::extraction_summary(
            &roundtrip,
            &format!("retoc verification roundtrip {}", container.name),
        )?;
        if roundtrip_failed != 0 || roundtrip_extracted != container.packages.len() {
            bail!(
                "retoc verification roundtrip {} expected {} assets, extracted {roundtrip_extracted}, failed {roundtrip_failed}",
                container.name,
                container.packages.len()
            );
        }

        stage(
            callback,
            5,
            &format!(
                "Proving {} matches its approved payload migration",
                container.name
            ),
        );
        let payload_equivalence =
            verify_preserved_export_payloads(&migrated_legacy, &roundtrip_legacy, &json_work)?;
        metadata_rebased_count += payload_equivalence
            .assets
            .iter()
            .filter(|asset| asset.metadata_rebased)
            .count();

        let candidate_utoc = output_directory.join(&container.relative_utoc);
        let candidate_ucas = candidate_utoc.with_extension("ucas");
        let candidate_pak = candidate_utoc.with_extension("pak");
        copy_file(&rebuilt_utoc, &candidate_utoc)?;
        copy_file(&rebuilt_ucas, &candidate_ucas)?;
        copy_file(&rebuilt_pak, &candidate_pak)?;
        container_results.push(ReplacementContainerResult {
            name: container.name.clone(),
            package_count: container.packages.len(),
            packages: canonical_entries(&container.packages)?,
            source: ContainerHashes {
                utoc_sha256: sha256_file(&container.utoc)?,
                ucas_sha256: sha256_file(&container.ucas)?,
                pak_sha256: sha256_file(&container.pak)?,
            },
            rebuilt: RebuiltHashes {
                utoc_sha256: sha256_file(&candidate_utoc)?,
                ucas_sha256: sha256_file(&candidate_ucas)?,
                pak_sha256: sha256_file(&candidate_pak)?,
                retoc_verified: true,
                inventory_preserved: true,
            },
            material_import_repairs,
            payload_equivalence,
        });
    }

    let material_import_repair_count = container_results
        .iter()
        .flat_map(|container| container.material_import_repairs.iter())
        .map(|repair| repair.material_import_count)
        .sum::<usize>();
    let skeleton_import_repair_count = container_results
        .iter()
        .map(|container| container.material_import_repairs.len())
        .sum::<usize>();
    let obsolete_dependency_count = container_results
        .iter()
        .flat_map(|container| container.material_import_repairs.iter())
        .map(|repair| repair.missing_source_imported_package_ids.len())
        .sum::<usize>();
    let ignored_inactive_material_dependency_count = container_results
        .iter()
        .flat_map(|container| container.material_import_repairs.iter())
        .map(|repair| repair.ignored_inactive_material_dependencies.len())
        .sum::<usize>();
    let auxiliary_import_fallback_count = container_results
        .iter()
        .flat_map(|container| container.material_import_repairs.iter())
        .map(|repair| repair.auxiliary_import_count)
        .sum::<usize>();
    let retired_physics_asset_reference_count = container_results
        .iter()
        .flat_map(|container| container.material_import_repairs.iter())
        .map(|repair| repair.retired_physics_asset_import_count)
        .sum::<usize>();
    let already_retired_physics_asset_count = container_results
        .iter()
        .flat_map(|container| container.material_import_repairs.iter())
        .map(|repair| repair.already_retired_physics_asset_import_count)
        .sum::<usize>();
    let split_package_import_count = container_results
        .iter()
        .flat_map(|container| container.material_import_repairs.iter())
        .map(|repair| repair.split_package_import_count)
        .sum::<usize>();
    let source_payloads_preserved = retired_physics_asset_reference_count == 0;
    let preserved_companions = companion_containers
        .iter()
        .map(|container| -> Result<_> {
            let candidate_utoc = output_directory.join(&container.relative_utoc);
            let candidate_ucas = candidate_utoc.with_extension("ucas");
            let candidate_pak = candidate_utoc.with_extension("pak");
            retoc.verify(
                &candidate_utoc,
                &format!("retoc verify preserved companion {}", container.name),
            )?;
            let source_utoc = sha256_file(&container.utoc)?;
            let source_ucas = sha256_file(&container.ucas)?;
            let source_pak = sha256_file(&container.pak)?;
            if source_utoc != sha256_file(&candidate_utoc)?
                || source_ucas != sha256_file(&candidate_ucas)?
                || source_pak != sha256_file(&candidate_pak)?
            {
                bail!(
                    "preserved companion container {} changed while copying to the candidate",
                    container.name
                );
            }
            Ok(json!({
                "name": container.name,
                "packageCount": container.packages.len(),
                "packages": canonical_entries(&container.packages)?,
                "bytePreserved": true,
                "retocVerified": true,
                "source": {
                    "utocSha256": source_utoc,
                    "ucasSha256": source_ucas,
                    "pakSha256": source_pak,
                }
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let donor_mappings = inspection
        .packages
        .iter()
        .map(|package| {
            let donor = donor_packages
                .get(&package.package_id)
                .with_context(|| format!("report donor is missing for {}", package.path))?;
            Ok(json!({
                "sourcePackageId": package.package_id,
                "sourcePath": canonical_package_path(&package.path)?,
                "donorPackageId": donor.package_id,
                "donorPath": canonical_package_path(&donor.path)?,
                "additiveSiblingDonor": donor.package_id != package.package_id,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let report_path = output_directory.join("armor-replacement-update-report.json");
    let report = json!({
        "schema": "obr-armor-replacement-update-report",
        "version": 8,
        "implementation": "native-rust",
        "adapter": adapter,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "status": "candidate_ready_for_runtime_test",
        "structurallyVerified": true,
        "runtimeVerified": false,
        "source": {
            "inputType": input_type,
            "inputPath": mod_input,
            "inputSha256": input_hash,
        },
        "target": {
            "gameRoot": game.root,
            "gamePackageInventory": inspection.target_utoc,
            "gamePackageInventorySha256": sha256_file(&inspection.target_utoc)?,
            "globalUtocSha256": sha256_file(&global_utoc)?,
            "globalUcasSha256": sha256_file(&global_ucas)?,
        },
        "identity": {
            "replacementPackageCount": inspection.packages.len(),
            "packageCount": all_packages.len(),
            "migratedMeshPackageCount": inspection.packages.len(),
            "preservedCompanionPackageCount": all_packages.len() - inspection.packages.len(),
            "currentGamePathsAndPackageIdsMatched": !mixed_armor,
            "currentCompanionPathsAndPackageIdsMatched": true,
            "additiveMeshSiblingDonorsResolved": mixed_armor,
            "payloadMutationCount": retired_physics_asset_reference_count,
            "referenceMutationCount": material_import_repair_count + skeleton_import_repair_count + retired_physics_asset_reference_count,
            "materialImportRepairCount": material_import_repair_count,
            "skeletonImportRepairCount": skeleton_import_repair_count,
            "obsoleteSourceDependencyCount": obsolete_dependency_count,
            "ignoredInactiveMaterialDependencyCount": ignored_inactive_material_dependency_count,
            "auxiliaryImportFallbackCount": auxiliary_import_fallback_count,
            "retiredPhysicsAssetReferenceRepairCount": retired_physics_asset_reference_count,
            "alreadyRetiredPhysicsAssetTombstoneCount": already_retired_physics_asset_count,
            "splitPackageImportCount": split_package_import_count,
            "retiredPhysicsAssetMigrationIdempotent": true,
            "sourceExportPayloadsPreserved": source_payloads_preserved,
            "sourceSidecarsBytePreserved": source_payloads_preserved,
            "approvedPayloadMigrationRoundtripPreserved": true,
            "linkageMetadataRebasedAssetCount": metadata_rebased_count,
        },
        "unreal": {
            "containerCount": inspection.containers.len() + companion_containers.len(),
            "containers": container_results,
            "preservedCompanionContainers": preserved_companions,
            "companionDependencyCount": companion_dependency_count,
            "meshDonors": donor_mappings,
        },
        "compatibility": {
            "sourceGeometryAndSkinWeightsPreserved": true,
            "optionalBodyReplacerBundledOrCorrected": false,
            "externalBodyShapeCompatibilityClaimed": false,
            "customSkeletonAutoDetected": skeletal_compatibility.is_some(),
            "customSkeletonProfile": skeletal_compatibility.as_ref().map(|value| &value.0),
            "installedOverridesUsedAsDonors": false,
            "installedOverrideLoadOrderCompatibilityClaimed": false,
            "note": "The updater preserves source geometry and skin weights. When a generic body-material convention proves that this armor uses an installed or explicitly connected custom female body, the current body material and custom skeleton are rebound automatically. The body replacer remains an external requirement and is never bundled. Body shape, morph, cloth, and runtime physics compatibility are disclosed but not claimed."
        },
        "output": {
            "directory": output_directory,
            "archive": output_archive,
        },
        "verification": {
            "sourceContainersVerified": true,
            "rebuiltContainersVerified": true,
            "packagePathsAndIdsPreserved": true,
            "roundtripFileSetsPreserved": true,
            "exportPayloadsPreserved": source_payloads_preserved,
            "sidecarsBytePreserved": source_payloads_preserved,
            "approvedPayloadMigrationRoundtripPreserved": true,
            "currentMaterialAndSkeletonImportsMigrated": true,
            "customSkeletonDependencyAppliedWhenProven": true,
            "companionContainersBytePreserved": true,
            "companionDependencyClosureResolved": true,
            "serializedMaterialArraysParsed": true,
            "materialSlotsResolvedBySerializedName": true,
            "retiredPhysicsAssetReferencesNulled": true,
            "stalePhysicsCreateDependenciesRemoved": true,
            "productionRuntimeGateRequired": true,
            "note": "This candidate resolves real serialized FSkeletalMaterial slots by name, migrates the skeleton reference separately, and handles a retired source PhysicsAsset only when the current donor has none and four independent structural gates prove its role. That stale typed reference is nulled and its create dependency removed instead of being mislabeled as a material. The rebuilt package must roundtrip to the approved migrated bytes exactly. It is not called runtime verified until an in-game production run proves the armor, geometry, and textures load correctly."
        }
    });
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;

    stage(callback, 6, "Creating portable armor candidate archive");
    create_zip_from_paths(
        &output_archive,
        &output_directory,
        std::slice::from_ref(&output_directory),
    )?;
    if !output_archive.is_file() {
        bail!(
            "output archive was not created: {}",
            output_archive.display()
        );
    }
    stage(
        callback,
        7,
        "Payload-preserving rebase complete; shipping-game test still required",
    );
    Ok(UpdateOutcome {
        adapter: adapter.to_owned(),
        output_directory,
        output_archive,
        report_path,
        package_count: all_packages.len(),
    })
}

fn run_texture_replacement_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    let mod_input = fs::canonicalize(&request.mod_input)
        .with_context(|| format!("mod input not found: {}", request.mod_input.display()))?;
    let input_type = if mod_input.is_file() {
        "archive"
    } else {
        "directory"
    };
    let input_hash = if mod_input.is_file() {
        sha256_file(&mod_input)?
    } else {
        sha256_directory(&mod_input)?
    };
    let game = validate_game_install(&request.game_root, "native UI");
    if !game.valid {
        bail!(
            "game folder is incomplete. Missing: {}",
            game.missing.join(", ")
        );
    }
    if !request.output_parent.is_dir() {
        bail!(
            "output parent does not exist: {}",
            request.output_parent.display()
        );
    }
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let output_directory = request.output_parent.join(format!(
        "{}-current-candidate-{stamp}",
        safe_leaf(&mod_input)
    ));
    let output_archive = portable_archive_path(&output_directory)?;
    if output_directory.exists() || output_archive.exists() {
        bail!("timestamped output already exists; wait one second and try again");
    }
    if request.persist_settings {
        save_settings(&game.root, &request.output_parent)?;
    }

    let game_paks = game.root.join(r"OblivionRemastered\Content\Paks");
    let global_utoc = game_paks.join("global.utoc");
    let global_ucas = game_paks.join("global.ucas");
    let work = tempfile::Builder::new()
        .prefix("obr-texture-replacement-update-")
        .tempdir()?;
    let staged = work.path().join("source");
    let container_work = work.path().join("containers");
    let retoc = RetocTool::materialize()?;

    stage(
        callback,
        1,
        "Classifying Texture2D packages and checking current game identities",
    );
    stage_input(&mod_input, &staged)?;
    let inspection = inspect_texture_staged(&staged, &game.root, &retoc)?;
    ensure_no_installed_replacement_collisions(
        &game_paks,
        &inspection.packages,
        &retoc,
        &request.installed_collision_exclusions,
    )?;
    let stock_view = if request.installed_collision_exclusions.is_empty() {
        None
    } else {
        Some(create_isolated_stock_view(&game.root)?)
    };
    let stock_input = stock_view
        .as_ref()
        .map(|view| view.path())
        .unwrap_or(game_paks.as_path());

    stage(
        callback,
        2,
        "Verifying pure dependency-free Texture2D replacement containers",
    );
    fs::create_dir_all(&output_directory)?;
    copy_tree(&staged, &output_directory)?;
    fs::create_dir_all(&container_work)?;

    let mut container_results = Vec::new();
    let mut metadata_rebased_count = 0_usize;
    for container in &inspection.containers {
        let root = container_work.join(&container.name);
        let input = root.join("input");
        let legacy = root.join("legacy");
        let current_stock = root.join("current-stock");
        let rebuilt = root.join("rebuilt");
        let roundtrip_input = root.join("roundtrip-input");
        let roundtrip_legacy = root.join("roundtrip-legacy");
        let json_work = root.join("payload-verification");
        for directory in [
            &input,
            &legacy,
            &current_stock,
            &rebuilt,
            &roundtrip_input,
            &roundtrip_legacy,
            &json_work,
        ] {
            fs::create_dir_all(directory)?;
        }
        for source in [
            &global_utoc,
            &global_ucas,
            &container.utoc,
            &container.ucas,
            &container.pak,
        ] {
            copy_file(source, &input.join(source.file_name().unwrap()))?;
        }

        stage(
            callback,
            3,
            &format!("Extracting Texture2D payloads from {}", container.name),
        );
        let to_legacy = retoc.run(args([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ]))?;
        let (extracted, failed) = RetocTool::extraction_summary(
            &to_legacy,
            &format!("retoc to-legacy {}", container.name),
        )?;
        if failed != 0 || extracted != container.packages.len() {
            bail!(
                "retoc to-legacy {} expected {} Texture2D assets, extracted {extracted}, failed {failed}",
                container.name,
                container.packages.len()
            );
        }

        stage(
            callback,
            4,
            &format!(
                "Checking {} texture classes, formats, bulk data, and current donors",
                container.name
            ),
        );
        let mut texture_assets = Vec::new();
        for package in &container.packages {
            let source_asset = find_legacy_asset(&legacy, &package.path)?;
            let mut source = inspect_texture_asset(&source_asset)?;
            source.asset = canonical_package_path(&package.path)?;

            let donor_root = current_stock.join(package.package_id.to_string());
            let donor_asset = extract_current_package(&retoc, stock_input, &donor_root, package)?;
            let donor = inspect_texture_asset(&donor_asset)?;
            if !source.class_name.eq_ignore_ascii_case("Texture2D")
                || !donor.class_name.eq_ignore_ascii_case("Texture2D")
            {
                bail!("Texture2D class proof failed for {}", package.path);
            }
            if !source.object_name.eq_ignore_ascii_case(&donor.object_name) {
                bail!(
                    "Texture2D object identity changed for {}: source {}, current {}",
                    package.path,
                    source.object_name,
                    donor.object_name
                );
            }
            if !source
                .pixel_format
                .eq_ignore_ascii_case(&donor.pixel_format)
            {
                bail!(
                    "Texture2D pixel format differs from the current target for {}: source {}, current {}",
                    package.path,
                    source.pixel_format,
                    donor.pixel_format
                );
            }
            if source.use_separate_bulk_data_files != donor.use_separate_bulk_data_files {
                source.warnings.push(format!(
                    "Bulk streaming layout differs from the current target (source separate={}, current separate={}); source sidecars are preserved and runtime testing is required",
                    source.use_separate_bulk_data_files,
                    donor.use_separate_bulk_data_files
                ));
            }
            texture_assets.push(source);
        }
        texture_assets.sort_by_key(|asset| asset.asset.to_ascii_lowercase());

        let rebuilt_utoc = rebuilt.join(format!("{}.utoc", container.name));
        let to_zen = retoc.run(args([
            OsString::from("to-zen"),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            legacy.as_os_str().to_owned(),
            rebuilt_utoc.as_os_str().to_owned(),
        ]))?;
        RetocTool::assert_success(&to_zen, &format!("retoc to-zen {}", container.name))?;
        let rebuilt_ucas = rebuilt_utoc.with_extension("ucas");
        let rebuilt_pak = rebuilt_utoc.with_extension("pak");
        for path in [&rebuilt_utoc, &rebuilt_ucas, &rebuilt_pak] {
            if !path.is_file() {
                bail!(
                    "rebuilt texture container output missing: {}",
                    path.display()
                );
            }
        }
        retoc.verify(
            &rebuilt_utoc,
            &format!("retoc verify rebuilt {}", container.name),
        )?;
        let (_, rebuilt_packages) = retoc.package_entries(&rebuilt_utoc)?;
        ensure_same_package_entries(
            &container.packages,
            &rebuilt_packages,
            &format!("texture package inventory for {}", container.name),
        )?;
        let (_, rebuilt_store) = retoc.package_store_entries(&rebuilt_utoc)?;
        for package in &container.packages {
            let entry = rebuilt_store
                .iter()
                .find(|entry| entry.package_id == package.package_id)
                .with_context(|| {
                    format!("rebuilt texture store is missing {}", package.package_id)
                })?;
            if !entry.imported_package_ids.is_empty() {
                bail!(
                    "rebuilt Texture2D package unexpectedly gained imports: {}",
                    package.path
                );
            }
        }

        for source in [
            &global_utoc,
            &global_ucas,
            &rebuilt_utoc,
            &rebuilt_ucas,
            &rebuilt_pak,
        ] {
            copy_file(source, &roundtrip_input.join(source.file_name().unwrap()))?;
        }
        let roundtrip = retoc.run(args([
            OsString::from("to-legacy"),
            roundtrip_input.as_os_str().to_owned(),
            roundtrip_legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ]))?;
        let (roundtrip_extracted, roundtrip_failed) = RetocTool::extraction_summary(
            &roundtrip,
            &format!("texture verification roundtrip {}", container.name),
        )?;
        if roundtrip_failed != 0 || roundtrip_extracted != container.packages.len() {
            bail!(
                "texture verification roundtrip {} expected {} assets, extracted {roundtrip_extracted}, failed {roundtrip_failed}",
                container.name,
                container.packages.len()
            );
        }

        stage(
            callback,
            5,
            &format!(
                "Proving {} preserved texture exports, UEXP, and UBULK bytes",
                container.name
            ),
        );
        let payload_equivalence = verify_rebased_payloads(&legacy, &roundtrip_legacy, &json_work)?;
        metadata_rebased_count += payload_equivalence
            .assets
            .iter()
            .filter(|asset| asset.metadata_rebased)
            .count();

        let candidate_utoc = output_directory.join(&container.relative_utoc);
        let candidate_ucas = candidate_utoc.with_extension("ucas");
        let candidate_pak = candidate_utoc.with_extension("pak");
        copy_file(&rebuilt_utoc, &candidate_utoc)?;
        copy_file(&rebuilt_ucas, &candidate_ucas)?;
        copy_file(&rebuilt_pak, &candidate_pak)?;
        container_results.push(TextureContainerResult {
            name: container.name.clone(),
            package_count: container.packages.len(),
            packages: canonical_entries(&container.packages)?,
            source: ContainerHashes {
                utoc_sha256: sha256_file(&container.utoc)?,
                ucas_sha256: sha256_file(&container.ucas)?,
                pak_sha256: sha256_file(&container.pak)?,
            },
            rebuilt: RebuiltHashes {
                utoc_sha256: sha256_file(&candidate_utoc)?,
                ucas_sha256: sha256_file(&candidate_ucas)?,
                pak_sha256: sha256_file(&candidate_pak)?,
                retoc_verified: true,
                inventory_preserved: true,
            },
            texture_assets,
            payload_equivalence,
        });
    }

    let texture_warning_count = container_results
        .iter()
        .flat_map(|container| container.texture_assets.iter())
        .map(|asset| asset.warnings.len())
        .sum::<usize>();
    let ubulk_asset_count = container_results
        .iter()
        .flat_map(|container| container.texture_assets.iter())
        .filter(|asset| asset.ubulk_bytes.is_some())
        .count();
    let report_path = output_directory.join("texture-replacement-update-report.json");
    let report = json!({
        "schema": "obr-texture-replacement-update-report",
        "version": 1,
        "implementation": "native-rust",
        "adapter": TEXTURE_REPLACEMENT_ADAPTER,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "status": "candidate_ready_for_runtime_test",
        "structurallyVerified": true,
        "runtimeVerified": false,
        "source": {
            "inputType": input_type,
            "inputPath": mod_input,
            "inputSha256": input_hash,
        },
        "target": {
            "gameRoot": game.root,
            "gamePackageInventory": inspection.target_utoc,
            "gamePackageInventorySha256": sha256_file(&inspection.target_utoc)?,
            "globalUtocSha256": sha256_file(&global_utoc)?,
            "globalUcasSha256": sha256_file(&global_ucas)?,
        },
        "identity": {
            "texturePackageCount": inspection.packages.len(),
            "currentGamePathsAndPackageIdsMatched": true,
            "textureClassesProven": true,
            "objectNamesMatchedCurrentTargets": true,
            "pixelFormatsMatchedCurrentTargets": true,
            "dependencyFreePackageStores": true,
            "rawExportsPreserved": true,
            "sidecarsBytePreserved": true,
            "ubulkAssetCount": ubulk_asset_count,
            "diagnosticWarningCount": texture_warning_count,
            "linkageMetadataRebasedAssetCount": metadata_rebased_count,
        },
        "unreal": {
            "containerCount": inspection.containers.len(),
            "containers": container_results,
        },
        "output": {
            "directory": output_directory,
            "archive": output_archive,
        },
        "verification": {
            "sourceContainersVerified": true,
            "rebuiltContainersVerified": true,
            "packagePathsAndIdsPreserved": true,
            "roundtripFileSetsPreserved": true,
            "textureRawExportsPreserved": true,
            "uexpAndUbulkBytePreserved": true,
            "productionRuntimeGateRequired": true,
            "note": "This lane does not decode, recompress, recolor, or reinterpret texture channels. It preserves the authored Texture2D export and bulk payloads while rebuilding current Zen linkage metadata. NNRM alpha/channel correctness and in-game streaming remain runtime-test requirements."
        }
    });
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;

    stage(
        callback,
        6,
        "Creating portable Texture2D replacement candidate archive",
    );
    create_zip_from_paths(
        &output_archive,
        &output_directory,
        std::slice::from_ref(&output_directory),
    )?;
    if !output_archive.is_file() {
        bail!(
            "output archive was not created: {}",
            output_archive.display()
        );
    }
    stage(
        callback,
        7,
        "Texture payload rebase complete; shipping-game test still required",
    );
    Ok(UpdateOutcome {
        adapter: TEXTURE_REPLACEMENT_ADAPTER.to_owned(),
        output_directory,
        output_archive,
        report_path,
        package_count: inspection.packages.len(),
    })
}

fn find_additive_static_mesh_asset(root: &Path, package_path: &str) -> Result<PathBuf> {
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
                .is_some_and(|candidate| candidate.to_ascii_lowercase() == expected)
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

fn run_additive_static_mesh_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    let mod_input = fs::canonicalize(&request.mod_input)
        .with_context(|| format!("mod input not found: {}", request.mod_input.display()))?;
    let input_hash = if mod_input.is_file() {
        sha256_file(&mod_input)?
    } else {
        sha256_directory(&mod_input)?
    };
    let game = validate_game_install(&request.game_root, "native UI");
    if !game.valid {
        bail!(
            "game folder is incomplete. Missing: {}",
            game.missing.join(", ")
        );
    }
    if !request.output_parent.is_dir() {
        bail!(
            "output parent does not exist: {}",
            request.output_parent.display()
        );
    }
    let output_directory = request.output_parent.join(format!(
        "{}-current-candidate-{}",
        safe_leaf(&mod_input),
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    let output_archive = portable_archive_path(&output_directory)?;
    if output_directory.exists() || output_archive.exists() {
        bail!("timestamped output already exists; wait one second and try again");
    }
    if request.persist_settings {
        save_settings(&game.root, &request.output_parent)?;
    }
    let paks = game.root.join(r"OblivionRemastered\Content\Paks");
    let global_utoc = paks.join("global.utoc");
    let global_ucas = paks.join("global.ucas");
    let work = tempfile::Builder::new()
        .prefix("obr-additive-static-mesh-update-")
        .tempdir()?;
    let staged = work.path().join("source");
    let retoc = RetocTool::materialize()?;
    stage(
        callback,
        1,
        "Classifying custom StaticMesh packages and resolving imports",
    );
    stage_input(&mod_input, &staged)?;
    let inspection = inspect_additive_static_mesh_staged(&staged, &game.root, &retoc)?;
    fs::create_dir_all(&output_directory)?;
    copy_tree(&staged, &output_directory)?;
    let mut results = Vec::new();
    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let input = root.join("input");
        let legacy = root.join("legacy");
        let rebuilt = root.join("rebuilt");
        let verify_input = root.join("verify-input");
        let verify_legacy = root.join("verify-legacy");
        let json_work = root.join("payload-verification");
        for dir in [
            &input,
            &legacy,
            &rebuilt,
            &verify_input,
            &verify_legacy,
            &json_work,
        ] {
            fs::create_dir_all(dir)?;
        }
        for source in [
            &global_utoc,
            &global_ucas,
            &container.utoc,
            &container.ucas,
            &container.pak,
        ] {
            copy_file(source, &input.join(source.file_name().unwrap()))?;
        }
        stage(
            callback,
            2,
            &format!(
                "Extracting guarded custom static meshes from {}",
                container.name
            ),
        );
        let run = retoc.run(args([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ]))?;
        let (count, failed) = RetocTool::extraction_summary(
            &run,
            &format!("custom static-mesh extraction {}", container.name),
        )?;
        if failed != 0 || count != container.packages.len() {
            bail!(
                "custom static-mesh extraction {} expected {} assets, extracted {count}, failed {failed}",
                container.name,
                container.packages.len()
            );
        }
        for package in &container.packages {
            inspect_static_mesh_asset(&find_additive_static_mesh_asset(&legacy, &package.path)?)?;
        }
        stage(
            callback,
            3,
            &format!("Rebuilding {} against current Zen metadata", container.name),
        );
        let utoc = rebuilt.join(format!("{}.utoc", container.name));
        let zen = retoc.run(args([
            OsString::from("to-zen"),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            legacy.as_os_str().to_owned(),
            utoc.as_os_str().to_owned(),
        ]))?;
        RetocTool::assert_success(&zen, &format!("retoc to-zen {}", container.name))?;
        let ucas = utoc.with_extension("ucas");
        let pak = utoc.with_extension("pak");
        for path in [&utoc, &ucas, &pak] {
            if !path.is_file() {
                bail!("rebuilt static-mesh output missing: {}", path.display());
            }
        }
        retoc.verify(&utoc, &format!("retoc verify rebuilt {}", container.name))?;
        let (_, entries) = retoc.package_entries(&utoc)?;
        let expected = container
            .packages
            .iter()
            .map(|e| {
                Ok((
                    canonical_additive_static_mesh_path(&e.path)?.to_ascii_lowercase(),
                    e.package_id,
                ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let actual = entries
            .iter()
            .map(|e| {
                Ok((
                    canonical_additive_static_mesh_path(&e.path)?.to_ascii_lowercase(),
                    e.package_id,
                ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if expected != actual {
            bail!("rebuilt package inventory changed for {}", container.name);
        }
        let (_, store) = retoc.package_store_entries(&utoc)?;
        for original in &container.package_store {
            let rebuilt_entry = store
                .iter()
                .find(|e| e.package_id == original.package_id)
                .with_context(|| {
                    format!("rebuilt package store is missing {}", original.package_id)
                })?;
            if BTreeSet::from_iter(rebuilt_entry.imported_package_ids.iter().copied())
                != BTreeSet::from_iter(original.imported_package_ids.iter().copied())
            {
                bail!("rebuilt package imports changed for {}", original.path);
            }
        }
        for source in [&global_utoc, &global_ucas, &utoc, &ucas, &pak] {
            copy_file(source, &verify_input.join(source.file_name().unwrap()))?;
        }
        let roundtrip = retoc.run(args([
            OsString::from("to-legacy"),
            verify_input.as_os_str().to_owned(),
            verify_legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ]))?;
        let (verify_count, verify_failed) = RetocTool::extraction_summary(
            &roundtrip,
            &format!("custom static-mesh roundtrip {}", container.name),
        )?;
        if verify_failed != 0 || verify_count != container.packages.len() {
            bail!(
                "custom static-mesh roundtrip {} expected {} assets, extracted {verify_count}, failed {verify_failed}",
                container.name,
                container.packages.len()
            );
        }
        let payload = verify_preserved_export_payloads(&legacy, &verify_legacy, &json_work)?;
        let candidate_utoc = output_directory.join(&container.relative_utoc);
        let candidate_ucas = candidate_utoc.with_extension("ucas");
        let candidate_pak = candidate_utoc.with_extension("pak");
        copy_file(&utoc, &candidate_utoc)?;
        copy_file(&ucas, &candidate_ucas)?;
        copy_file(&pak, &candidate_pak)?;
        results.push(json!({"name":container.name,"packages":container.packages,"payloadEquivalence":payload}));
    }
    let report_path = output_directory.join("custom-static-mesh-update-report.json");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(
            &json!({"schema":"obr-custom-static-mesh-update-report","version":1,"adapter":ADDITIVE_STATIC_MESH_ADAPTER,"status":"candidate_ready_for_runtime_test","structurallyVerified":true,"runtimeVerified":false,"sourceSha256":input_hash,"gamePackageInventory":inspection.target_utoc,"containers":results,"verification":{"packagePathsAndIdsPreserved":true,"packageImportsPreserved":true,"roundtripFileSetsPreserved":true,"productionRuntimeGateRequired":true}}),
        )?,
    )?;
    stage(
        callback,
        4,
        "Creating portable custom StaticMesh candidate archive",
    );
    create_zip_from_paths(
        &output_archive,
        &output_directory,
        std::slice::from_ref(&output_directory),
    )?;
    if !output_archive.is_file() {
        bail!(
            "output archive was not created: {}",
            output_archive.display()
        );
    }
    stage(
        callback,
        5,
        "Custom static-mesh candidate complete; shipping-game test still required",
    );
    Ok(UpdateOutcome {
        adapter: ADDITIVE_STATIC_MESH_ADAPTER.to_owned(),
        output_directory,
        output_archive,
        report_path,
        package_count: inspection.packages.len(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_archive_name_preserves_dots_and_timestamp() {
        let directory = Path::new(r"C:\tmp\RAO-1.0-current-candidate-20260713-225545");
        assert_eq!(
            portable_archive_path(directory).unwrap(),
            PathBuf::from(r"C:\tmp\RAO-1.0-current-candidate-20260713-225545.zip")
        );
    }
}
