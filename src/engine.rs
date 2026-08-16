use crate::archive::{
    copy_input_tree, copy_tree, create_zip_from_paths, sha256_directory, sha256_file,
};
use crate::container::lint_equal_order_overrides;
use crate::dependencies::{
    DependencyKind, DependencyReport, RUNTIME_DEPENDENCY_TRANSACTION_API, check_or_install,
    game_is_running, installed_state, scan_dependencies,
};
use crate::fixes::{
    DEPENDENCY_DIAGNOSTIC_API, DEPENDENCY_PRESERVATION_API, DependencyPreservationReport,
    EXACT_DEPENDENCY_EXTRACTION_API, ExactExtractionReport, diagnose_package_dependencies,
    extract_packages_with_dependency_view,
};
use crate::dependency_layers::{
    LAYERED_IOSTORE_DEPENDENCY_API, LayeredProbeWithSources, PackageProviderLayer,
    probe_layered_iostore_dependencies_with_sources,
};
use crate::game::{save_settings, validate_game_install};
use crate::install_plan::{
    InstallPlan, build_logical_update_context, logical_install_adapter_id,
    nested_logical_install_adapter, reconstruct_logical_update_candidate,
    resolve_staged_install_view, supports_logical_install_publication, verify_install_trees_match,
};
use crate::pak::{
    LEGACY_PAK_PASSTHROUGH_ADAPTER, probe_legacy_pak_passthrough_input, publish_passthrough_paks,
};
use crate::plugin::{
    ADDITIVE_CONTRACT_API, MAGICLOADER_WORLDSPACE_PLUGIN_POLICY, PLUGIN_MANIFEST_API,
    PLUGIN_PRESERVATION_API, PLUGIN_SEMANTIC_REWRITE_API, UNDELETE_DISABLE_POLICY_API,
    WORLDSPACE_SEMANTIC_GATE_API, WorldspaceLaneEvaluation,
    evaluate_magicloader_worldspace_policy, evaluate_worldspace_lane_semantics,
    inspect_plugin_set, resolve_installed_master_records, verify_plugin_set_preserved,
    verify_plugin_set_with_rewritten_esp,
};
use crate::preflight::{PreflightRequest, analyze};
use crate::replacement::{
    ADDITIVE_STATIC_MESH_ADAPTER, ARMOR_REPLACEMENT_ADAPTER, COMPOSITE_PACKAGE_REBASE_ADAPTER,
    HETEROGENEOUS_REPLACEMENT_ADAPTER, MIXED_ARMOR_REPLACEMENT_ADAPTER, ProvenHeterogeneousAsset,
    TEXTURE_REPLACEMENT_ADAPTER, canonical_additive_static_mesh_path, canonical_package_path,
    classify_heterogeneous_asset, composite_effective_package_path, composite_roundtrip_requests,
    extract_composite_packages_exact, extract_current_packages_batched,
    extract_source_composite_packages_exact, extract_source_composite_packages_with_fallback,
    extract_source_packages_exact,
    extract_source_static_mesh_packages, find_extracted_additive_static_mesh,
    inspect_additive_static_mesh_staged, inspect_composite_package_staged,
    inspect_composite_package_staged_with_dependencies_multi,
    inspect_heterogeneous_replacement_staged, inspect_mixed_armor_staged, inspect_staged,
    inspect_texture_staged, recover_composite_package_identities, stage_input,
    validate_texture_replacement_pair, verify_donor_rebinds_consumed,
};
use crate::retoc::{PackageEntry, PackageStoreEntry, RetocTool};
use crate::tes4::{
    DELETED_RECORD, Record, SyncMapEntry, infer_self_slot, merge_inventory_addition,
    package_to_game_path, read_plugin, read_sync_map, record_editor_id,
    rewrite_plugin_records_with_flag_updates, sorted_form_ids,
    supports_additive_inventory_record, validate_inventory_addition,
};
use crate::uasset::{
    BodySetupRepair, CompositePackageAssetKind, CompositePackageImportRepair, MaterialImportRepair,
    OptionalBlueprintDependencySuppression, PayloadEquivalenceReport, SkeletalCompatibilityProfile,
    TextureAssetDiagnostic, classify_composite_package_asset,
    derive_skeletal_compatibility_profile, inspect_static_mesh_asset, inspect_texture_asset,
    repair_composite_skeletal_mesh_imports, repair_current_template_imports,
    repair_legacy_body_setups, repair_single_external_import, repair_skeletal_mesh_imports,
    repair_static_mesh_imports, suppress_optional_blueprint_dependency,
    unresolved_package_store_dependencies, verify_preserved_export_payloads,
    verify_rebased_asset_metadata, verify_rebased_payloads,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
    exact_extraction: ExactExtractionReport,
    dependency_preservation: DependencyPreservationReport,
    package_migrations: Vec<CompositePackageMigration>,
    optional_dependency_suppressions: Vec<OptionalBlueprintDependencySuppression>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncMapResolution {
    key: String,
    local_form_id: String,
    editor_id: Option<String>,
    declared_object_path: String,
    rebuilt_package_path: String,
    rebuilt_inventory_path: String,
    resolution: String,
    directory_alias_allowed: bool,
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
    source_directory: PathBuf,
    utoc: PathBuf,
    ucas: PathBuf,
    pak: PathBuf,
    packages: Vec<String>,
    package_store: Vec<PackageStoreEntry>,
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

fn has_direct_container_directory(root: &Path) -> bool {
    // Containers may sit in a direct child folder of Content\Paks or one
    // level deeper (witness: ~mods/TorchWeapons, Mods/SuperSledgePak).
    let paks = root.join(r"Content\Paks");
    paks.is_dir()
        && WalkDir::new(paks)
            .min_depth(2)
            .max_depth(3)
            .into_iter()
            .filter_map(Result::ok)
            .any(|entry| {
                entry.file_type().is_file()
                    && entry
                        .path()
                        .extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|value| value.eq_ignore_ascii_case("utoc"))
            })
}

/// Physical container folders of an additive mod: every distinct parent
/// directory of a UTOC below Content\Paks. Witness shapes: one direct child
/// folder (the original contract), one folder nested a single level deeper
/// ("torch weapons", Nexus 3999: ~mods/TorchWeapons; "Super Sledge
/// Standalone", Nexus 977: Mods/SuperSledgePak), and containers split across
/// direct child folders ("Berserk Armor", Nexus 4979 and "Cosmic's Black
/// Cape", Nexus 4840: LogicMods plus ~mods). The publisher preserves each
/// folder exactly; anything deeper than two levels below Content\Paks stays
/// fail-closed.
fn find_container_directories(mod_root: &Path) -> Result<Vec<PathBuf>> {
    let paks = mod_root.join(r"Content\Paks");
    let mut utocs = WalkDir::new(&paks)
        .min_depth(1)
        .max_depth(8)
        .follow_links(false)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("utoc"))
        })
        .map(|entry| entry.into_path())
        .collect::<Vec<_>>();
    utocs.sort();
    if utocs.is_empty() {
        bail!("mod contains no UTOC containers below Content\\Paks");
    }
    let mut parents = utocs
        .iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect::<Vec<_>>();
    parents.sort();
    parents.dedup();
    for parent in &parents {
        let relative = parent.strip_prefix(&paks)?;
        let depth = relative.components().count();
        if depth == 0 || depth > 2 {
            bail!(
                "native additive container folders must sit one or two levels below Content\\Paks: {}",
                relative.display()
            );
        }
    }
    Ok(parents)
}

fn find_mod_root(extracted: &Path) -> Result<PathBuf> {
    let roots = WalkDir::new(extracted)
        .max_depth(8)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_dir())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| {
            path.join(r"Content\Dev\ObvData\Data").is_dir() && has_direct_container_directory(path)
        })
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        bail!(
            "expected exactly one extracted mod root containing Content\\Dev and one direct Content\\Paks container folder; found {}",
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
    let expected_ids = packages
        .iter()
        .map(|package| package.package_id)
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
    let mut container_members = BTreeMap::<PathBuf, (Option<PathBuf>, bool)>::new();
    for path in WalkDir::new(&mods)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
    {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "ucas" | "utoc") {
            continue;
        }
        let stem_key = PathBuf::from(
            path.with_extension("")
                .to_string_lossy()
                .to_ascii_lowercase(),
        );
        let row = container_members.entry(stem_key).or_default();
        match extension.as_str() {
            "utoc" => row.0 = Some(path),
            _ => row.1 = true,
        }
    }
    let incomplete = container_members
        .values()
        .filter_map(|(utoc, ucas_present)| match utoc {
            Some(utoc) if !ucas_present => {
                Some(format!("{} (missing: ucas)", utoc.display()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if !incomplete.is_empty() {
        bail!(
            "the game ~mods directory contains {} incomplete IoStore container group(s) whose installed package inventory cannot be read. Remove the leftover file(s) or restore the missing member(s), then run the update again:\n{}",
            incomplete.len(),
            incomplete.join("\n")
        );
    }
    let mut utocs = container_members
        .into_values()
        .filter_map(|(utoc, _)| utoc)
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
            if expected_ids.contains(&package.package_id) {
                collisions.push(format!("{} in {}", package.path, utoc.display()));
            }
        }
    }
    if !collisions.is_empty() {
        bail!(
            "a replacement of the same runtime package ID is installed in the game ~mods directory. Remove it before updating so current stock assets can be used as clean donors:\n{}",
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

#[allow(clippy::too_many_arguments)]
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

// SyncMap authors do not agree on directory layout, so resolve by exact path first and
// then by a unique object leaf tied to a real plugin-owned FormID. Multiple distinct
// FormIDs may intentionally share one Unreal object/package; the FormID is the unique
// identity at this boundary.
fn resolve_sync_map_entries(
    entries: &[SyncMapEntry],
    owned_records: &[&Record],
    package_paths: &[String],
) -> Result<Vec<SyncMapResolution>> {
    let packages = package_paths
        .iter()
        .map(|source| Ok((source, package_to_game_path(source)?)))
        .collect::<Result<Vec<_>>>()?;
    let mut resolutions = Vec::new();
    let mut resolved_form_ids = HashSet::new();
    for entry in entries {
        let local_id = u32::from_str_radix(entry.local_form_id.trim_start_matches("0x"), 16)?;
        if !resolved_form_ids.insert(local_id) {
            bail!("multiple SyncMap entries reference plugin-owned ESP FormID 0x{local_id:06X}");
        }
        let mut matching_records = owned_records
            .iter()
            .copied()
            .filter(|record| record.form_id & 0x00FF_FFFF == local_id);
        let record = matching_records.next().with_context(|| {
            format!(
                "SyncMap key {} has no matching plugin-owned ESP FormID",
                entry.key
            )
        })?;
        if matching_records.next().is_some() {
            bail!(
                "SyncMap key {} is ambiguous across multiple plugin-owned ESP records with local FormID 0x{local_id:06X}",
                entry.key
            );
        }
        let exact = packages
            .iter()
            .filter(|(_, game_path)| game_path.eq_ignore_ascii_case(&entry.package_path))
            .collect::<Vec<_>>();
        let (source_path, game_path, resolution, directory_alias_allowed) = match exact.as_slice() {
            [(source_path, game_path)] => (*source_path, game_path, "exact-package-path", false),
            [] => {
                let object_name = entry
                    .object_path
                    .rsplit('.')
                    .next()
                    .and_then(|value| value.rsplit('/').next())
                    .filter(|value| !value.is_empty())
                    .with_context(|| format!("SyncMap key {} has no object name", entry.key))?;
                let candidates = packages
                    .iter()
                    .filter(|(_, game_path)| {
                        game_path
                            .rsplit('/')
                            .next()
                            .is_some_and(|leaf| leaf.eq_ignore_ascii_case(object_name))
                    })
                    .collect::<Vec<_>>();
                match candidates.as_slice() {
                    [(source_path, game_path)] => {
                        (*source_path, game_path, "unique-object-leaf", true)
                    }
                    [] => bail!(
                        "SyncMap object {} has no rebuilt package with the same object leaf",
                        entry.object_path
                    ),
                    _ => bail!(
                        "SyncMap object {} is ambiguous across {} rebuilt package paths",
                        entry.object_path,
                        candidates.len()
                    ),
                }
            }
            _ => bail!(
                "SyncMap path {} is ambiguous across {} rebuilt package paths",
                entry.package_path,
                exact.len()
            ),
        };
        resolutions.push(SyncMapResolution {
            key: entry.key.clone(),
            local_form_id: entry.local_form_id.clone(),
            editor_id: record_editor_id(record),
            declared_object_path: entry.object_path.clone(),
            rebuilt_package_path: game_path.clone(),
            rebuilt_inventory_path: (*source_path).clone(),
            resolution: resolution.to_owned(),
            directory_alias_allowed,
        });
    }
    Ok(resolutions)
}
/// Structural fail-closed parse of a MagicLoader JSON sidecar. MagicLoader itself accepts
/// trailing commas, so they are normalized (outside string literals only) before the strict
/// parse; the sidecar bytes shipped to the candidate are never modified.
pub(crate) fn validate_magic_loader_sidecar(payload: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(payload).context("sidecar is not UTF-8")?;
    let mut normalized = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    let chars = text.chars().collect::<Vec<_>>();
    for (index, character) in chars.iter().copied().enumerate() {
        if in_string {
            normalized.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
            normalized.push(character);
            continue;
        }
        if character == ',' {
            let next_meaningful = chars[index + 1..]
                .iter()
                .copied()
                .find(|value| !value.is_whitespace());
            if matches!(next_meaningful, Some('}') | Some(']')) {
                continue;
            }
        }
        normalized.push(character);
    }
    let value: serde_json::Value =
        serde_json::from_str(&normalized).context("sidecar is not structurally valid JSON")?;
    let object = value
        .as_object()
        .context("sidecar root is not a JSON object")?;
    if object.is_empty() {
        bail!("sidecar declares no configuration entries");
    }
    Ok(())
}

/// SyncMap resolution across the layered package domain: bundled mod packages first
/// (exact path, then unique object leaf), then exact stock-game package paths. Stock
/// targets never use leaf aliasing; anything unresolved or ambiguous fails closed.
fn resolve_sync_map_entries_layered(
    entries: &[SyncMapEntry],
    owned_records: &[&Record],
    bundled_packages: &[String],
    stock_packages: &[PackageStoreEntry],
) -> Result<Vec<SyncMapResolution>> {
    let bundled = bundled_packages
        .iter()
        .map(|source| Ok((source, package_to_game_path(source)?)))
        .collect::<Result<Vec<_>>>()?;
    let mut stock_by_game_path = HashMap::<String, Vec<&PackageStoreEntry>>::new();
    for entry in stock_packages {
        if let Ok(game_path) = package_to_game_path(&entry.path) {
            stock_by_game_path
                .entry(game_path.to_ascii_lowercase())
                .or_default()
                .push(entry);
        }
    }
    let mut resolutions = Vec::new();
    let mut resolved_form_ids = HashSet::new();
    for entry in entries {
        let local_id = u32::from_str_radix(entry.local_form_id.trim_start_matches("0x"), 16)?;
        if !resolved_form_ids.insert(local_id) {
            bail!("multiple SyncMap entries reference plugin-owned ESP FormID 0x{local_id:06X}");
        }
        let mut matching_records = owned_records
            .iter()
            .copied()
            .filter(|record| record.form_id & 0x00FF_FFFF == local_id);
        let record = matching_records.next().with_context(|| {
            format!(
                "SyncMap key {} has no matching plugin-owned ESP FormID",
                entry.key
            )
        })?;
        if matching_records.next().is_some() {
            bail!(
                "SyncMap key {} is ambiguous across multiple plugin-owned ESP records with local FormID 0x{local_id:06X}",
                entry.key
            );
        }
        let exact_bundled = bundled
            .iter()
            .filter(|(_, game_path)| game_path.eq_ignore_ascii_case(&entry.package_path))
            .collect::<Vec<_>>();
        let (source_path, game_path, resolution, directory_alias_allowed) =
            match exact_bundled.as_slice() {
                [(source_path, game_path)] => (
                    (*source_path).clone(),
                    game_path.clone(),
                    "exact-package-path-bundled",
                    false,
                ),
                [] => {
                    let object_name = entry
                        .object_path
                        .rsplit('.')
                        .next()
                        .and_then(|value| value.rsplit('/').next())
                        .filter(|value| !value.is_empty())
                        .with_context(|| format!("SyncMap key {} has no object name", entry.key))?;
                    let leaf_bundled = bundled
                        .iter()
                        .filter(|(_, game_path)| {
                            game_path
                                .rsplit('/')
                                .next()
                                .is_some_and(|leaf| leaf.eq_ignore_ascii_case(object_name))
                        })
                        .collect::<Vec<_>>();
                    match leaf_bundled.as_slice() {
                        [(source_path, game_path)] => (
                            (*source_path).clone(),
                            game_path.clone(),
                            "unique-object-leaf-bundled",
                            true,
                        ),
                        [] => {
                            let stock = stock_by_game_path
                                .get(&entry.package_path.to_ascii_lowercase())
                                .map(Vec::as_slice)
                                .unwrap_or_default();
                            match stock {
                                [stock_entry] => (
                                    stock_entry.path.clone(),
                                    package_to_game_path(&stock_entry.path)?,
                                    "exact-package-path-stock",
                                    false,
                                ),
                                [] => bail!(
                                    "SyncMap object {} resolves in neither the bundled packages nor the current stock inventory",
                                    entry.object_path
                                ),
                                _ => bail!(
                                    "SyncMap path {} is ambiguous across multiple stock package paths",
                                    entry.package_path
                                ),
                            }
                        }
                        _ => bail!(
                            "SyncMap object {} is ambiguous across {} bundled package paths",
                            entry.object_path,
                            leaf_bundled.len()
                        ),
                    }
                }
                _ => bail!(
                    "SyncMap path {} is ambiguous across {} bundled package paths",
                    entry.package_path,
                    exact_bundled.len()
                ),
            };
        resolutions.push(SyncMapResolution {
            key: entry.key.clone(),
            local_form_id: entry.local_form_id.clone(),
            editor_id: record_editor_id(record),
            declared_object_path: entry.object_path.clone(),
            rebuilt_package_path: game_path,
            rebuilt_inventory_path: source_path,
            resolution: resolution.to_owned(),
            directory_alias_allowed,
        });
    }
    Ok(resolutions)
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
    if let Some(nested_adapter) = nested_logical_install_adapter(&request.adapter) {
        let nested_adapter = nested_adapter.to_owned();
        return run_logical_install_update(request, &nested_adapter, callback);
    }
    run_direct_update(request, callback)
}

fn run_direct_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    // The adapter comes from preflight. Refuse unknown names instead of guessing which conversion is close enough.
    match request.adapter.as_str() {
        "native-additive-syncmap-v1" => run_additive_update(request, callback),
        MAGICLOADER_WORLDSPACE_ADAPTER => run_magicloader_worldspace_update(request, callback),
        ARMOR_REPLACEMENT_ADAPTER => run_armor_replacement_update(request, callback),
        MIXED_ARMOR_REPLACEMENT_ADAPTER => run_mixed_armor_replacement_update(request, callback),
        TEXTURE_REPLACEMENT_ADAPTER => run_texture_replacement_update(request, callback),
        HETEROGENEOUS_REPLACEMENT_ADAPTER => {
            run_heterogeneous_replacement_update(request, callback)
        }
        COMPOSITE_PACKAGE_REBASE_ADAPTER => run_composite_package_update(request, callback),
        "native-additive-static-mesh-v1" | ADDITIVE_STATIC_MESH_ADAPTER => {
            run_additive_static_mesh_update(request, callback)
        }
        LEGACY_PAK_PASSTHROUGH_ADAPTER => run_legacy_pak_passthrough_update(request, callback),
        crate::plugin_only::PLUGIN_ONLY_ADAPTER => run_plugin_only_update(request, callback),
        adapter => bail!("preflight selected an unknown or empty update adapter: {adapter}"),
    }
}

/// Publishes a proven legacy pak-only payload as a byte-preserved candidate
/// with a canonical `~mods` install layout. The fail-closed probe is re-run at
/// update time; nothing is structurally rebuilt.
fn run_legacy_pak_passthrough_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    let adapter = LEGACY_PAK_PASSTHROUGH_ADAPTER;
    stage(callback, 1, "Hashing the source and validating the current game");
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

    stage(
        callback,
        2,
        "Re-proving the fail-closed legacy pak passthrough contract",
    );
    let summary = probe_legacy_pak_passthrough_input(&mod_input, &game.root)?;

    stage(
        callback,
        3,
        "Publishing byte-preserved paks into the ~mods install layout",
    );
    fs::create_dir_all(&output_directory)?;
    let mappings = publish_passthrough_paks(&mod_input, &summary, &output_directory)?;

    stage(
        callback,
        4,
        "Re-verifying published pak hashes against the probe evidence",
    );
    if mappings.len() != summary.pak_count {
        bail!(
            "published {} pak(s) but the probe proved {}",
            mappings.len(),
            summary.pak_count
        );
    }
    for pak in &summary.paks {
        let published = output_directory.join(pak.install_relative_path.replace('/', "\\"));
        if sha256_file(&published)? != pak.pak_sha256 {
            bail!(
                "published pak {} does not byte-match its verified source",
                pak.file_name
            );
        }
    }

    stage(callback, 5, "Writing the passthrough update report");
    let report_path = output_directory.join("legacy-pak-passthrough-update-report.json");
    let install_plan = summary
        .paks
        .iter()
        .map(|pak| {
            json!({
                "sourceRelativePath": pak.source_relative_path,
                "candidateRelativePath": pak.install_relative_path,
                "gameRelativeDestination": pak.install_relative_path,
                "pakSha256": pak.pak_sha256,
            })
        })
        .collect::<Vec<_>>();
    let report = json!({
        "schema": "obr-legacy-pak-passthrough-update-report",
        "version": 1,
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
            "mainPak": summary.current_game.pak_file_name,
            "mainPakIndexVersion": summary.current_game.pak_index_version,
            "currentWwiseMediaFileCount": summary.current_game.wwise_media_file_count,
        },
        "identity": {
            "pakCount": summary.pak_count,
            "entryCount": summary.entry_count,
            "contentPlanes": summary.content_planes,
            "matchedCurrentMediaCount": summary.matched_current_media_count,
        },
        "passthrough": serde_json::to_value(&summary)?,
        "installPlan": install_plan,
        "output": {
            "directory": output_directory,
            "archive": output_archive,
        },
        "verification": {
            "payloadBytePreserved": true,
            "structurallyRebuilt": false,
            "indexSha1Verified": true,
            "entryStoredPayloadSha1Verified": true,
            "zlibRoundtripVerified": true,
            "mountAndEntryPathShapeVerified": true,
            "currentGameMediaTargetsVerified": true,
            "productionRuntimeGateRequired": true,
            "note": "This candidate is a version-passthrough: the source pak bytes are preserved exactly and nothing is structurally rebuilt for the current game version. Container integrity, per-entry stored-payload hashes, zlib roundtrips, mount/path shape, the Wwise audio media plane, and presence of every media ID in the current game's shipped pak index are proven; in-game behavior is not. It is not called runtime verified until a shipping-game run proves the replaced audio plays correctly."
        },
        "disclosures": summary.disclosures,
    });
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;

    stage(callback, 6, "Creating portable passthrough candidate archive");
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
        "Byte-preserving passthrough complete; shipping-game test still required",
    );
    Ok(UpdateOutcome {
        adapter: adapter.to_owned(),
        output_directory,
        output_archive,
        report_path,
        package_count: summary.entry_count,
    })
}

/// Publishes a plugin-only mod as a canonical-layout runtime-test candidate.
/// The complete lane probe must re-prove every gate against the current game;
/// the ESP is byte-preserved unless the undelete-and-disable policy proved a
/// deletion-stub rewrite, and every sidecar byte is preserved.
fn run_plugin_only_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    use crate::plugin_only::{
        PLUGIN_ONLY_ADAPTER, PLUGIN_ONLY_INSTALLABLE_EXTENSIONS, PLUGIN_ONLY_LANE_API,
        evaluate_plugin_only_lane, stage_plugin_only_logical_view,
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
    let game_data = game
        .root
        .join(r"OblivionRemastered\Content\Dev\ObvData\Data");
    let game_esm = game_data.join("Oblivion.esm");

    stage(callback, 1, "Inspecting the plugin-only mod and target game");
    let work = tempfile::Builder::new()
        .prefix("obr-plugin-only-update-")
        .tempdir()?;
    let extract_root = work.path().join("archive");
    fs::create_dir_all(&extract_root)?;
    if mod_input.is_dir() {
        crate::archive::copy_tree(&mod_input, &extract_root)?;
    } else {
        crate::archive::extract_archive(&mod_input, &extract_root)?;
    }
    // Classify every file in the complete tree: installable payloads enter the
    // canonical mapping, documentation is preserved without installation, and
    // any other functional file fails the lane closed.
    let mut documentation = Vec::new();
    for entry in walkdir::WalkDir::new(&extract_root).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!("plugin-only input contains a filesystem link");
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&extract_root)?
            .to_string_lossy()
            .replace('\\', "/");
        let extension = entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if PLUGIN_ONLY_INSTALLABLE_EXTENSIONS
            .iter()
            .any(|value| extension.eq_ignore_ascii_case(value))
        {
            continue;
        }
        let file_name = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let documentation_like = matches!(
            extension.as_str(),
            "txt" | "md" | "rtf" | "pdf" | "png" | "jpg" | "jpeg" | "gif" | "webp"
        ) || matches!(
            file_name.as_str(),
            "readme" | "license" | "licence" | "notice" | "changelog"
        );
        if !documentation_like {
            bail!("plugin-only lane refuses an unrecognized functional file: {relative}");
        }
        documentation.push(relative);
    }
    documentation.sort();

    stage(
        callback,
        2,
        "Proving Data-plane layout, masters, and current-master semantics",
    );
    let lane = evaluate_plugin_only_lane(&mod_input, Some(&game_data));
    if lane.status != "proven" {
        bail!(
            "the plugin-only lane is blocked: {}",
            lane.blockers.join(", ")
        );
    }
    let layout = lane
        .layout
        .clone()
        .context("the proven plugin-only lane lost its layout")?;
    let esp_logical = lane
        .esp_logical_path
        .clone()
        .context("the proven plugin-only lane lost its ESP path")?;
    let (_staged, logical_root, publish_layout) = stage_plugin_only_logical_view(&mod_input)?;
    if publish_layout != layout {
        bail!("the publication layout no longer matches the proven lane layout");
    }
    let source_esp_path = logical_root.join(&esp_logical);
    let source_esp_bytes = fs::read(&source_esp_path)?;
    let source_esp_hash = sha256_file(&source_esp_path)?;
    let plugin = crate::tes4::read_plugin_bytes(&source_esp_bytes, &esp_logical)?;
    let has_overrides = plugin
        .records
        .iter()
        .any(|record| ((record.form_id >> 24) as usize) < plugin.masters.len());
    let mut plugin_replacements: HashMap<u32, Record> = HashMap::new();
    let mut flag_update_form_ids: HashSet<u32> = HashSet::new();
    let mut worldspace_evaluation: Option<WorldspaceLaneEvaluation> = None;
    if has_overrides {
        let evaluation = evaluate_worldspace_lane_semantics(
            &plugin,
            &source_esp_bytes,
            &esp_logical,
            &game_data,
        )?;
        if evaluation.semantic_gate.status != "proven" {
            bail!(
                "the current-master semantic gate is blocked: {}",
                evaluation.semantic_gate.blockers.join(", ")
            );
        }
        match evaluation.deleted_override_policy.status.as_str() {
            "not-applicable" | "provable" => {}
            _ => bail!(
                "the undelete-and-disable deletion policy is blocked: {}",
                evaluation.deleted_override_policy.blockers.join(", ")
            ),
        }
        let policy = &evaluation.deleted_override_policy;
        if policy.status == "provable"
            && (policy.transformable_count != policy.deletion_stub_count
                || evaluation.deletion_replacements.len() != policy.deletion_stub_count)
        {
            bail!(
                "undelete-and-disable count invariant failed: {} stub(s), {} transformable, {} replacement(s)",
                policy.deletion_stub_count,
                policy.transformable_count,
                evaluation.deletion_replacements.len()
            );
        }
        flag_update_form_ids = evaluation.deletion_replacements.keys().copied().collect();
        plugin_replacements = evaluation.deletion_replacements.clone();
        worldspace_evaluation = Some(evaluation);
    } else {
        resolve_installed_master_records(&plugin, &game_data, &[])?;
    }
    // A SyncMap sidecar makes the TesSyncMapInjector runtime (under UE4SS) a
    // hard requirement for the candidate to function.
    if lane.sync_map_entry_count > 0 {
        let dependency_candidates =
            scan_dependencies(&request.dependency_inputs, Some(&mod_input));
        let installed_dependencies = installed_state(&game.root);
        let ue4ss_available = installed_dependencies.ue4ss.installed
            || dependency_candidates
                .iter()
                .any(|candidate| candidate.kinds.contains(&DependencyKind::UE4SS));
        let injector_available = installed_dependencies.tes_sync_map_injector.installed
            || dependency_candidates.iter().any(|candidate| {
                candidate
                    .kinds
                    .contains(&DependencyKind::TesSyncMapInjector)
            });
        if !ue4ss_available || !injector_available {
            bail!(
                "SyncMap mod requires UE4SS and TesSyncMapInjector. Place their archives beside the mod or attach them in the app."
            );
        }
    }

    stage(callback, 3, "Publishing the canonical runtime-test candidate");
    fs::create_dir_all(&output_directory)?;
    let candidate_root = output_directory.join("OblivionRemastered");
    crate::archive::copy_tree(&logical_root, &candidate_root)?;
    let candidate_esp = candidate_root.join(&esp_logical);
    if !plugin_replacements.is_empty() {
        let rewritten = rewrite_plugin_records_with_flag_updates(
            &source_esp_bytes,
            &plugin_replacements,
            &flag_update_form_ids,
            &esp_logical,
        )?;
        // Byte-roundtrip proof: splicing the original deletion stubs back must
        // reproduce the source plugin exactly.
        let originals = plugin
            .records
            .iter()
            .filter(|record| plugin_replacements.contains_key(&record.form_id))
            .map(|record| (record.form_id, record.clone()))
            .collect::<HashMap<_, _>>();
        let restored = rewrite_plugin_records_with_flag_updates(
            &rewritten,
            &originals,
            &flag_update_form_ids,
            &esp_logical,
        )?;
        if restored != source_esp_bytes {
            bail!(
                "undelete-and-disable byte-roundtrip proof failed; the rewrite touched bytes outside the transformed records"
            );
        }
        fs::write(&candidate_esp, rewritten)?;
    }
    let passthrough_root = output_directory.join("unmapped-passthrough");
    for relative in &documentation {
        let source = extract_root.join(relative);
        let target = passthrough_root.join(relative);
        fs::create_dir_all(target.parent().context("passthrough file has no parent")?)?;
        copy_file(&source, &target)?;
    }

    stage(callback, 4, "Verifying the published candidate");
    if plugin_replacements.is_empty() {
        verify_plugin_set_preserved(&logical_root, &candidate_root)?;
    } else {
        verify_plugin_set_with_rewritten_esp(&logical_root, &candidate_root, &esp_logical)?;
        let candidate_bytes = fs::read(&candidate_esp)?;
        let candidate_plugin = crate::tes4::read_plugin_bytes(&candidate_bytes, &esp_logical)?;
        let final_evaluation = evaluate_worldspace_lane_semantics(
            &candidate_plugin,
            &candidate_bytes,
            &esp_logical,
            &game_data,
        )?;
        if final_evaluation.semantic_gate.status != "proven" {
            bail!(
                "the rewritten candidate fails the current-master semantic gate: {}",
                final_evaluation.semantic_gate.blockers.join(", ")
            );
        }
        if final_evaluation.deleted_override_policy.deletion_stub_count != 0 {
            bail!(
                "the rewritten candidate still carries {} deleted master override(s)",
                final_evaluation.deleted_override_policy.deletion_stub_count
            );
        }
    }
    let candidate_esp_hash = sha256_file(&candidate_esp)?;

    let mut fix_apis = vec![PLUGIN_MANIFEST_API, PLUGIN_ONLY_LANE_API];
    if plugin_replacements.is_empty() {
        fix_apis.push(PLUGIN_PRESERVATION_API);
    } else {
        fix_apis.push(UNDELETE_DISABLE_POLICY_API);
    }
    if has_overrides {
        fix_apis.push(WORLDSPACE_SEMANTIC_GATE_API);
    }
    fix_apis.sort_unstable();
    fix_apis.dedup();
    let report_path = output_directory.join("plugin-only-update-report.json");
    let mut report = json!({
        "schema": "obr-plugin-only-update-report",
        "version": 1,
        "adapter": PLUGIN_ONLY_ADAPTER,
        "implementation": "native-rust",
        "fixApis": fix_apis,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "reportSnapshot": "candidate-publication",
        "status": "candidate_ready_for_runtime_test",
        "structurallyVerified": true,
        "runtimeVerified": false,
        "source": {
            "inputType": input_type,
            "inputPath": mod_input,
            "inputSha256": input_hash,
            "esp": esp_logical,
            "espSha256": source_esp_hash,
        },
        "target": {
            "gameRoot": game.root,
            "esm": game_esm,
            "esmBytes": fs::metadata(&game_esm)?.len(),
            "esmSha256": sha256_file(&game_esm)?,
        },
        "identity": {
            "esmEdited": false,
            "espBytePreserved": plugin_replacements.is_empty(),
            "espUndeleteDisableRewrite": !plugin_replacements.is_empty(),
            "espUndeleteDisableCount": plugin_replacements.len(),
            "espSourceSha256": source_esp_hash,
            "espCandidateSha256": candidate_esp_hash,
            "mastersPreserved": true,
            "masters": plugin.masters,
            "declaredRecordCount": plugin.declared_record_count,
            "nextObjectId": format!("0x{:08X}", plugin.next_object_id),
        },
        "installPlan": {
            "scheme": layout.scheme,
            "wrapper": layout.wrapper,
            "mappings": layout.mappings,
            "unmappedDocumentation": documentation,
            "documentationPolicy": "Documentation files are preserved under unmapped-passthrough and are never installed into the game tree.",
        },
        "laneEvaluation": lane,
        "output": {
            "directory": output_directory,
            "archive": output_archive,
            "archiveContainsReportSnapshot": "candidate-publication",
        },
        "verification": {
            "espReparsed": true,
            "completePluginSetPreserved": true,
            "sidecarBytesPreserved": true,
            "productionRuntimeGateRequired": true,
            "note": "SyncMap package targets and the MagicLoader runtime are disclosed runtime requirements; this candidate is not called repaired until an in-game production run proves the content and behavior.",
        },
    });
    if let Some(evaluation) = worldspace_evaluation.as_ref() {
        report["identity"]["worldspaceSemanticGate"] =
            serde_json::to_value(&evaluation.semantic_gate)?;
        report["identity"]["deletedOverridePolicy"] =
            serde_json::to_value(&evaluation.deleted_override_policy)?;
    }
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;

    stage(callback, 5, "Creating portable candidate archive");
    let mut zip_paths = vec![candidate_root.clone(), report_path.clone()];
    if passthrough_root.is_dir() {
        zip_paths.push(passthrough_root.clone());
    }
    create_zip_from_paths(&output_archive, &output_directory, &zip_paths)?;
    if !output_archive.is_file() {
        bail!(
            "output archive was not created: {}",
            output_archive.display()
        );
    }
    stage(
        callback,
        6,
        "Plugin-only candidate published; run the in-game production test",
    );
    Ok(UpdateOutcome {
        adapter: PLUGIN_ONLY_ADAPTER.to_owned(),
        output_directory,
        output_archive,
        report_path,
        package_count: 0,
    })
}

fn nested_adapter_owns_logical_destinations(
    plan: &InstallPlan,
    nested_adapter: &str,
) -> Result<BTreeSet<PathBuf>> {
    if !matches!(
        nested_adapter,
        "native-additive-syncmap-v1"
            | ARMOR_REPLACEMENT_ADAPTER
            | MIXED_ARMOR_REPLACEMENT_ADAPTER
            | TEXTURE_REPLACEMENT_ADAPTER
            | ADDITIVE_STATIC_MESH_ADAPTER
            | HETEROGENEOUS_REPLACEMENT_ADAPTER
            | COMPOSITE_PACKAGE_REBASE_ADAPTER
    ) {
        bail!("logical publication received an unsupported nested adapter: {nested_adapter}");
    }
    let owned = plan
        .mappings
        .iter()
        .filter(|mapping| {
            let path = mapping
                .logical_destination
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            let extension = mapping
                .logical_destination
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            path.starts_with("content/paks/~mods/")
                && matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "pak" | "ucas" | "utoc"
                )
        })
        .map(|mapping| mapping.logical_destination.clone())
        .collect::<BTreeSet<_>>();
    if owned.is_empty() {
        bail!("nested adapter has no mapped IoStore payload in the logical install plan");
    }
    Ok(owned)
}

fn nested_logical_candidate_root(
    nested_adapter: &str,
    logical_source_root: &Path,
    outcome: &UpdateOutcome,
) -> Result<PathBuf> {
    let candidate = if nested_adapter == "native-additive-syncmap-v1" {
        outcome.output_directory.join(
            logical_source_root
                .file_name()
                .context("logical source root has no directory name")?,
        )
    } else {
        outcome.output_directory.clone()
    };
    if !candidate.is_dir() {
        bail!(
            "nested adapter did not produce its expected logical candidate root: {}",
            candidate.display()
        );
    }
    Ok(candidate)
}

fn hash_selected_source(path: &Path) -> Result<String> {
    if path.is_file() {
        sha256_file(path)
    } else {
        sha256_directory(path)
    }
}

fn rollback_new_publication(moves: &[(&Path, &Path)]) -> Vec<String> {
    let mut errors = Vec::new();
    for (published, staged) in moves {
        if published.exists()
            && let Err(error) = fs::rename(published, staged)
        {
            errors.push(format!(
                "moving {} back to temporary staging: {error}",
                published.display()
            ));
        }
    }
    errors
}

fn run_logical_install_update(
    mut request: UpdateRequest,
    nested_adapter: &str,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    let outer_adapter = logical_install_adapter_id(nested_adapter)?;
    let game = validate_game_install(&request.game_root, "logical install publication");
    if !game.valid {
        bail!(
            "game folder is incomplete. Missing: {}",
            game.missing.join(", ")
        );
    }
    request.game_root = game.root;
    let mod_input = fs::canonicalize(&request.mod_input)
        .with_context(|| format!("mod input not found: {}", request.mod_input.display()))?;
    let output_parent = fs::canonicalize(&request.output_parent).with_context(|| {
        format!(
            "output parent does not exist: {}",
            request.output_parent.display()
        )
    })?;
    if !output_parent.is_dir() {
        bail!(
            "output parent is not a directory: {}",
            output_parent.display()
        );
    }
    if mod_input.is_dir() && output_parent.starts_with(&mod_input) {
        bail!("logical publication output cannot be inside the immutable source directory");
    }
    let original_source_sha256 = hash_selected_source(&mod_input)?;
    let output_directory = output_parent.join(format!(
        "{}-current-candidate-{}",
        safe_leaf(&mod_input),
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    let output_archive = portable_archive_path(&output_directory)?;
    let output_name = output_directory
        .file_name()
        .context("logical candidate has no directory name")?
        .to_string_lossy();
    let report_path =
        output_parent.join(format!("{output_name}-logical-install-update-report.json"));
    if output_directory.exists() || output_archive.exists() || report_path.exists() {
        bail!(
            "timestamped logical publication output already exists; wait one second and try again"
        );
    }

    callback(1, 13, "Snapshotting the complete physical archive layout");
    let work = tempfile::Builder::new()
        .prefix(".obr-logical-publication-")
        .tempdir_in(&output_parent)?;
    let physical_root = work.path().join("physical-source");
    stage_input(&mod_input, &physical_root)?;
    let resolved = resolve_staged_install_view(&physical_root)?;
    if !supports_logical_install_publication(&resolved.plan) {
        bail!("logical publication supports only choice-free canonical or manual-structural plans");
    }
    let owned = nested_adapter_owns_logical_destinations(&resolved.plan, nested_adapter)?;
    let context = build_logical_update_context(
        &physical_root,
        &resolved,
        original_source_sha256.clone(),
        nested_adapter,
        &owned,
    )?;

    callback(
        2,
        13,
        "Running the proven adapter against the immutable logical view",
    );
    let nested_output_parent = work.path().join("nested-output");
    fs::create_dir_all(&nested_output_parent)?;
    let nested_request = UpdateRequest {
        adapter: nested_adapter.to_owned(),
        mod_input: resolved.view.root().to_path_buf(),
        game_root: request.game_root.clone(),
        output_parent: nested_output_parent,
        dependency_inputs: request.dependency_inputs.clone(),
        installed_collision_exclusions: request.installed_collision_exclusions.clone(),
        persist_settings: false,
    };
    let mut nested_progress = |step: usize, total: usize, message: &str| {
        let total = total.max(1);
        let nested_step = 2 + step.min(total).saturating_mul(5) / total;
        callback(nested_step, 13, message)
    };
    let (nested_outcome, deferred_runtime_dependencies) =
        if nested_adapter == "native-additive-syncmap-v1" {
            run_additive_update_with_dependency_policy(nested_request, &mut nested_progress, false)?
        } else {
            (
                run_direct_update(nested_request, &mut nested_progress)?,
                Vec::new(),
            )
        };
    if nested_outcome.adapter != nested_adapter {
        bail!(
            "nested adapter identity changed from {nested_adapter} to {}",
            nested_outcome.adapter
        );
    }
    let nested_report_sha256 = sha256_file(&nested_outcome.report_path)?;
    let logical_candidate_root =
        nested_logical_candidate_root(nested_adapter, resolved.view.root(), &nested_outcome)?;
    let excluded_logical_paths = nested_outcome
        .report_path
        .strip_prefix(&logical_candidate_root)
        .ok()
        .map(Path::to_path_buf)
        .into_iter()
        .collect::<Vec<_>>();

    callback(
        8,
        13,
        "Reconstructing the original physical layout from approved mappings",
    );
    let staged_candidate = work.path().join("physical-candidate");
    let publication = reconstruct_logical_update_candidate(
        &context,
        &physical_root,
        &logical_candidate_root,
        &excluded_logical_paths,
        &staged_candidate,
    )?;

    callback(
        9,
        13,
        "Running fresh preflight against the reconstructed candidate",
    );
    let fresh_preflight = analyze(&PreflightRequest {
        mod_input: staged_candidate.clone(),
        game_root: Some(request.game_root.clone()),
        output_parent: Some(output_parent.clone()),
        connected_tools: request.dependency_inputs.clone(),
    });
    if !fresh_preflight.can_update
        || fresh_preflight.selected_adapter.as_deref() != Some(outer_adapter.as_str())
        || fresh_preflight.install_plan.as_ref() != Some(&context.install_plan)
        || !fresh_preflight.disposition.blocker_ids.is_empty()
    {
        bail!(
            "fresh preflight did not reproduce the approved logical publication plan: status={}, adapter={:?}, blockers={}",
            fresh_preflight.status,
            fresh_preflight.selected_adapter,
            fresh_preflight.disposition.blocker_ids.join(", ")
        );
    }
    if hash_selected_source(&mod_input)? != original_source_sha256 {
        bail!("selected source changed before logical candidate publication");
    }

    callback(
        10,
        13,
        "Creating and reopening the portable candidate before publication",
    );
    let staged_archive = work.path().join("verified-physical-candidate.zip");
    create_zip_from_paths(
        &staged_archive,
        &staged_candidate,
        std::slice::from_ref(&staged_candidate),
    )?;
    let archive_verification_root = work.path().join("archive-verification");
    stage_input(&staged_archive, &archive_verification_root)?;
    let archive_inventory_sha256 =
        verify_install_trees_match(&staged_candidate, &archive_verification_root)?;
    let archive_sha256 = sha256_file(&staged_archive)?;
    if hash_selected_source(&mod_input)? != original_source_sha256 {
        bail!("selected source changed during logical candidate publication");
    }

    let dependency_plan = if deferred_runtime_dependencies.is_empty() {
        None
    } else {
        Some(check_or_install(
            &request.game_root,
            deferred_runtime_dependencies.clone(),
            false,
        )?)
    };
    let mut report = json!({
        "schema": "obr-logical-install-update-report",
        "version": 2,
        "implementation": "native-rust",
        "adapter": outer_adapter,
        "nestedAdapter": nested_adapter,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "status": if dependency_plan.is_some() {
            "candidate-publication-runtime-dependencies-pending"
        } else {
            "candidate_ready_for_runtime_test"
        },
        "structurallyVerified": true,
        "runtimeVerified": false,
        "source": {
            "inputType": if mod_input.is_file() { "archive" } else { "directory" },
            "inputPath": mod_input,
            "inputSha256": original_source_sha256,
        },
        "logicalUpdateContext": context,
        "nestedAdapterResult": {
            "reportSha256": nested_report_sha256,
            "packageCount": nested_outcome.package_count,
            "runtimeDependencyInstallationDeferred": dependency_plan.is_some(),
        },
        "freshPreflight": {
            "schema": fresh_preflight.schema,
            "version": fresh_preflight.version,
            "status": fresh_preflight.status,
            "selectedAdapter": fresh_preflight.selected_adapter,
            "disposition": fresh_preflight.disposition,
        },
        "output": {
            "directory": output_directory,
            "archive": output_archive,
            "archiveSha256": archive_sha256,
            "archiveInventorySha256": archive_inventory_sha256,
            "reportOutsideCandidateInventory": report_path,
        },
        "verification": publication,
        "runtimeDependenciesAtPublication": dependency_plan,
        "sourceImmutableBeforePublication": true,
        "productionRuntimeGateRequired": true,
    });
    let staged_report = work.path().join("logical-install-update-report.json");
    fs::write(&staged_report, serde_json::to_vec_pretty(&report)?)?;

    if request.persist_settings {
        save_settings(&request.game_root, &output_parent)?;
        request.persist_settings = false;
    }
    callback(
        11,
        13,
        "Publishing the verified directory, archive, and report without clobbering",
    );
    fs::rename(&staged_candidate, &output_directory).with_context(|| {
        format!(
            "publishing verified physical candidate {}",
            output_directory.display()
        )
    })?;
    if let Err(error) = fs::rename(&staged_archive, &output_archive) {
        let rollback = rollback_new_publication(&[(&output_directory, &staged_candidate)]);
        bail!(
            "publishing verified candidate archive failed: {error}; rollback errors: {}",
            rollback.join("; ")
        );
    }
    if let Err(error) = fs::rename(&staged_report, &report_path) {
        let rollback = rollback_new_publication(&[
            (&output_archive, &staged_archive),
            (&output_directory, &staged_candidate),
        ]);
        bail!(
            "publishing logical update report failed: {error}; rollback errors: {}",
            rollback.join("; ")
        );
    }
    if sha256_file(&output_archive)? != archive_sha256
        || hash_selected_source(&mod_input)? != original_source_sha256
    {
        let rollback = rollback_new_publication(&[
            (&report_path, &staged_report),
            (&output_archive, &staged_archive),
            (&output_directory, &staged_candidate),
        ]);
        bail!(
            "published output or selected source changed across the atomic move; rollback errors: {}",
            rollback.join("; ")
        );
    }

    if !deferred_runtime_dependencies.is_empty() {
        callback(
            12,
            13,
            "Candidate published; installing validated runtime dependencies transactionally",
        );
        let dependency_report = check_or_install(
            &request.game_root,
            deferred_runtime_dependencies,
            true,
        )
        .with_context(|| {
            format!(
                "runtime dependency install failed; the verified mapped candidate remains at {}",
                output_archive.display()
            )
        })?;
        if !dependency_report.ready {
            bail!(
                "runtime dependencies were not ready after installation; the verified mapped candidate remains at {}",
                output_archive.display()
            );
        }
        report["generatedAt"] = json!(chrono::Utc::now().to_rfc3339());
        report["status"] = json!("candidate_ready_for_runtime_test");
        report["runtimeDependenciesAfterPublication"] = serde_json::to_value(&dependency_report)?;
        report["sourceImmutableAfterPublication"] =
            json!(hash_selected_source(&mod_input)? == original_source_sha256);
        fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
        if hash_selected_source(&mod_input)? != original_source_sha256 {
            bail!(
                "selected source changed after runtime dependency installation; the verified mapped candidate remains at {}",
                output_archive.display()
            );
        }
    } else {
        report["sourceImmutableAfterPublication"] = json!(true);
        fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    }

    callback(
        13,
        13,
        "Mapped candidate complete; shipping-game test still required",
    );
    Ok(UpdateOutcome {
        adapter: outer_adapter,
        output_directory,
        output_archive,
        report_path,
        package_count: nested_outcome.package_count,
    })
}

/// The guarded MagicLoader + multi-master worldspace ESP + SyncMap + additive IoStore lane.
pub const MAGICLOADER_WORLDSPACE_ADAPTER: &str = "native-magicloader-worldspace-syncmap-v1";

/// Which proven ESP + SyncMap + IoStore lane the shared additive engine body runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EspSyncLane {
    /// Inventory-additive ESP policy; master overrides merge current-master inventory rows.
    AdditiveSyncmap,
    /// MagicLoader sidecar + multi-master worldspace ESP; overrides pass the three-way
    /// current-master semantic gate and witness-shaped deletion stubs are undeleted-and-disabled.
    MagicLoaderWorldspace,
}

impl EspSyncLane {
    fn adapter_id(self) -> &'static str {
        match self {
            EspSyncLane::AdditiveSyncmap => "native-additive-syncmap-v1",
            EspSyncLane::MagicLoaderWorldspace => MAGICLOADER_WORLDSPACE_ADAPTER,
        }
    }
}

/// The layered-provider support proven for one additive update: the probe
/// evidence, the extra proven dependency entries for the composite
/// inspection, and the per-edge provider disclosures for the update report.
struct LayeredDependencySupport {
    probe: LayeredProbeWithSources,
    extra_target_dependencies: HashMap<u64, PackageEntry>,
    disclosures: Vec<String>,
    used_provider_ids: Vec<String>,
}

/// Attempts to satisfy the additive lane's stock-unresolved imports with the
/// layered IoStore resolver (`zen-layered-iostore-dependency-resolver-v1`).
///
/// Returns `Ok(None)` when the layered resolver cannot completely resolve the
/// reachable import graph; the guarded identity-recovery contract then stays
/// the only remaining avenue and fails truthfully on its own evidence. When
/// resolution is complete, every provider whose packages satisfy an import is
/// materialized into the bounded dependency view, and every satisfied edge is
/// disclosed with its chosen provider. A provider whose packages collide with
/// the selected mod's own package IDs or paths fails closed instead of being
/// mounted into the view.
fn resolve_layered_dependency_support(
    mod_input: &Path,
    dependency_inputs: &[PathBuf],
    game_root: &Path,
    dependency_view: &Path,
    source_package_store: &[PackageStoreEntry],
    retoc: &RetocTool,
) -> Result<Option<LayeredDependencySupport>> {
    let Ok(probe) =
        probe_layered_iostore_dependencies_with_sources(mod_input, dependency_inputs, game_root)
    else {
        return Ok(None);
    };
    if !probe.report.resolution_complete {
        return Ok(None);
    }
    let supporting_layer = |layer: PackageProviderLayer| {
        matches!(
            layer,
            PackageProviderLayer::ConnectedDependency
                | PackageProviderLayer::InstalledActiveMod
                | PackageProviderLayer::GameContainer
        )
    };
    let mut needed_providers = BTreeMap::new();
    let mut required_targets = Vec::new();
    for edge in &probe.report.dependency_edges {
        let Some(target) = edge.target.as_ref().filter(|_| edge.resolved) else {
            continue;
        };
        if !supporting_layer(target.layer) {
            continue;
        }
        needed_providers.insert(target.provider_id.clone(), target.layer);
        required_targets.push((edge, target));
    }
    if required_targets.is_empty() {
        return Ok(None);
    }
    let source_ids = source_package_store
        .iter()
        .map(|entry| entry.package_id)
        .collect::<HashSet<_>>();
    let source_paths = source_package_store
        .iter()
        .map(|entry| entry.path.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut provider_entries = HashMap::<u64, (String, PackageEntry)>::new();
    let mut used_provider_ids = Vec::new();
    for provider in &probe.providers {
        if !needed_providers.contains_key(&provider.provider_id) {
            continue;
        }
        used_provider_ids.push(provider.provider_id.clone());
        for container in &provider.containers {
            for source in [
                Some(&container.utoc),
                Some(&container.ucas),
                container.pak.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                let name = source
                    .file_name()
                    .context("layered provider container has no filename")?;
                let target = dependency_view.join(name);
                if target.exists() {
                    bail!(
                        "layered provider container filename collides with the dependency view: {}",
                        container.relative_utoc
                    );
                }
                copy_file(source, &target)?;
            }
            let (_, store) = retoc.package_store_entries_allow_empty(&container.utoc)?;
            for entry in store {
                if source_ids.contains(&entry.package_id)
                    || source_paths.contains(&entry.path.to_ascii_lowercase())
                {
                    bail!(
                        "layered provider {} shadows a selected-mod package ({}); the additive lane fails closed on selected-vs-provider identity collisions",
                        provider.provider_id,
                        entry.path
                    );
                }
                provider_entries
                    .entry(entry.package_id)
                    .or_insert_with(|| {
                        (
                            provider.provider_id.clone(),
                            PackageEntry {
                                package_id: entry.package_id,
                                path: entry.path.clone(),
                            },
                        )
                    });
            }
        }
    }
    let mut extra_target_dependencies = HashMap::new();
    let mut disclosures = Vec::new();
    for (edge, target) in required_targets {
        let (chosen_provider, entry) =
            provider_entries.get(&target.package_id).with_context(|| {
                format!(
                    "layered provider {} no longer exposes package {}",
                    target.provider_id, target.package_id
                )
            })?;
        if !chosen_provider.eq_ignore_ascii_case(&target.provider_id) {
            bail!(
                "layered provider precedence disagreement for package {}: report chose {}, materialized view chose {chosen_provider}",
                target.package_id,
                target.provider_id
            );
        }
        extra_target_dependencies
            .entry(target.package_id)
            .or_insert_with(|| entry.clone());
        if edge.source.layer == PackageProviderLayer::SelectedMod {
            disclosures.push(format!(
                "{} required by {} is satisfied by provider {} [{}] in {}",
                target.package_path,
                edge.source.package_path,
                target.provider_id,
                target.layer.label(),
                target.container,
            ));
        }
    }
    disclosures.sort();
    disclosures.dedup();
    used_provider_ids.sort();
    Ok(Some(LayeredDependencySupport {
        probe,
        extra_target_dependencies,
        disclosures,
        used_provider_ids,
    }))
}

fn run_additive_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    let (outcome, deferred_dependencies) =
        run_additive_update_with_dependency_policy(request, callback, true)?;
    if !deferred_dependencies.is_empty() {
        bail!("direct additive update unexpectedly deferred runtime dependencies");
    }
    Ok(outcome)
}

fn run_magicloader_worldspace_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
) -> Result<UpdateOutcome> {
    let (outcome, deferred_dependencies) = run_esp_sync_lane_update(
        request,
        callback,
        true,
        EspSyncLane::MagicLoaderWorldspace,
    )?;
    if !deferred_dependencies.is_empty() {
        bail!("direct MagicLoader worldspace update unexpectedly deferred runtime dependencies");
    }
    Ok(outcome)
}

fn run_additive_update_with_dependency_policy(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
    install_runtime_dependencies: bool,
) -> Result<(UpdateOutcome, Vec<crate::dependencies::DependencyCandidate>)> {
    run_esp_sync_lane_update(
        request,
        callback,
        install_runtime_dependencies,
        EspSyncLane::AdditiveSyncmap,
    )
}

fn run_esp_sync_lane_update(
    request: UpdateRequest,
    callback: &mut ProgressCallback<'_>,
    install_runtime_dependencies: bool,
    lane: EspSyncLane,
) -> Result<(UpdateOutcome, Vec<crate::dependencies::DependencyCandidate>)> {
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
    let stock_utoc = game_paks.join("OblivionRemastered-Windows.utoc");
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
    let mod_root = find_mod_root(&extract_root).context(
        "the native additive adapter requires one canonical complete logical mod root; physical wrappers must enter through the guarded logical-install publication adapter",
    )?;
    let mod_data = mod_root.join(r"Content\Dev\ObvData\Data");
    let mod_container_directories = find_container_directories(&mod_root)?;
    // Inventory the complete staged input so a sibling ESP/ESM/ESL cannot be
    // silently dropped, then evaluate the mutation policy relative to the exact
    // mod root whose Content directories the engine will consume.
    let staged_plugin_set = inspect_plugin_set(&extract_root)?;
    let plugin_set = inspect_plugin_set(&mod_root)?;
    if staged_plugin_set.plugin_count != plugin_set.plugin_count {
        bail!(
            "native additive scope found {} plugin file(s) outside the selected mod root",
            staged_plugin_set
                .plugin_count
                .saturating_sub(plugin_set.plugin_count)
        );
    }
    let lane_plugin_policy = match lane {
        EspSyncLane::AdditiveSyncmap => plugin_set.additive_syncmap_v1.clone(),
        EspSyncLane::MagicLoaderWorldspace => evaluate_magicloader_worldspace_policy(&plugin_set),
    };
    if !lane_plugin_policy.compatible {
        bail!(
            "{} plugin policy failed: {}",
            lane_plugin_policy.id,
            lane_plugin_policy.blockers.join(", ")
        );
    }
    let magic_loader_dir = mod_data.join("MagicLoader");
    let magic_loader_files = if lane == EspSyncLane::MagicLoaderWorldspace {
        let files = if magic_loader_dir.is_dir() {
            files_with_extension(&magic_loader_dir, "json")?
        } else {
            Vec::new()
        };
        if files.is_empty() {
            bail!("the MagicLoader worldspace lane requires at least one MagicLoader JSON sidecar");
        }
        for file in &files {
            let payload = fs::read(file)?;
            validate_magic_loader_sidecar(&payload).with_context(|| {
                format!(
                    "MagicLoader sidecar failed the structural parse: {}",
                    file.file_name().unwrap_or_default().to_string_lossy()
                )
            })?;
        }
        files
    } else {
        Vec::new()
    };
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
    let mut utoc_files = Vec::new();
    for directory in &mod_container_directories {
        utoc_files.extend(files_with_extension(directory, "utoc")?);
    }
    if utoc_files.is_empty() {
        bail!("mod contains no UTOC containers");
    }

    stage(
        callback,
        2,
        "Validating runtime tools, ESP, ESM override, and stable FormIDs",
    );
    let plugin = read_plugin(&esp_files[0])?;
    if plugin.masters.is_empty() || !plugin.masters[0].eq_ignore_ascii_case("Oblivion.esm") {
        bail!(
            "native additive scope requires Oblivion.esm first in a full-master chain; found: {}",
            plugin.masters.join(", ")
        );
    }
    let plugin_index = plugin.masters.len() as u8;
    let owned_index = infer_self_slot(plugin_index, &plugin.records)
        .self_index()
        .context("self-slot inference is ambiguous; the plugin's own record slot is unproven")?;
    let owned_records = plugin
        .records
        .iter()
        .filter(|record| (record.form_id >> 24) as u8 == owned_index)
        .collect::<Vec<_>>();
    let overrides = plugin
        .records
        .iter()
        .filter(|record| ((record.form_id >> 24) as u8) < plugin_index)
        .collect::<Vec<_>>();
    if plugin.records.iter().any(|record| {
        let index = (record.form_id >> 24) as u8;
        index > plugin_index && index != owned_index
    }) {
        bail!("ESP contains records beyond its master/plugin index range");
    }
    let owned_record_ids = owned_records
        .iter()
        .map(|record| record.form_id)
        .collect::<HashSet<_>>();
    let owned_ids = sorted_form_ids(owned_records.iter().map(|record| record.form_id));
    let target_record_ids = overrides
        .iter()
        .map(|record| record.form_id)
        .collect::<Vec<_>>();
    let esp_name = esp_files[0]
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("plugin.esp")
        .to_owned();
    let source_esp_bytes = fs::read(&esp_files[0])?;
    let mut override_results = Vec::new();
    let mut plugin_replacements = HashMap::new();
    let mut flag_update_form_ids = HashSet::new();
    let mut current_records = HashMap::new();
    let mut worldspace_evaluation: Option<WorldspaceLaneEvaluation> = None;
    // Overrides outside the proven inventory-merge contract (or carrying the
    // deleted flag) leave the additive lane's merge path and must instead be
    // proven byte-preserved by the same current-master semantic gate and
    // undelete-and-disable policy the MagicLoader worldspace lane uses.
    let semantic_gate_path = lane == EspSyncLane::MagicLoaderWorldspace
        || overrides.iter().any(|record| {
            !supports_additive_inventory_record(&record.kind)
                || record.flags & DELETED_RECORD != 0
        });
    match (lane, semantic_gate_path) {
        (EspSyncLane::AdditiveSyncmap, false) => {
            current_records =
                resolve_installed_master_records(&plugin, &game_data, &target_record_ids)?;
            let mut referenced_master_ids = Vec::new();
            for override_record in overrides {
                let current = current_records
                    .get(&override_record.form_id)
                    .with_context(|| {
                        format!(
                            "installed master chain has no override target 0x{:08X}",
                            override_record.form_id
                        )
                    })?;
                if current.record.kind != override_record.kind {
                    bail!(
                        "master override 0x{:08X} is {}/{} in staged/installed data",
                        override_record.form_id,
                        override_record.kind,
                        current.record.kind
                    );
                }
                let (merged, mut result) =
                    merge_inventory_addition(override_record, &current.record, plugin_index)?;
                if !result.preserved_current_master_entries.is_empty() {
                    plugin_replacements.insert(override_record.form_id, merged);
                }
                for addition in result
                    .added_inventory_entries
                    .iter_mut()
                    .chain(&mut result.preserved_current_master_entries)
                {
                    let item_form_id =
                        u32::from_str_radix(addition.item_form_id.trim_start_matches("0x"), 16)?;
                    addition.reference_validated = match addition.reference_scope.as_str() {
                        "plugin-owned" => owned_record_ids.contains(&item_form_id),
                        "current-master" => {
                            referenced_master_ids.push(item_form_id);
                            true
                        }
                        _ => false,
                    };
                    if !addition.reference_validated {
                        bail!(
                            "inventory override {} adds unresolved {} inventory reference {}",
                            result.form_id,
                            addition.reference_scope,
                            addition.item_form_id
                        );
                    }
                }
                override_results.push(result);
            }
            referenced_master_ids.sort_unstable();
            referenced_master_ids.dedup();
            resolve_installed_master_records(&plugin, &game_data, &referenced_master_ids)
                .context("resolving inventory references through the installed master chain")?;
        }
        _ => {
            let _ = &target_record_ids;
            let evaluation = evaluate_worldspace_lane_semantics(
                &plugin,
                &source_esp_bytes,
                &esp_name,
                &game_data,
            )?;
            if evaluation.semantic_gate.status != "proven" {
                bail!(
                    "the current-master semantic gate is blocked: {}",
                    evaluation.semantic_gate.blockers.join(", ")
                );
            }
            match evaluation.deleted_override_policy.status.as_str() {
                "not-applicable" | "provable" => {}
                _ => bail!(
                    "the undelete-and-disable deletion policy is blocked: {}",
                    evaluation.deleted_override_policy.blockers.join(", ")
                ),
            }
            let policy = &evaluation.deleted_override_policy;
            if policy.status == "provable"
                && (policy.transformable_count != policy.deletion_stub_count
                    || evaluation.deletion_replacements.len() != policy.deletion_stub_count)
            {
                bail!(
                    "undelete-and-disable count invariant failed: {} stub(s), {} transformable, {} replacement(s)",
                    policy.deletion_stub_count,
                    policy.transformable_count,
                    evaluation.deletion_replacements.len()
                );
            }
            flag_update_form_ids = evaluation.deletion_replacements.keys().copied().collect();
            plugin_replacements = evaluation.deletion_replacements.clone();
            worldspace_evaluation = Some(evaluation);
        }
    }
    let dependency_candidates = scan_dependencies(&request.dependency_inputs, Some(&mod_input));
    let installed_dependencies = installed_state(&game.root);
    let ue4ss_available = installed_dependencies.ue4ss.installed
        || dependency_candidates
            .iter()
            .any(|candidate| candidate.kinds.contains(&DependencyKind::UE4SS));
    let injector_available = installed_dependencies.tes_sync_map_injector.installed
        || dependency_candidates.iter().any(|candidate| {
            candidate
                .kinds
                .contains(&DependencyKind::TesSyncMapInjector)
        });
    if !ue4ss_available || !injector_available {
        bail!(
            "SyncMap mod requires UE4SS and TesSyncMapInjector. Place their archives beside the mod or attach them in the app."
        );
    }

    stage(callback, 3, "Checking that Unreal packages are additive");
    let mut container_inputs = Vec::new();
    let mut original_packages = Vec::new();
    let mut container_names = HashSet::new();
    for utoc in utoc_files {
        let raw_stem = utoc
            .file_stem()
            .and_then(|value| value.to_str())
            .context("UTOC has no filename")?
            .to_owned();
        // Publication name: an authored triple whose shared stem carries a
        // redundant inner ".pak" extension is published under the cleaned
        // stem so the container keeps its override suffix semantics.
        let name = crate::replacement::normalized_container_publish_stem(&raw_stem);
        if !container_names.insert(name.to_ascii_lowercase()) {
            bail!("duplicate additive container name across folders: {name}");
        }
        let directory = utoc
            .parent()
            .context("UTOC has no parent directory")?
            .to_path_buf();
        let ucas = directory.join(format!("{raw_stem}.ucas"));
        let pak = directory.join(format!("{raw_stem}.pak"));
        if !ucas.is_file() {
            bail!("container is missing UCAS: {raw_stem}");
        }
        if !pak.is_file() {
            bail!("container is missing PAK: {raw_stem}");
        }
        retoc.verify(&utoc, &format!("retoc verify source {raw_stem}"))?;
        let (_, package_store) = retoc.package_store_entries(&utoc)?;
        let packages = package_store
            .iter()
            .map(|package| package.path.clone())
            .collect::<Vec<_>>();
        original_packages.extend(packages.iter().cloned());
        container_inputs.push(ContainerInput {
            name,
            source_directory: directory,
            utoc,
            ucas,
            pak,
            packages,
            package_store,
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
    let source_package_store = container_inputs
        .iter()
        .flat_map(|container| container.package_store.iter().cloned())
        .collect::<Vec<_>>();
    let (_, current_game_store) = retoc.package_store_entries(&stock_utoc)?;
    let dependency_trace =
        diagnose_package_dependencies(&source_package_store, &current_game_store)?;
    let dependency_view = create_isolated_stock_view(&game.root)?;
    let target_probe = work.path().join("target-probe");
    fs::create_dir_all(&target_probe)?;
    let mut collisions = Vec::new();
    for package in &original_packages {
        let result = retoc.run(args([
            OsString::from("to-legacy"),
            dependency_view.path().as_os_str().to_owned(),
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
    for container in &container_inputs {
        for source in [&container.utoc, &container.ucas, &container.pak] {
            let target = dependency_view.path().join(source.file_name().unwrap());
            if target.exists() {
                bail!(
                    "mod container filename collides with the dependency view: {}",
                    source.display()
                );
            }
            copy_file(source, &target)?;
        }
    }
    let layered_dependency_support = if lane == EspSyncLane::AdditiveSyncmap
        && !dependency_trace.fully_resolved
    {
        stage(
            callback,
            3,
            "Resolving stock-unresolved imports across connected, installed, and game/DLC providers",
        );
        resolve_layered_dependency_support(
            &mod_input,
            &request.dependency_inputs,
            &game.root,
            dependency_view.path(),
            &source_package_store,
            &retoc,
        )?
    } else {
        None
    };
    let composite_inspection = inspect_composite_package_staged_with_dependencies_multi(
        &mod_container_directories,
        &game.root,
        &retoc,
        layered_dependency_support
            .as_ref()
            .map(|support| &support.extra_target_dependencies),
    )?;
    let identity_recovery = recover_composite_package_identities(
        &composite_inspection,
        &retoc,
        dependency_view.path(),
        &work.path().join("identity-recovery"),
    )?;
    let mut available_dependencies = composite_inspection.target_dependencies.clone();
    for package in &composite_inspection.packages {
        available_dependencies
            .entry(package.package_id)
            .or_insert_with(|| package.clone());
    }
    if let Some(recovery) = &identity_recovery {
        for alias in &recovery.aliases {
            available_dependencies
                .entry(alias.target_package.package_id)
                .or_insert_with(|| alias.target_package.clone());
        }
        for suppression in &recovery.suppressions {
            available_dependencies
                .entry(suppression.target_package.package_id)
                .or_insert_with(|| suppression.target_package.clone());
        }
    }
    let source_ids = composite_inspection
        .packages
        .iter()
        .map(|package| package.package_id)
        .collect::<HashSet<_>>();
    let current_composite_view = create_isolated_stock_view(&game.root)?;

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
    let candidate_container_directory = |source_directory: &Path| -> Result<PathBuf> {
        Ok(candidate_root.join(
            source_directory
                .strip_prefix(&mod_root)
                .context("container folder is outside the selected mod root")?,
        ))
    };
    let esp_relative = esp_files[0]
        .strip_prefix(&mod_root)
        .context("ESP is outside the selected mod root")?;
    let candidate_esp = candidate_root.join(esp_relative);
    if !plugin_replacements.is_empty() {
        let rewritten = rewrite_plugin_records_with_flag_updates(
            &source_esp_bytes,
            &plugin_replacements,
            &flag_update_form_ids,
            &esp_name,
        )?;
        if lane == EspSyncLane::MagicLoaderWorldspace {
            // Byte-roundtrip proof: splicing the original deletion stubs back into the
            // candidate must reproduce the source plugin exactly, so nothing outside the
            // N transformed records and their GRUP size headers changed.
            let originals = plugin
                .records
                .iter()
                .filter(|record| plugin_replacements.contains_key(&record.form_id))
                .map(|record| (record.form_id, record.clone()))
                .collect::<HashMap<_, _>>();
            let restored = rewrite_plugin_records_with_flag_updates(
                &rewritten,
                &originals,
                &flag_update_form_ids,
                &esp_name,
            )?;
            if restored != source_esp_bytes {
                bail!(
                    "undelete-and-disable byte-roundtrip proof failed; the rewrite touched bytes outside the transformed records"
                );
            }
        }
        fs::write(&candidate_esp, rewritten)?;
    }
    let mut container_results = Vec::new();
    let mut skeletal_donor_repairs = HashMap::new();
    for container in &container_inputs {
        let root = container_work.join(&container.name);
        let legacy = root.join("legacy");
        let rebuilt = root.join("rebuilt");
        fs::create_dir_all(&legacy)?;
        fs::create_dir_all(&rebuilt)?;
        let package_entries = container
            .package_store
            .iter()
            .map(|package| PackageEntry {
                package_id: package.package_id,
                path: package.path.clone(),
            })
            .collect::<Vec<_>>();
        let exact_extraction = extract_packages_with_dependency_view(
            &retoc,
            dependency_view.path(),
            &legacy,
            &package_entries,
            &format!("dependency-complete extraction {}", container.name),
        )?;
        let composite_container = composite_inspection
            .containers
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(&container.name))
            .context("composite inspection lost an additive container")?;
        let source_store = composite_container
            .package_store
            .iter()
            .map(|entry| (entry.package_id, entry))
            .collect::<HashMap<_, _>>();
        let mut expected_imports = HashMap::<u64, Vec<u64>>::new();
        let mut package_migrations = Vec::new();
        let mut optional_dependency_suppressions = Vec::new();
        for package in &composite_container.packages {
            let effective = composite_effective_package_path(package, &composite_inspection)?;
            let asset = find_extracted_additive_static_mesh(&legacy, &effective)?;
            let suppressions = identity_recovery
                .as_ref()
                .map(|recovery| {
                    recovery
                        .suppressions
                        .iter()
                        .filter(|suppression| suppression.consumer_package_id == package.package_id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if suppressions.len() > 1 {
                bail!("one Blueprint package requires multiple optional dependency suppressions");
            }
            let package_store = source_store
                .get(&package.package_id)
                .context("additive composite container lost a package-store row")?;
            let suppression = suppressions
                .first()
                .map(|suppression| {
                    let replacement = PackageEntry {
                        package_id: suppression.temporary_source_package.package_id,
                        path: suppression.temporary_identity.source_package_path.clone(),
                    };
                    suppress_optional_blueprint_dependency(
                        &asset,
                        package_store,
                        &suppression.target_package,
                        &replacement,
                        &suppression.temporary_identity.source_object_name,
                        &suppression.role,
                        &root
                            .join("optional-component-suppression")
                            .join(package.package_id.to_string()),
                    )
                })
                .transpose()?;
            let mut migration_store = (*package_store).clone();
            if let Some(suppression) = &suppression {
                migration_store.imported_package_ids =
                    suppression.target_imported_package_ids.clone();
            }
            let migration = migrate_composite_package(
                package,
                &asset,
                &migration_store,
                &source_ids,
                &composite_inspection.target_dependencies,
                &composite_inspection.target_package_imports,
                &available_dependencies,
                dependency_view.path(),
                current_composite_view.path(),
                &retoc,
                &root
                    .join("package-migrations")
                    .join(package.package_id.to_string()),
            )?;
            expected_imports.insert(package.package_id, migration.expected_imports.clone());
            if migration.kind == "skeletal-mesh"
                && let Some(repair) = &migration.import_repair
            {
                skeletal_donor_repairs.insert(package.package_id, repair.clone());
            }
            package_migrations.push(migration);
            if let Some(suppression) = suppression {
                optional_dependency_suppressions.push(suppression);
            }
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
        let (_, rebuilt_store) = retoc.package_store_entries(&rebuilt_utoc)?;
        let mut dependency_edge_count = 0_usize;
        for (package_id, expected) in &expected_imports {
            let actual = rebuilt_store
                .iter()
                .find(|entry| entry.package_id == *package_id)
                .with_context(|| format!("rebuilt additive store lost package {package_id}"))?;
            if actual
                .imported_package_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected.iter().copied().collect::<BTreeSet<_>>()
            {
                bail!(
                    "rebuilt additive imports changed for package {package_id}: expected {:?}, found {:?}",
                    expected.iter().copied().collect::<BTreeSet<_>>(),
                    actual
                        .imported_package_ids
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>()
                );
            }
            dependency_edge_count += expected.len();
        }
        let dependency_preservation = DependencyPreservationReport {
            api: "zen-approved-dependency-migration-v1".to_owned(),
            package_count: expected_imports.len(),
            dependency_edge_count,
            preserved: true,
        };
        let candidate_directory = candidate_container_directory(&container.source_directory)?;
        // The candidate tree was copied verbatim, so a container published
        // under a normalized stem must not leave its authored spelling
        // behind as a stale duplicate.
        for original in [&container.utoc, &container.ucas, &container.pak] {
            let copied = candidate_directory.join(
                original
                    .file_name()
                    .context("source container has no filename")?,
            );
            if copied.is_file() {
                fs::remove_file(&copied)?;
            }
        }
        for path in [&rebuilt_utoc, &rebuilt_ucas, &rebuilt_pak] {
            copy_file(path, &candidate_directory.join(path.file_name().unwrap()))?;
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
                utoc_sha256: sha256_file(
                    &candidate_directory.join(format!("{}.utoc", container.name)),
                )?,
                ucas_sha256: sha256_file(
                    &candidate_directory.join(format!("{}.ucas", container.name)),
                )?,
                pak_sha256: sha256_file(
                    &candidate_directory.join(format!("{}.pak", container.name)),
                )?,
                retoc_verified: true,
                inventory_preserved: true,
            },
            body_setup_repairs,
            exact_extraction,
            dependency_preservation,
            package_migrations,
            optional_dependency_suppressions,
        });
    }
    if let Some(recovery) = &identity_recovery
        && !recovery.aliases.is_empty()
    {
        let provider = recovery
            .provider
            .as_ref()
            .context("identity alias provider is missing for persistent aliases")?;
        // Deterministic provider placement: the candidate folder of the first
        // container (sorted input order) whose package store holds a
        // recovered consumer, so the alias provider mounts beside the
        // packages that import it.
        let consumer_ids = recovery
            .aliases
            .iter()
            .map(|alias| alias.consumer_package_id)
            .collect::<HashSet<_>>();
        let provider_home = container_inputs
            .iter()
            .find(|container| {
                container
                    .package_store
                    .iter()
                    .any(|package| consumer_ids.contains(&package.package_id))
            })
            .or_else(|| container_inputs.first())
            .context("identity alias provider has no host container folder")?;
        let provider_directory = candidate_container_directory(&provider_home.source_directory)?;
        for source in [
            &provider.provider_utoc,
            &provider.provider_ucas,
            &provider.provider_pak,
        ] {
            copy_file(source, &provider_directory.join(source.file_name().unwrap()))?;
        }
        retoc.verify(
            &provider_directory.join(provider.provider_utoc.file_name().unwrap()),
            "additive identity alias provider",
        )?;
    }
    verify_donor_rebinds_consumed(identity_recovery.as_ref(), &skeletal_donor_repairs)?;

    stage(
        callback,
        5,
        "Rechecking ESP bytes, IDs, SyncMap, and package inventories",
    );
    let source_esp_hash = sha256_file(&esp_files[0])?;
    let candidate_esp_hash = sha256_file(&candidate_esp)?;
    if plugin_replacements.is_empty() && source_esp_hash != candidate_esp_hash {
        bail!("ESP bytes changed without a planned semantic inventory merge");
    }
    if plugin_replacements.is_empty() {
        verify_plugin_set_preserved(&mod_root, &candidate_root)?;
    } else {
        verify_plugin_set_with_rewritten_esp(
            &mod_root,
            &candidate_root,
            &esp_relative.to_string_lossy(),
        )?;
    }
    let candidate_plugin = read_plugin(&candidate_esp)?;
    let candidate_owned_ids = sorted_form_ids(
        candidate_plugin
            .records
            .iter()
            .filter(|record| (record.form_id >> 24) as u8 == owned_index)
            .map(|record| record.form_id),
    );
    ensure_same_set(&owned_ids, &candidate_owned_ids, "plugin-owned ESP FormIDs")?;
    if plugin.masters != candidate_plugin.masters {
        bail!("ESP master list changed");
    }
    if candidate_plugin.declared_record_count != plugin.declared_record_count
        || candidate_plugin.next_object_id != plugin.next_object_id
    {
        bail!("ESP header identity changed during inventory merge");
    }
    match (lane, semantic_gate_path) {
        (EspSyncLane::AdditiveSyncmap, false) => {
            for (form_id, current) in &current_records {
                let candidate_override = candidate_plugin
                    .records
                    .iter()
                    .find(|record| record.form_id == *form_id)
                    .with_context(|| format!("rewritten ESP lost override 0x{form_id:08X}"))?;
                validate_inventory_addition(candidate_override, &current.record, plugin_index)?;
            }
        }
        _ => {
            for (form_id, replacement) in &plugin_replacements {
                let candidate_record = candidate_plugin
                    .records
                    .iter()
                    .find(|record| record.form_id == *form_id)
                    .with_context(|| format!("rewritten ESP lost override 0x{form_id:08X}"))?;
                if candidate_record.flags != replacement.flags
                    || candidate_record.kind != replacement.kind
                    || candidate_record.subrecords.len() != replacement.subrecords.len()
                    || candidate_record
                        .subrecords
                        .iter()
                        .zip(&replacement.subrecords)
                        .any(|(actual, expected)| {
                            actual.kind != expected.kind || actual.data != expected.data
                        })
                {
                    bail!(
                        "rewritten override 0x{form_id:08X} does not match the planned undelete-and-disable record"
                    );
                }
            }
            // The final candidate must itself pass the semantic gate with zero deletion stubs.
            let candidate_bytes = fs::read(&candidate_esp)?;
            let final_evaluation = evaluate_worldspace_lane_semantics(
                &candidate_plugin,
                &candidate_bytes,
                &esp_name,
                &game_data,
            )?;
            if final_evaluation.semantic_gate.status != "proven" {
                bail!(
                    "the rewritten candidate fails the current-master semantic gate: {}",
                    final_evaluation.semantic_gate.blockers.join(", ")
                );
            }
            if final_evaluation.deleted_override_policy.deletion_stub_count != 0 {
                bail!(
                    "the rewritten candidate still carries {} deleted master override(s)",
                    final_evaluation.deleted_override_policy.deletion_stub_count
                );
            }
        }
    }
    let sync_entries = read_sync_map(&sync_files[0])?;
    if sync_entries.is_empty() {
        bail!("SyncMap contains no [Meshes] entries");
    }
    let sync_map_resolutions = match lane {
        EspSyncLane::AdditiveSyncmap => {
            resolve_sync_map_entries(&sync_entries, &owned_records, &original_packages)?
        }
        EspSyncLane::MagicLoaderWorldspace => resolve_sync_map_entries_layered(
            &sync_entries,
            &owned_records,
            &original_packages,
            &current_game_store,
        )?,
    };
    let dependency_plan: DependencyReport =
        check_or_install(&game.root, dependency_candidates.clone(), false)?;
    let body_setup_repair_count = container_results
        .iter()
        .map(|container| container.body_setup_repairs.len())
        .sum::<usize>();
    let persistent_alias_package_count = identity_recovery
        .as_ref()
        .map(|recovery| {
            recovery
                .aliases
                .iter()
                .map(|alias| alias.target_package.package_id)
                .collect::<BTreeSet<_>>()
                .len()
        })
        .unwrap_or(0);
    let report_path = output_directory.join(match lane {
        EspSyncLane::AdditiveSyncmap => "additive-update-report.json",
        EspSyncLane::MagicLoaderWorldspace => "magicloader-worldspace-update-report.json",
    });
    let dependency_install_report_path =
        output_directory.join("runtime-dependency-install-report.json");
    let mut fix_apis = vec![
        PLUGIN_MANIFEST_API,
        match lane {
            EspSyncLane::AdditiveSyncmap => ADDITIVE_CONTRACT_API,
            EspSyncLane::MagicLoaderWorldspace => crate::plugin::MAGICLOADER_SYNCMAP_KEY_GATE_API,
        },
        RUNTIME_DEPENDENCY_TRANSACTION_API,
        DEPENDENCY_DIAGNOSTIC_API,
        EXACT_DEPENDENCY_EXTRACTION_API,
        DEPENDENCY_PRESERVATION_API,
        "zen-approved-dependency-migration-v1",
        "single-resolved-dependency-public-export-rebase-v2",
        "package-store-decoder-placeholder-repair-v2",
    ];
    if layered_dependency_support.is_some() {
        fix_apis.push(LAYERED_IOSTORE_DEPENDENCY_API);
    }
    if plugin_replacements.is_empty() {
        fix_apis.push(PLUGIN_PRESERVATION_API);
    } else if lane == EspSyncLane::MagicLoaderWorldspace {
        fix_apis.push(UNDELETE_DISABLE_POLICY_API);
    } else {
        fix_apis.push(PLUGIN_SEMANTIC_REWRITE_API);
    }
    if lane == EspSyncLane::MagicLoaderWorldspace {
        fix_apis.extend([
            MAGICLOADER_WORLDSPACE_PLUGIN_POLICY,
            WORLDSPACE_SEMANTIC_GATE_API,
        ]);
    }
    if identity_recovery
        .as_ref()
        .is_some_and(|recovery| !recovery.aliases.is_empty())
    {
        fix_apis.extend([
            "package-root-public-export-identity-alias-v1",
            "blueprint-serialized-alias-role-proof-v1",
        ]);
    }
    if identity_recovery
        .as_ref()
        .is_some_and(|recovery| !recovery.suppressions.is_empty())
    {
        fix_apis.extend([
            "blueprint-serialized-alias-role-proof-v1",
            "optional-secondary-blueprint-component-suppression-v1",
        ]);
    }
    fix_apis.sort_unstable();
    fix_apis.dedup();
    let mut report = json!({
        "schema": match lane {
            EspSyncLane::AdditiveSyncmap => "obr-additive-mod-update-report",
            EspSyncLane::MagicLoaderWorldspace => "obr-magicloader-worldspace-update-report",
        },
        "version": match lane {
            EspSyncLane::AdditiveSyncmap => 7,
            EspSyncLane::MagicLoaderWorldspace => 1,
        },
        "adapter": lane.adapter_id(),
        "implementation": "native-rust",
        "fixApis": fix_apis,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "reportSnapshot": "candidate-publication",
        "status": if dependency_plan.ready {
            "candidate_ready_for_runtime_test"
        } else {
            "candidate_verified_dependency_install_pending"
        },
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
            "pluginManifestSha256": plugin_set.manifest_sha256.clone(),
        },
        "target": {
            "gameRoot": game.root,
            "esm": game_esm,
            "esmBytes": fs::metadata(&game_esm)?.len(),
            "esmSha256": sha256_file(&game_esm)?,
            "globalUtocSha256": sha256_file(&global_utoc)?,
            "globalUcasSha256": sha256_file(&global_ucas)?,
            "stockPackageUtocSha256": sha256_file(&stock_utoc)?,
        },
        "identity": {
            "esmEdited": false,
            "espBytePreserved": plugin_replacements.is_empty(),
            "espSemanticInventoryMerge": !plugin_replacements.is_empty(),
            "rewrittenOverrideCount": plugin_replacements.len(),
            "espSourceSha256": source_esp_hash,
            "espCandidateSha256": candidate_esp_hash,
            "mastersPreserved": true,
            "masters": plugin.masters,
            "declaredRecordCount": plugin.declared_record_count,
            "nextObjectId": format!("0x{:08X}", plugin.next_object_id),
            "pluginOwnedFormIds": owned_ids,
            "masterOverrides": override_results,
            "optionalUnrealDependencySuppressionCount": identity_recovery
                .as_ref()
                .map(|recovery| recovery.suppressions.len())
                .unwrap_or(0),
            "persistentUnrealIdentityAliasCount": identity_recovery
                .as_ref()
                .map(|recovery| recovery.aliases.len())
                .unwrap_or(0),
            "recoveredStaleDependencyRebindCount": identity_recovery
                .as_ref()
                .map(|recovery| recovery.donor_rebinds.len())
                .unwrap_or(0),
            "recoveredStaleDependencyRebinds": identity_recovery
                .as_ref()
                .map(|recovery| recovery.donor_rebinds.clone())
                .unwrap_or_default(),
            "syncMapEntries": sync_entries,
            "syncMapResolutions": sync_map_resolutions,
        },
        "pluginCompatibility": plugin_set,
        "unreal": {
            "additivePackageCount": original_packages.len(),
            "targetPathCollisionCount": 0,
            "bodySetupRepairCount": body_setup_repair_count,
            "collisionPolicy": "For structurally recognized StaticMesh BodySetup exports, the incompatible derived cooked-physics tail is normalized to the shipping game's accepted empty-cache boundary while the serialized property region (including AggGeom simple-collision source data) and BodySetupGuid are preserved. Each change remains disclosed as collisionRemoved: true and requires an in-game collision test.",
            "packagePaths": original_packages,
            "dependencyTrace": dependency_trace,
            "layeredDependencyResolution": layered_dependency_support.as_ref().map(|support| json!({
                "api": LAYERED_IOSTORE_DEPENDENCY_API,
                "logicalSha256": support.probe.report.logical_sha256,
                "usedProviderIds": support.used_provider_ids,
                "satisfiedImportDisclosures": support.disclosures,
                "note": "Imports listed here are satisfied by connected, installed, or game/DLC providers under explicit precedence; the candidate depends on those providers staying installed or connected.",
            })),
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
            "archiveContainsReportSnapshot": "candidate-publication",
            "postPublicationDependencyReport": dependency_install_report_path,
        },
        "verification": {
            "sourceContainersVerified": true,
            "rebuiltContainersVerified": true,
            "packageInventoriesPreserved": true,
            "packageDependencyGraphsPreserved": true,
            "dependencyCompleteExtraction": true,
            "approvedCompositeDependencyMigration": true,
            "espReparsed": true,
            "completePluginSetPreserved": true,
            "syncMapLinksResolved": true,
            "runtimeDependenciesReadyAtPublication": dependency_plan.ready,
            "productionRuntimeGateRequired": true,
            "note": "The portable candidate is published before any dependency installation mutates the game. Final dependency state is recorded separately, and this candidate is not called repaired until an in-game production run proves the content and behavior."
        },
        "runtimeDependenciesAtPublication": &dependency_plan,
        "runtimeDependencyInstall": {
            "phase": "after-durable-candidate-publication",
            "transactionPolicy": "all payloads are validated and staged before commit; any commit failure restores every changed destination",
        },
    });
    if lane == EspSyncLane::MagicLoaderWorldspace {
        let evaluation = worldspace_evaluation
            .as_ref()
            .context("the MagicLoader worldspace lane lost its semantic evaluation")?;
        report["identity"]["espSemanticInventoryMerge"] = json!(false);
        report["identity"]["espUndeleteDisableRewrite"] = json!(!plugin_replacements.is_empty());
        report["identity"]["espUndeleteDisableCount"] = json!(plugin_replacements.len());
        report["identity"]["worldspaceSemanticGate"] =
            serde_json::to_value(&evaluation.semantic_gate)?;
        report["identity"]["deletedOverridePolicy"] =
            serde_json::to_value(&evaluation.deleted_override_policy)?;
        let magic_loader_runtime_installed = {
            let path = game.root.join(r"MagicLoader\MagicLoader.exe");
            fs::read(&path)
                .ok()
                .is_some_and(|bytes| bytes.starts_with(b"MZ"))
        };
        let sidecars = magic_loader_files
            .iter()
            .map(|file| {
                Ok(json!({
                    "name": file.file_name().unwrap_or_default().to_string_lossy(),
                    "bytes": fs::metadata(file)?.len(),
                    "sha256": sha256_file(file)?,
                    "bytePreserved": true,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        report["magicLoader"] = json!({
            "sidecars": sidecars,
            "runtimeInstalled": magic_loader_runtime_installed,
            "runtimePolicy": "The updater never installs an unverified MagicLoader payload; MagicLoader 2 must be installed in the game root before this mod is run.",
        });
    }
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
    if !install_runtime_dependencies {
        stage(
            callback,
            7,
            "Nested additive candidate complete; runtime dependencies deferred until outer publication",
        );
        return Ok((
            UpdateOutcome {
                adapter: lane.adapter_id().to_owned(),
                output_directory,
                output_archive,
                report_path,
                package_count: original_packages.len() + persistent_alias_package_count,
            },
            dependency_candidates,
        ));
    }
    stage(
        callback,
        7,
        "Candidate published; installing validated runtime dependencies transactionally",
    );
    let dependency_report: DependencyReport =
        check_or_install(&game.root, dependency_candidates, true).with_context(|| {
            format!(
                "runtime dependency install failed; the verified candidate remains at {}",
                output_archive.display()
            )
        })?;
    if !dependency_report.ready {
        bail!(
            "runtime dependencies were not ready after installation; the verified candidate remains at {}",
            output_archive.display()
        );
    }
    fs::write(
        &dependency_install_report_path,
        serde_json::to_vec_pretty(&json!({
            "schema": "obr-runtime-dependency-install-report",
            "version": 1,
            "generatedAt": chrono::Utc::now().to_rfc3339(),
            "candidateArchive": output_archive,
            "candidateReport": report_path,
            "transactional": true,
            "result": &dependency_report,
        }))?,
    )?;
    report["generatedAt"] = json!(chrono::Utc::now().to_rfc3339());
    report["reportSnapshot"] = json!("post-publication-final");
    report["status"] = json!("candidate_ready_for_runtime_test");
    report["verification"]["runtimeDependenciesReadyAfterPublication"] =
        json!(dependency_report.ready);
    report["runtimeDependenciesAfterPublication"] = serde_json::to_value(&dependency_report)?;
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    stage(
        callback,
        8,
        "Structural update complete; shipping-game test still required",
    );
    Ok((
        UpdateOutcome {
            adapter: lane.adapter_id().to_owned(),
            output_directory,
            output_archive,
            report_path,
            package_count: original_packages.len() + persistent_alias_package_count,
        },
        Vec::new(),
    ))
}

fn canonical_entries(entries: &[PackageEntry]) -> Result<Vec<PackageEntry>> {
    let mut canonical = entries
        .iter()
        .map(|entry| {
            Ok(PackageEntry {
                package_id: entry.package_id,
                path: canonical_additive_static_mesh_path(&entry.path)?,
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
    let (_, current_packages) = retoc.package_entries(&inspection.target_utoc)?;
    let current_packages_by_id = current_packages
        .into_iter()
        .map(|package| (package.package_id, package))
        .collect::<HashMap<_, _>>();
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
            let current_package = current_packages_by_id
                .get(&package.package_id)
                .with_context(|| {
                    format!(
                        "current Texture2D package inventory is missing {}",
                        package.path
                    )
                })?;
            let donor_asset =
                extract_current_package(&retoc, stock_input, &donor_root, current_package)?;
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

fn run_heterogeneous_replacement_update(
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

    let game_paks = game.root.join(r"OblivionRemastered\Content\Paks");
    let work = tempfile::Builder::new()
        .prefix("obr-heterogeneous-replacement-update-")
        .tempdir()?;
    let staged = work.path().join("source");
    let retoc = RetocTool::materialize()?;
    stage(
        callback,
        1,
        "Validating heterogeneous package identities, imports, and dependency closure",
    );
    stage_input(&mod_input, &staged)?;
    let inspection = inspect_heterogeneous_replacement_staged(&staged, &game.root, &retoc)?;
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
    let current_packages_by_id = inspection.target_dependencies.clone();

    fs::create_dir_all(&output_directory)?;
    copy_tree(&staged, &output_directory)?;
    let mut container_results = Vec::new();
    let mut static_mesh_count = 0_usize;
    let mut texture_count = 0_usize;
    let mut metadata_rebased_count = 0_usize;

    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let legacy = root.join("legacy");
        let current_stock = root.join("current-stock");
        let rebuilt = root.join("rebuilt");
        let verify_legacy = root.join("verify-legacy");
        let json_work = root.join("payload-verification");
        for directory in [
            &legacy,
            &current_stock,
            &rebuilt,
            &verify_legacy,
            &json_work,
        ] {
            fs::create_dir_all(directory)?;
        }

        let source_view = create_isolated_stock_view(&game.root)?;
        for source in [&container.utoc, &container.ucas, &container.pak] {
            copy_file(
                source,
                &source_view.path().join(source.file_name().unwrap()),
            )?;
        }
        stage(
            callback,
            2,
            &format!(
                "Extracting each source package with exact package-store spelling from {}",
                container.name
            ),
        );
        extract_source_packages_exact(
            &retoc,
            source_view.path(),
            &legacy,
            &container.packages,
            &format!("heterogeneous source extraction {}", container.name),
        )?;

        let mut classifications = HashMap::<u64, &'static str>::new();
        let mut texture_assets = Vec::new();
        let mut static_mesh_import_repairs = Vec::new();
        stage(
            callback,
            3,
            &format!(
                "Proving StaticMesh and Texture2D contracts for {}",
                container.name
            ),
        );
        let mut pending_textures = Vec::new();
        for package in &container.packages {
            let source_asset = find_additive_static_mesh_asset(&legacy, &package.path)?;
            match classify_heterogeneous_asset(&source_asset)? {
                ProvenHeterogeneousAsset::StaticMesh { imports } => {
                    classifications.insert(package.package_id, "static-mesh");
                    static_mesh_count += 1;
                    if imports
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
                    {
                        let source_row = container
                            .package_store
                            .iter()
                            .find(|entry| entry.package_id == package.package_id)
                            .context("heterogeneous source package store lost a StaticMesh row")?;
                        static_mesh_import_repairs.push(repair_static_mesh_imports(
                            &source_asset,
                            &source_row.imported_package_ids,
                            &inspection.target_dependencies,
                            &root
                                .join("import-repairs")
                                .join(package.package_id.to_string()),
                        )?);
                        let repaired = inspect_static_mesh_asset(&source_asset)?;
                        if repaired
                            .iter()
                            .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
                        {
                            bail!("{} retained unresolved imports after repair", package.path);
                        }
                    }
                }
                ProvenHeterogeneousAsset::Texture2D(mut source) => {
                    classifications.insert(package.package_id, "texture2d");
                    texture_count += 1;
                    source.asset = canonical_additive_static_mesh_path(&package.path)?;
                    pending_textures.push((package, Box::new(source)));
                }
            }
        }
        // One batched donor extraction per container reads the current package
        // store once instead of once per Texture2D donor.
        let donor_targets = pending_textures
            .iter()
            .map(|(package, _)| {
                Ok(current_packages_by_id
                    .get(&package.package_id)
                    .context("heterogeneous current package inventory lost an identity")?
                    .clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let donor_assets = extract_current_packages_batched(
            &retoc,
            stock_input,
            &current_stock.join("donors"),
            &donor_targets,
            &format!("heterogeneous current donor extraction {}", container.name),
        )?;
        for ((package, source), donor_asset) in pending_textures.into_iter().zip(donor_assets) {
            let donor = inspect_texture_asset(&donor_asset)?;
            texture_assets.push(validate_texture_replacement_pair(
                *source,
                &donor,
                &package.path,
            )?);
        }
        texture_assets.sort_by_key(|asset| asset.asset.to_ascii_lowercase());
        let body_setup_repairs = repair_legacy_body_setups(&legacy)?;

        stage(
            callback,
            4,
            &format!(
                "Rebuilding {} once against current Zen metadata",
                container.name
            ),
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
        for output in [&rebuilt_utoc, &rebuilt_ucas, &rebuilt_pak] {
            if !output.is_file() {
                bail!(
                    "rebuilt heterogeneous container output missing: {}",
                    output.display()
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
            &format!("heterogeneous package inventory for {}", container.name),
        )?;
        let (_, rebuilt_store) = retoc.package_store_entries(&rebuilt_utoc)?;
        for source in &container.package_store {
            let rebuilt_entry = rebuilt_store
                .iter()
                .find(|entry| entry.package_id == source.package_id)
                .with_context(|| {
                    format!("rebuilt package store is missing {}", source.package_id)
                })?;
            let authored = BTreeSet::from_iter(source.imported_package_ids.iter().copied());
            let rebuilt_imports =
                BTreeSet::from_iter(rebuilt_entry.imported_package_ids.iter().copied());
            if authored != rebuilt_imports {
                bail!(
                    "rebuilt package imports changed for {}: authored [{}], rebuilt [{}]",
                    source.path,
                    authored
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                    rebuilt_imports
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }

        stage(
            callback,
            5,
            &format!(
                "Verifying the rebuilt {} roundtrip against current Zen metadata",
                container.name
            ),
        );
        let roundtrip_view = create_isolated_stock_view(&game.root)?;
        for source in [&rebuilt_utoc, &rebuilt_ucas, &rebuilt_pak] {
            copy_file(
                source,
                &roundtrip_view.path().join(source.file_name().unwrap()),
            )?;
        }
        extract_source_packages_exact(
            &retoc,
            roundtrip_view.path(),
            &verify_legacy,
            &rebuilt_packages,
            &format!("heterogeneous roundtrip {}", container.name),
        )?;
        for package in &rebuilt_packages {
            let asset = find_additive_static_mesh_asset(&verify_legacy, &package.path)?;
            let actual = match classify_heterogeneous_asset(&asset)? {
                ProvenHeterogeneousAsset::StaticMesh { .. } => "static-mesh",
                ProvenHeterogeneousAsset::Texture2D(_) => "texture2d",
            };
            let expected = classifications
                .get(&package.package_id)
                .context("roundtrip package classification has no source identity")?;
            if actual != *expected {
                bail!(
                    "roundtrip asset class changed for {}: expected {}, found {}",
                    package.path,
                    expected,
                    actual
                );
            }
        }
        let payload_equivalence =
            verify_preserved_export_payloads(&legacy, &verify_legacy, &json_work)?;
        for package in &rebuilt_packages {
            if classifications.get(&package.package_id) != Some(&"texture2d") {
                continue;
            }
            let source_asset = find_additive_static_mesh_asset(&legacy, &package.path)?;
            let roundtrip_asset = find_additive_static_mesh_asset(&verify_legacy, &package.path)?;
            verify_rebased_asset_metadata(
                &source_asset,
                &roundtrip_asset,
                &json_work.join(format!("texture-{}", package.package_id)),
            )?;
        }
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
        let mut package_kinds = container
            .packages
            .iter()
            .map(|package| {
                json!({
                    "packageId": package.package_id,
                    "path": package.path,
                    "assetKind": classifications.get(&package.package_id),
                })
            })
            .collect::<Vec<_>>();
        package_kinds.sort_by_key(|row| {
            row["path"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
        });
        container_results.push(json!({
            "name": container.name,
            "packageCount": container.packages.len(),
            "packages": package_kinds,
            "source": {
                "utocSha256": sha256_file(&container.utoc)?,
                "ucasSha256": sha256_file(&container.ucas)?,
                "pakSha256": sha256_file(&container.pak)?,
            },
            "rebuilt": {
                "utocSha256": sha256_file(&candidate_utoc)?,
                "ucasSha256": sha256_file(&candidate_ucas)?,
                "pakSha256": sha256_file(&candidate_pak)?,
                "retocVerified": true,
                "inventoryPreserved": true,
                "importsPreserved": true,
            },
            "staticMeshImportRepairs": static_mesh_import_repairs,
            "bodySetupRepairs": body_setup_repairs,
            "textureAssets": texture_assets,
            "payloadEquivalence": payload_equivalence,
        }));
    }
    if static_mesh_count == 0 || texture_count == 0 {
        bail!(
            "heterogeneous replacement adapter requires at least one structurally proven StaticMesh and one Texture2D package"
        );
    }

    let report_path = output_directory.join("heterogeneous-replacement-update-report.json");
    let report = json!({
        "schema": "obr-heterogeneous-replacement-update-report",
        "version": 1,
        "implementation": "native-rust",
        "adapter": HETEROGENEOUS_REPLACEMENT_ADAPTER,
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
        },
        "identity": {
            "packageCount": inspection.packages.len(),
            "staticMeshCount": static_mesh_count,
            "texture2DCount": texture_count,
            "currentGamePackageIdsMatched": true,
            "currentGamePathOrProjectRootAliasMatched": true,
            "sourceAndCurrentImportSetsRequiredToMatch": false,
            "sourceDependencyClosureComplete": true,
            "authoredSourceImportsPreserved": true,
            "metadataRebasedAssetCount": metadata_rebased_count,
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
            "sourceExactCaseExtraction": true,
            "sourceContainersVerified": true,
            "rebuiltContainersVerified": true,
            "packagePathsAndIdsPreserved": true,
            "packageImportsPreserved": true,
            "roundtripClassesPreserved": true,
            "roundtripFileSetsPreserved": true,
            "payloadsPreservedOutsideAllowedLinkageMetadata": true,
            "productionRuntimeGateRequired": true,
        }
    });
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    stage(
        callback,
        6,
        "Creating portable heterogeneous replacement candidate archive",
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
        "Heterogeneous candidate complete; shipping-game test still required",
    );
    Ok(UpdateOutcome {
        adapter: HETEROGENEOUS_REPLACEMENT_ADAPTER.to_owned(),
        output_directory,
        output_archive,
        report_path,
        package_count: inspection.packages.len(),
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CompositePackageMigration {
    kind: &'static str,
    decoder_unresolved_import_count: usize,
    import_repair: Option<CompositePackageImportRepair>,
    static_mesh_repair: Option<serde_json::Value>,
    expected_imports: Vec<u64>,
}

fn extract_current_composite_asset(
    retoc: &RetocTool,
    current_view: &Path,
    current: &PackageEntry,
    output: &Path,
    label: &str,
) -> Result<PathBuf> {
    extract_composite_packages_exact(
        retoc,
        current_view,
        output,
        &[(current.clone(), current.path.clone())],
        label,
    )?;
    find_extracted_additive_static_mesh(output, &current.path)
}

#[allow(clippy::too_many_arguments)]
fn migrate_composite_package(
    package: &PackageEntry,
    asset: &Path,
    source_store: &PackageStoreEntry,
    source_ids: &HashSet<u64>,
    target_dependencies: &HashMap<u64, PackageEntry>,
    target_package_imports: &HashMap<u64, Vec<u64>>,
    available_dependencies: &HashMap<u64, PackageEntry>,
    source_view: &Path,
    current_view: &Path,
    retoc: &RetocTool,
    work: &Path,
) -> Result<CompositePackageMigration> {
    let existing = target_dependencies.contains_key(&package.package_id);
    let (kind, unresolved) =
        classify_composite_package_asset(asset, existing, &work.join("classification"))?;
    let missing = source_store
        .imported_package_ids
        .iter()
        .filter(|dependency| !available_dependencies.contains_key(dependency))
        .count();
    let mut expected = source_store
        .imported_package_ids
        .iter()
        .filter(|dependency| available_dependencies.contains_key(dependency))
        .copied()
        .collect::<BTreeSet<_>>();
    let mut import_repair = None;
    let mut static_mesh_repair = None;
    let kind_name = match kind {
        CompositePackageAssetKind::SkeletalMesh => {
            if !existing {
                bail!("additive SkeletalMesh packages require a separate proven donor contract");
            }
            if unresolved != 0 {
                let current = target_dependencies
                    .get(&package.package_id)
                    .context("existing SkeletalMesh has no current donor identity")?;
                let donor = extract_current_composite_asset(
                    retoc,
                    current_view,
                    current,
                    &work.join("current"),
                    "current SkeletalMesh extraction",
                )?;
                let repair = repair_composite_skeletal_mesh_imports(
                    asset,
                    &donor,
                    source_store,
                    available_dependencies,
                    &work.join("repair"),
                )?;
                expected = repair.target_imported_package_ids.iter().copied().collect();
                import_repair = Some(repair);
            } else if missing != 0 {
                bail!("resolved SkeletalMesh retains unresolved package-store dependencies");
            }
            "skeletal-mesh"
        }
        CompositePackageAssetKind::StaticMesh => {
            let imports = inspect_static_mesh_asset(asset)?;
            if imports
                .iter()
                .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
            {
                let repair = repair_static_mesh_imports(
                    asset,
                    &source_store.imported_package_ids,
                    available_dependencies,
                    &work.join("repair"),
                )?;
                expected.extend(repair.target_package_ids.iter().copied());
                static_mesh_repair = Some(serde_json::to_value(repair)?);
            } else if missing != 0 {
                bail!("resolved StaticMesh retains unresolved package-store dependencies");
            }
            "static-mesh"
        }
        CompositePackageAssetKind::Texture2D => {
            inspect_texture_asset(asset)?;
            if unresolved != 0 {
                if !existing {
                    bail!("additive Texture2D has unresolved imports");
                }
                let current = target_dependencies
                    .get(&package.package_id)
                    .context("existing Texture2D has no current template")?;
                let donor = extract_current_composite_asset(
                    retoc,
                    current_view,
                    current,
                    &work.join("current"),
                    "current Texture2D extraction",
                )?;
                let mut repair = repair_current_template_imports(
                    asset,
                    &donor,
                    source_store,
                    available_dependencies,
                    &work.join("repair"),
                )?;
                repair.target_imported_package_ids = target_package_imports
                    .get(&package.package_id)
                    .context("existing Texture2D has no current package-store graph")?
                    .clone();
                expected = repair.target_imported_package_ids.iter().copied().collect();
                import_repair = Some(repair);
            } else if missing != 0 {
                bail!("resolved Texture2D retains unresolved package-store dependencies");
            }
            "texture2d"
        }
        CompositePackageAssetKind::MaterialInstanceConstant => {
            if unresolved != 0 {
                let mut repair = if existing {
                    let current = target_dependencies
                        .get(&package.package_id)
                        .context("existing material instance has no current template")?;
                    let donor = extract_current_composite_asset(
                        retoc,
                        current_view,
                        current,
                        &work.join("current"),
                        "current material extraction",
                    )?;
                    repair_current_template_imports(
                        asset,
                        &donor,
                        source_store,
                        available_dependencies,
                        &work.join("repair"),
                    )?
                } else {
                    let targets = source_store
                        .imported_package_ids
                        .iter()
                        .filter(|dependency| !source_ids.contains(dependency))
                        .filter_map(|dependency| target_dependencies.get(dependency))
                        .collect::<Vec<_>>();
                    if targets.len() != 1 {
                        bail!(
                            "additive material with one unresolved public export must have exactly one external current dependency; found {}",
                            targets.len()
                        );
                    }
                    let target = targets[0];
                    let donor = extract_current_composite_asset(
                        retoc,
                        current_view,
                        target,
                        &work.join("dependency"),
                        "current material-parent extraction",
                    )?;
                    repair_single_external_import(
                        asset,
                        &donor,
                        target,
                        source_store,
                        available_dependencies,
                        &work.join("repair"),
                    )?
                };
                if existing {
                    repair.target_imported_package_ids = target_package_imports
                        .get(&package.package_id)
                        .context("existing material has no current package-store graph")?
                        .clone();
                }
                expected = repair.target_imported_package_ids.iter().copied().collect();
                import_repair = Some(repair);
            } else if missing != 0 {
                bail!("resolved material instance retains unresolved package-store dependencies");
            }
            "material-instance"
        }
        CompositePackageAssetKind::ResolvedAuthoredPackage => {
            if missing != 0 {
                bail!("authored package retains unresolved package-store dependencies");
            }
            if unresolved != 0 {
                let targets = unresolved_package_store_dependencies(
                    asset,
                    source_store,
                    available_dependencies,
                    &work.join("unresolved-package-store"),
                )?;
                if targets.len() != 1 {
                    bail!(
                        "authored package decoder repair requires exactly one package-store-proven target; found {}",
                        targets.len()
                    );
                }
                let target = &targets[0];
                let donor_root = work.join("resolved-dependency");
                // The proven target is either a current-game package (read
                // from the pure current view) or a source-bundled package
                // (read from the exclusive source-only view); a merged view
                // could silently substitute bytes for shared IDs.
                if target_dependencies.contains_key(&target.package_id) {
                    extract_composite_packages_exact(
                        retoc,
                        current_view,
                        &donor_root,
                        &[(target.clone(), target.path.clone())],
                        "authored package dependency extraction",
                    )?;
                } else {
                    extract_source_composite_packages_exact(
                        retoc,
                        source_view,
                        &donor_root,
                        &[(target.clone(), target.path.clone())],
                        "authored package dependency extraction",
                    )?;
                }
                let donor = find_extracted_additive_static_mesh(&donor_root, &target.path)?;
                let repair = repair_single_external_import(
                    asset,
                    &donor,
                    target,
                    source_store,
                    available_dependencies,
                    &work.join("repair"),
                )?;
                expected = repair.target_imported_package_ids.iter().copied().collect();
                import_repair = Some(repair);
            }
            "resolved-authored-package"
        }
        CompositePackageAssetKind::CurrentTemplatePackage => {
            let current = target_dependencies
                .get(&package.package_id)
                .context("current-template package has no current identity")?;
            let donor = extract_current_composite_asset(
                retoc,
                current_view,
                current,
                &work.join("current"),
                "current template extraction",
            )?;
            let mut repair = repair_current_template_imports(
                asset,
                &donor,
                source_store,
                available_dependencies,
                &work.join("repair"),
            )?;
            repair.target_imported_package_ids = target_package_imports
                .get(&package.package_id)
                .context("current-template package has no current package-store graph")?
                .clone();
            expected = repair.target_imported_package_ids.iter().copied().collect();
            import_repair = Some(repair);
            "current-template-package"
        }
    };
    Ok(CompositePackageMigration {
        kind: kind_name,
        decoder_unresolved_import_count: unresolved,
        import_repair,
        static_mesh_repair,
        expected_imports: expected.into_iter().collect(),
    })
}

fn run_composite_package_update(
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

    let work = tempfile::Builder::new()
        .prefix("obr-composite-package-update-")
        .tempdir()?;
    let staged = work.path().join("source");
    let retoc = RetocTool::materialize()?;
    stage(
        callback,
        1,
        "Classifying composite package identities and repair contracts",
    );
    stage_input(&mod_input, &staged)?;
    let inspection = inspect_composite_package_staged(&staged, &game.root, &retoc)?;
    let game_paks = game.root.join(r"OblivionRemastered\Content\Paks");
    ensure_no_installed_replacement_collisions(
        &game_paks,
        &inspection.packages,
        &retoc,
        &request.installed_collision_exclusions,
    )?;
    let source_view = create_isolated_stock_view(&game.root)?;
    let current_view = create_isolated_stock_view(&game.root)?;
    for container in &inspection.containers {
        for source in [&container.utoc, &container.ucas, &container.pak] {
            copy_file(
                source,
                &source_view.path().join(
                    source
                        .file_name()
                        .context("source composite container has no filename")?,
                ),
            )?;
        }
    }
    let identity_recovery = recover_composite_package_identities(
        &inspection,
        &retoc,
        source_view.path(),
        &work.path().join("identity-recovery"),
    )?;
    let mut available_dependencies = inspection.target_dependencies.clone();
    for package in &inspection.packages {
        available_dependencies
            .entry(package.package_id)
            .or_insert_with(|| package.clone());
    }
    if let Some(recovery) = &identity_recovery {
        for alias in &recovery.aliases {
            available_dependencies
                .entry(alias.target_package.package_id)
                .or_insert_with(|| alias.target_package.clone());
        }
        for suppression in &recovery.suppressions {
            available_dependencies
                .entry(suppression.target_package.package_id)
                .or_insert_with(|| suppression.target_package.clone());
        }
    }
    let source_ids = inspection
        .packages
        .iter()
        .map(|package| package.package_id)
        .collect::<HashSet<_>>();
    fs::create_dir_all(&output_directory)?;
    copy_tree(&staged, &output_directory)?;

    struct BuiltCompositeContainer {
        container: crate::replacement::ReplacementContainer,
        legacy: PathBuf,
        rebuilt_utoc: PathBuf,
        rebuilt_ucas: PathBuf,
        rebuilt_pak: PathBuf,
        package_rows: Vec<serde_json::Value>,
        expected_imports: HashMap<u64, Vec<u64>>,
        body_setup_repairs: Vec<BodySetupRepair>,
    }
    let mut built = Vec::new();
    let mut skeletal_donor_repairs = HashMap::new();
    stage(
        callback,
        2,
        "Extracting dependency-complete composite package sets",
    );
    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let legacy = root.join("legacy");
        let rebuilt = root.join("rebuilt");
        fs::create_dir_all(&rebuilt)?;
        let effective_packages = container
            .packages
            .iter()
            .map(|package| {
                Ok((
                    package.clone(),
                    composite_effective_package_path(package, &inspection)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let source_utocs = inspection
            .containers
            .iter()
            .map(|container| container.utoc.clone())
            .collect::<Vec<_>>();
        extract_source_composite_packages_with_fallback(
            &retoc,
            source_view.path(),
            current_view.path(),
            &source_utocs,
            &legacy,
            &effective_packages,
            &format!("composite extraction {}", container.name),
        )?;
        let source_store = container
            .package_store
            .iter()
            .map(|entry| (entry.package_id, entry))
            .collect::<HashMap<_, _>>();
        let mut rows = Vec::new();
        let mut expected_imports = HashMap::new();
        for package in &container.packages {
            let effective = composite_effective_package_path(package, &inspection)?;
            let asset = find_extracted_additive_static_mesh(&legacy, &effective)?;
            let suppression = identity_recovery
                .as_ref()
                .map(|recovery| {
                    recovery
                        .suppressions
                        .iter()
                        .filter(|suppression| suppression.consumer_package_id == package.package_id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if suppression.len() > 1 {
                bail!("one Blueprint package requires multiple optional dependency suppressions");
            }
            let package_store = source_store
                .get(&package.package_id)
                .context("composite container lost a package-store row")?;
            let suppression = suppression
                .first()
                .map(|suppression| {
                    let replacement = PackageEntry {
                        package_id: suppression.temporary_source_package.package_id,
                        path: suppression.temporary_identity.source_package_path.clone(),
                    };
                    suppress_optional_blueprint_dependency(
                        &asset,
                        package_store,
                        &suppression.target_package,
                        &replacement,
                        &suppression.temporary_identity.source_object_name,
                        &suppression.role,
                        &root
                            .join("packages")
                            .join(package.package_id.to_string())
                            .join("optional-component-suppression"),
                    )
                })
                .transpose()?;
            let mut migration_store = (*package_store).clone();
            if let Some(suppression) = &suppression {
                migration_store.imported_package_ids =
                    suppression.target_imported_package_ids.clone();
            }
            let migration = migrate_composite_package(
                package,
                &asset,
                &migration_store,
                &source_ids,
                &inspection.target_dependencies,
                &inspection.target_package_imports,
                &available_dependencies,
                source_view.path(),
                current_view.path(),
                &retoc,
                &root.join("packages").join(package.package_id.to_string()),
            )
            .with_context(|| format!("migrating composite package {}", package.path))?;
            expected_imports.insert(package.package_id, migration.expected_imports.clone());
            if migration.kind == "skeletal-mesh"
                && let Some(repair) = &migration.import_repair
            {
                skeletal_donor_repairs.insert(package.package_id, repair.clone());
            }
            rows.push(json!({
                "packageId": package.package_id,
                "sourcePath": package.path,
                "outputPath": effective,
                "assetKind": migration.kind,
                "decoderUnresolvedImportCount": migration.decoder_unresolved_import_count,
                "importRepair": migration.import_repair,
                "staticMeshRepair": migration.static_mesh_repair,
                "optionalDependencySuppression": suppression,
            }));
        }
        let body_setup_repairs = repair_legacy_body_setups(&legacy)?;
        stage(
            callback,
            3,
            &format!("Rebuilding composite container {}", container.name),
        );
        let rebuilt_utoc = rebuilt.join(format!("{}.utoc", container.name));
        let result = retoc.run(args([
            OsString::from("to-zen"),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            legacy.as_os_str().to_owned(),
            rebuilt_utoc.as_os_str().to_owned(),
        ]))?;
        RetocTool::assert_success(&result, &format!("retoc to-zen {}", container.name))?;
        let rebuilt_ucas = rebuilt_utoc.with_extension("ucas");
        let rebuilt_pak = rebuilt_utoc.with_extension("pak");
        for path in [&rebuilt_utoc, &rebuilt_ucas, &rebuilt_pak] {
            if !path.is_file() {
                bail!("rebuilt composite output is missing: {}", path.display());
            }
        }
        retoc.verify(&rebuilt_utoc, &format!("retoc verify {}", container.name))?;
        let (_, rebuilt_packages) = retoc.package_entries(&rebuilt_utoc)?;
        let expected_inventory = effective_packages
            .iter()
            .map(|(package, path)| {
                Ok((
                    canonical_additive_static_mesh_path(path)?.to_ascii_lowercase(),
                    package.package_id,
                ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let actual_inventory = rebuilt_packages
            .iter()
            .map(|package| {
                Ok((
                    canonical_additive_static_mesh_path(&package.path)?.to_ascii_lowercase(),
                    package.package_id,
                ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if expected_inventory != actual_inventory {
            bail!(
                "rebuilt composite package inventory changed for {}",
                container.name
            );
        }
        let (_, rebuilt_store) = retoc.package_store_entries(&rebuilt_utoc)?;
        for (package_id, expected) in &expected_imports {
            let actual = rebuilt_store
                .iter()
                .find(|entry| entry.package_id == *package_id)
                .with_context(|| format!("rebuilt composite store lost package {package_id}"))?;
            if actual
                .imported_package_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected.iter().copied().collect::<BTreeSet<_>>()
            {
                bail!("rebuilt composite imports changed for package {package_id}");
            }
        }
        built.push(BuiltCompositeContainer {
            container: container.clone(),
            legacy,
            rebuilt_utoc,
            rebuilt_ucas,
            rebuilt_pak,
            package_rows: rows,
            expected_imports,
            body_setup_repairs,
        });
    }

    verify_donor_rebinds_consumed(identity_recovery.as_ref(), &skeletal_donor_repairs)?;

    stage(
        callback,
        4,
        "Roundtripping every rebuilt composite package against current stock",
    );
    let verify_view = create_isolated_stock_view(&game.root)?;
    for container in &built {
        for source in [
            &container.rebuilt_utoc,
            &container.rebuilt_ucas,
            &container.rebuilt_pak,
        ] {
            copy_file(
                source,
                &verify_view.path().join(
                    source
                        .file_name()
                        .context("rebuilt composite container has no filename")?,
                ),
            )?;
        }
    }
    if let Some(recovery) = &identity_recovery
        && !recovery.aliases.is_empty()
    {
        let provider = recovery
            .provider
            .as_ref()
            .context("identity alias provider is missing for persistent aliases")?;
        for source in [
            &provider.provider_utoc,
            &provider.provider_ucas,
            &provider.provider_pak,
        ] {
            copy_file(
                source,
                &verify_view.path().join(
                    source
                        .file_name()
                        .context("identity alias provider has no filename")?,
                ),
            )?;
        }
    }
    let mut container_reports = Vec::new();
    for container in &built {
        let verify_legacy = work
            .path()
            .join("roundtrip")
            .join(&container.container.name);
        // The rebuilt container's directory index inherits the legacy tree's
        // on-disk casing, which platform directory-case pinning can mix
        // between authored and current spellings. Retoc filters are
        // case-sensitive, so the roundtrip must request every package by the
        // rebuilt container's OWN materialized spelling, resolved by package
        // ID and failing closed on any missing identity.
        let (_, rebuilt_entries) = retoc.package_entries(&container.rebuilt_utoc)?;
        let roundtrip_requests =
            composite_roundtrip_requests(&rebuilt_entries, &container.container.packages)?;
        // The roundtrip runs through the same byte-proven extraction as the
        // source lane: the exclusive view (rebuilt containers, provider, and
        // global only) is the byte truth — the layered stock store can hand
        // back its own bulk chunks for package IDs the current game also
        // carries — while the layered view only contributes proven
        // import-name resolution and the guarded conversion fallback.
        let rebuilt_utocs = built
            .iter()
            .map(|built_container| built_container.rebuilt_utoc.clone())
            .collect::<Vec<_>>();
        extract_source_composite_packages_with_fallback(
            &retoc,
            verify_view.path(),
            current_view.path(),
            &rebuilt_utocs,
            &verify_legacy,
            &roundtrip_requests,
            &format!("composite roundtrip {}", container.container.name),
        )?;
        let payload = verify_preserved_export_payloads(
            &container.legacy,
            &verify_legacy,
            &work
                .path()
                .join("payload-verification")
                .join(&container.container.name),
        )?;
        let candidate_utoc = output_directory.join(&container.container.relative_utoc);
        let candidate_ucas = candidate_utoc.with_extension("ucas");
        let candidate_pak = candidate_utoc.with_extension("pak");
        copy_file(&container.rebuilt_utoc, &candidate_utoc)?;
        copy_file(&container.rebuilt_ucas, &candidate_ucas)?;
        copy_file(&container.rebuilt_pak, &candidate_pak)?;
        container_reports.push(json!({
            "name": container.container.name,
            "packageCount": container.container.packages.len(),
            "packages": container.package_rows,
            "bodySetupRepairs": container.body_setup_repairs,
            "expectedImportedPackageSets": container.expected_imports,
            "payloadEquivalence": payload,
            "rebuilt": {
                "utocSha256": sha256_file(&candidate_utoc)?,
                "ucasSha256": sha256_file(&candidate_ucas)?,
                "pakSha256": sha256_file(&candidate_pak)?,
                "retocVerified": true,
                "inventoryPreserved": true,
            }
        }));
    }

    let identity_alias_report = if let Some(recovery) = &identity_recovery
        && !recovery.aliases.is_empty()
    {
        let provider = recovery
            .provider
            .as_ref()
            .context("identity alias provider is missing for persistent aliases")?;
        let mut alias_packages = recovery
            .aliases
            .iter()
            .map(|alias| {
                (
                    alias.target_package.clone(),
                    alias.target_package.path.clone(),
                )
            })
            .collect::<Vec<_>>();
        alias_packages.sort_by_key(|(package, _)| package.package_id);
        alias_packages.dedup_by_key(|(package, _)| package.package_id);
        let alias_roundtrip = work.path().join("roundtrip").join(&provider.provider_name);
        extract_composite_packages_exact(
            &retoc,
            verify_view.path(),
            &alias_roundtrip,
            &alias_packages,
            "identity alias provider roundtrip",
        )?;
        let payload = verify_preserved_export_payloads(
            &provider.legacy_root,
            &alias_roundtrip,
            &work
                .path()
                .join("payload-verification")
                .join(&provider.provider_name),
        )?;
        let candidate_utoc = output_directory.join(&provider.relative_utoc);
        let candidate_ucas = candidate_utoc.with_extension("ucas");
        let candidate_pak = candidate_utoc.with_extension("pak");
        copy_file(&provider.provider_utoc, &candidate_utoc)?;
        copy_file(&provider.provider_ucas, &candidate_ucas)?;
        copy_file(&provider.provider_pak, &candidate_pak)?;
        Some(json!({
            "name": provider.provider_name,
            "relativeUtoc": provider.relative_utoc,
            "packageCount": alias_packages.len(),
            "aliases": recovery.aliases,
            "payloadEquivalence": payload,
            "rebuilt": {
                "utocSha256": sha256_file(&candidate_utoc)?,
                "ucasSha256": sha256_file(&candidate_ucas)?,
                "pakSha256": sha256_file(&candidate_pak)?,
                "retocVerified": true,
                "inventoryPreserved": true,
            }
        }))
    } else {
        None
    };

    let report_path = output_directory.join("composite-package-update-report.json");
    let report = json!({
        "schema": "obr-composite-package-update-report",
        "version": 1,
        "implementation": "native-rust",
        "adapter": COMPOSITE_PACKAGE_REBASE_ADAPTER,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "status": "candidate_ready_for_runtime_test",
        "structurallyVerified": true,
        "runtimeVerified": false,
        "source": {"inputType": input_type, "inputSha256": input_hash},
        "identity": {
            "containerCount": inspection.containers.len(),
            "packageCount": inspection.packages.len(),
            "recoveredAliasPackageCount": identity_recovery
                .as_ref()
                .map(|recovery| recovery.aliases.iter().map(|alias| alias.target_package.package_id).collect::<BTreeSet<_>>().len())
                .unwrap_or(0),
            "recoveredStaleDependencyRebindCount": identity_recovery
                .as_ref()
                .map(|recovery| recovery.donor_rebinds.len())
                .unwrap_or(0),
            "classDrivenSystemWideRules": true,
            "modSpecificWhitelistUsed": false,
            "packagePathsAndIdsVerified": true,
            "packageImportSetsVerified": true,
            "authoredPayloadsRoundtripVerified": true,
        },
        "fixApis": [
            "zen-exact-dependency-extraction-v1",
            "zen-dependency-preservation-v1",
            "identity-and-export-topology-current-template-import-rebase-v1",
            "serialized-role-current-template-import-rebase-v1",
            "single-resolved-dependency-public-export-rebase-v2",
            "package-store-decoder-placeholder-repair-v2",
            "package-root-public-export-identity-alias-v1",
            "blueprint-serialized-alias-role-proof-v1",
            "optional-secondary-blueprint-component-suppression-v1"
        ],
        "unreal": {
            "containers": container_reports,
            "identityAliasProvider": identity_alias_report,
            "staleDependencyRebinds": identity_recovery
                .as_ref()
                .map(|recovery| recovery.donor_rebinds.clone())
                .unwrap_or_default(),
        },
        "output": {"directory": output_directory, "archive": output_archive},
        "verification": {
            "sourceContainersVerified": true,
            "rebuiltContainersVerified": true,
            "packagePathsAndIdsPreservedOrCanonicallyRebased": true,
            "packageImportSetsMatchApprovedGraph": true,
            "roundtripFileSetsPreserved": true,
            "approvedExportPayloadMigrationPreserved": true,
            "productionRuntimeGateRequired": true
        }
    });
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    stage(
        callback,
        5,
        "Creating portable composite-package candidate archive",
    );
    create_zip_from_paths(
        &output_archive,
        &output_directory,
        std::slice::from_ref(&output_directory),
    )?;
    if !output_archive.is_file() {
        bail!("composite candidate archive was not created");
    }
    stage(
        callback,
        6,
        "Composite candidate complete; shipping-game test still required",
    );
    Ok(UpdateOutcome {
        adapter: COMPOSITE_PACKAGE_REBASE_ADAPTER.to_owned(),
        output_directory,
        output_archive,
        report_path,
        package_count: inspection.packages.len()
            + identity_recovery
                .as_ref()
                .map(|recovery| {
                    recovery
                        .aliases
                        .iter()
                        .map(|alias| alias.target_package.package_id)
                        .collect::<BTreeSet<_>>()
                        .len()
                })
                .unwrap_or(0),
    })
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

    let work = tempfile::Builder::new()
        .prefix("obr-additive-static-mesh-update-")
        .tempdir()?;
    let staged = work.path().join("source");
    let retoc = RetocTool::materialize()?;
    stage(
        callback,
        1,
        "Classifying StaticMesh packages by identity and export structure",
    );
    stage_input(&mod_input, &staged)?;
    let inspection = inspect_additive_static_mesh_staged(&staged, &game.root, &retoc)?;
    fs::create_dir_all(&output_directory)?;
    copy_tree(&staged, &output_directory)?;
    let mut results = Vec::new();
    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let legacy = root.join("legacy");
        let rebuilt = root.join("rebuilt");
        let verify_legacy = root.join("verify-legacy");
        let json_work = root.join("payload-verification");
        for dir in [&legacy, &rebuilt, &verify_legacy, &json_work] {
            fs::create_dir_all(dir)?;
        }
        let input_view = create_isolated_stock_view(&game.root)?;
        for source in [&container.utoc, &container.ucas, &container.pak] {
            copy_file(source, &input_view.path().join(source.file_name().unwrap()))?;
        }
        stage(
            callback,
            2,
            &format!(
                "Extracting structurally proven StaticMeshes from {}",
                container.name
            ),
        );
        extract_source_static_mesh_packages(
            &retoc,
            input_view.path(),
            &legacy,
            &container.packages,
            &format!("StaticMesh source extraction {}", container.name),
        )?;
        let extracted_uasset_count = WalkDir::new(&legacy)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_file()
                    && entry
                        .path()
                        .extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
            })
            .count();
        if extracted_uasset_count != container.packages.len() {
            bail!(
                "StaticMesh source extraction {} expected {} exact assets; found {extracted_uasset_count}",
                container.name,
                container.packages.len()
            );
        }
        let mut static_mesh_import_repairs = Vec::new();
        for package in &container.packages {
            let asset = find_additive_static_mesh_asset(&legacy, &package.path)?;
            let imports = inspect_static_mesh_asset(&asset)?;
            if imports
                .iter()
                .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
            {
                let source_row = container
                    .package_store
                    .iter()
                    .find(|entry| entry.package_id == package.package_id)
                    .context("StaticMesh source package store lost a package row")?;
                static_mesh_import_repairs.push(repair_static_mesh_imports(
                    &asset,
                    &source_row.imported_package_ids,
                    &inspection.target_dependencies,
                    &root
                        .join("import-repairs")
                        .join(package.package_id.to_string()),
                )?);
                let repaired_imports = inspect_static_mesh_asset(&asset)?;
                if repaired_imports
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
                {
                    bail!("{} retained unresolved imports after repair", package.path);
                }
            }
        }
        let body_setup_repairs = repair_legacy_body_setups(&legacy)?;
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
                .find(|entry| entry.package_id == original.package_id)
                .with_context(|| {
                    format!("rebuilt package store is missing {}", original.package_id)
                })?;
            if BTreeSet::from_iter(rebuilt_entry.imported_package_ids.iter().copied())
                != BTreeSet::from_iter(original.imported_package_ids.iter().copied())
            {
                bail!("rebuilt package imports changed for {}", original.path);
            }
        }
        let verify_view = create_isolated_stock_view(&game.root)?;
        for source in [&utoc, &ucas, &pak] {
            copy_file(
                source,
                &verify_view.path().join(source.file_name().unwrap()),
            )?;
        }
        extract_source_static_mesh_packages(
            &retoc,
            verify_view.path(),
            &verify_legacy,
            &container.packages,
            &format!("StaticMesh roundtrip {}", container.name),
        )?;
        let verify_uasset_count = WalkDir::new(&verify_legacy)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_file()
                    && entry
                        .path()
                        .extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
            })
            .count();
        if verify_uasset_count != container.packages.len() {
            bail!(
                "StaticMesh roundtrip {} expected {} exact assets; found {verify_uasset_count}",
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
        results.push(json!({"name":container.name,"packages":container.packages,"staticMeshImportRepairs":static_mesh_import_repairs,"bodySetupRepairs":body_setup_repairs,"payloadEquivalence":payload}));
    }
    let report_path = output_directory.join("static-mesh-update-report.json");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(
            &json!({"schema":"obr-static-mesh-update-report","version":2,"adapter":ADDITIVE_STATIC_MESH_ADAPTER,"status":"candidate_ready_for_runtime_test","structurallyVerified":true,"runtimeVerified":false,"sourceSha256":input_hash,"gamePackageInventory":inspection.target_utoc,"identity":{"existingGamePackageCount":inspection.target_package_imports.len(),"additivePackageCount":inspection.packages.len()-inspection.target_package_imports.len(),"classificationSource":"package-path-id-and-export-structure"},"containers":results,"verification":{"packagePathsAndIdsPreserved":true,"packageImportsPreserved":true,"bodySetupCookedPhysicsNormalized":true,"roundtripFileSetsPreserved":true,"productionRuntimeGateRequired":true}}),
        )?,
    )?;
    stage(
        callback,
        4,
        "Creating portable StaticMesh candidate archive",
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
        "StaticMesh candidate complete; shipping-game test still required",
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
    fn installed_collision_scan_names_incomplete_container_groups() {
        let temporary = tempfile::tempdir().unwrap();
        let mods = temporary.path().join("~mods");
        fs::create_dir_all(&mods).unwrap();
        fs::write(mods.join("Leftover_P.utoc"), b"junk").unwrap();
        let retoc = RetocTool::materialize().unwrap();
        let error = ensure_no_installed_replacement_collisions(temporary.path(), &[], &retoc, &[])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("incomplete IoStore container group"),
            "{error}"
        );
        assert!(error.contains("Leftover_P.utoc"), "{error}");
        assert!(error.contains("missing: ucas"), "{error}");
    }

    #[test]
    fn resolves_sync_map_directory_alias_by_unique_object_leaf() {
        let records = [Record {
            kind: "ARMO".to_owned(),
            form_id: 0x0100_0800,
            flags: 0,
            subrecords: vec![crate::tes4::Subrecord {
                kind: "EDID".to_owned(),
                data: b"ArenaHelmet\0".to_vec(),
            }],
        }];
        let owned = records.iter().collect::<Vec<_>>();
        let entries = [SyncMapEntry {
            key: "000800".to_owned(),
            local_form_id: "0x000800".to_owned(),
            object_path: "/Game/Forms/items/armor/ArenaHelmet.ArenaHelmet".to_owned(),
            package_path: "/Game/Forms/items/armor/ArenaHelmet".to_owned(),
        }];
        let packages =
            vec!["../../../OblivionRemastered/Content/Forms/Armor/ArenaHelmet.uasset".to_owned()];
        let result = resolve_sync_map_entries(&entries, &owned, &packages).unwrap();
        assert_eq!(result[0].resolution, "unique-object-leaf");
        assert_eq!(result[0].editor_id.as_deref(), Some("ArenaHelmet"));
        assert_eq!(
            result[0].rebuilt_package_path,
            "/Game/Forms/Armor/ArenaHelmet"
        );
        assert!(result[0].directory_alias_allowed);
    }

    #[test]
    fn allows_distinct_sync_map_form_ids_to_share_one_rebuilt_package() {
        let records = [
            Record {
                kind: "ARMO".to_owned(),
                form_id: 0x0100_08F1,
                flags: 0,
                subrecords: vec![crate::tes4::Subrecord {
                    kind: "EDID".to_owned(),
                    data: b"FinePD\0".to_vec(),
                }],
            },
            Record {
                kind: "ARMO".to_owned(),
                form_id: 0x0100_08F2,
                flags: 0,
                subrecords: vec![crate::tes4::Subrecord {
                    kind: "EDID".to_owned(),
                    data: b"RoughPD\0".to_vec(),
                }],
            },
        ];
        let owned = records.iter().collect::<Vec<_>>();
        let entries = [
            SyncMapEntry {
                key: "0008F1".to_owned(),
                local_form_id: "0x0008F1".to_owned(),
                object_path: "/Game/Forms/items/armor/Offhand_Weapon.Offhand_Weapon".to_owned(),
                package_path: "/Game/Forms/items/armor/Offhand_Weapon".to_owned(),
            },
            SyncMapEntry {
                key: "0008F2".to_owned(),
                local_form_id: "0x0008F2".to_owned(),
                object_path: "/Game/Forms/items/armor/Offhand_Weapon.Offhand_Weapon".to_owned(),
                package_path: "/Game/Forms/items/armor/Offhand_Weapon".to_owned(),
            },
        ];
        let packages = vec!["../../../Content/Forms/items/armor/Offhand_Weapon.uasset".to_owned()];

        let result = resolve_sync_map_entries(&entries, &owned, &packages).unwrap();

        assert_eq!(result.len(), 2);
        assert!(
            result
                .iter()
                .all(|entry| entry.rebuilt_package_path == "/Game/Forms/items/armor/Offhand_Weapon")
        );
        assert!(
            result
                .iter()
                .all(|entry| entry.resolution == "exact-package-path")
        );
        assert!(result.iter().all(|entry| !entry.directory_alias_allowed));
        assert_eq!(result[0].editor_id.as_deref(), Some("FinePD"));
        assert_eq!(result[1].editor_id.as_deref(), Some("RoughPD"));
    }

    #[test]
    fn refuses_duplicate_sync_map_form_ids_across_different_packages() {
        let records = [Record {
            kind: "ARMO".to_owned(),
            form_id: 0x0100_08F1,
            flags: 0,
            subrecords: Vec::new(),
        }];
        let owned = records.iter().collect::<Vec<_>>();
        let entries = [
            SyncMapEntry {
                key: "0008F1".to_owned(),
                local_form_id: "0x0008F1".to_owned(),
                object_path: "/Game/Forms/items/armor/Offhand_Weapon.Offhand_Weapon".to_owned(),
                package_path: "/Game/Forms/items/armor/Offhand_Weapon".to_owned(),
            },
            SyncMapEntry {
                key: "010008F1".to_owned(),
                local_form_id: "0x0008F1".to_owned(),
                object_path: "/Game/Forms/items/armor/Other_Weapon.Other_Weapon".to_owned(),
                package_path: "/Game/Forms/items/armor/Other_Weapon".to_owned(),
            },
        ];
        let packages = vec![
            "../../../Content/Forms/items/armor/Offhand_Weapon.uasset".to_owned(),
            "../../../Content/Forms/items/armor/Other_Weapon.uasset".to_owned(),
        ];

        let error = resolve_sync_map_entries(&entries, &owned, &packages).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("multiple SyncMap entries reference plugin-owned ESP FormID 0x0008F1")
        );
    }

    #[test]
    fn refuses_ambiguous_sync_map_object_leaf() {
        let records = [Record {
            kind: "ARMO".to_owned(),
            form_id: 0x0100_0800,
            flags: 0,
            subrecords: Vec::new(),
        }];
        let owned = records.iter().collect::<Vec<_>>();
        let entries = [SyncMapEntry {
            key: "000800".to_owned(),
            local_form_id: "0x000800".to_owned(),
            object_path: "/Game/Forms/items/armor/ArenaHelmet.ArenaHelmet".to_owned(),
            package_path: "/Game/Forms/items/armor/ArenaHelmet".to_owned(),
        }];
        let packages = vec![
            "../../../OblivionRemastered/Content/Forms/Armor/ArenaHelmet.uasset".to_owned(),
            "../../../OblivionRemastered/Content/Alternate/ArenaHelmet.uasset".to_owned(),
        ];
        let error = resolve_sync_map_entries(&entries, &owned, &packages).unwrap_err();
        assert!(error.to_string().contains("ambiguous across 2"));
    }
    #[test]
    fn portable_archive_name_preserves_dots_and_timestamp() {
        let directory = Path::new(r"C:\tmp\RAO-1.0-current-candidate-20260713-225545");
        assert_eq!(
            portable_archive_path(directory).unwrap(),
            PathBuf::from(r"C:\tmp\RAO-1.0-current-candidate-20260713-225545.zip")
        );
    }

    #[test]
    fn logical_publication_boundary_grants_only_mapped_iostore_payload_ownership() {
        let plan = crate::install_plan::InstallPlan {
            api: crate::install_plan::INSTALL_PLAN_API,
            evidence: crate::install_plan::LayoutEvidence::Canonical,
            mappings: vec![
                crate::install_plan::InstallMapping {
                    physical_source: PathBuf::from("Wrapper/Data/Fixture.esp"),
                    logical_destination: PathBuf::from("Content/Dev/ObvData/Data/Fixture.esp"),
                    priority: 0,
                    scope: crate::install_plan::MappingScope::Required,
                },
                crate::install_plan::InstallMapping {
                    physical_source: PathBuf::from("Wrapper/Paks/Fixture.utoc"),
                    logical_destination: PathBuf::from("Content/Paks/~mods/Fixture.utoc"),
                    priority: 0,
                    scope: crate::install_plan::MappingScope::Required,
                },
            ],
            choice_groups: Vec::new(),
            unmapped_sources: vec![PathBuf::from("docs/readme.txt")],
        };

        let owned =
            nested_adapter_owns_logical_destinations(&plan, "native-additive-syncmap-v1").unwrap();
        assert_eq!(
            owned,
            BTreeSet::from([PathBuf::from("Content/Paks/~mods/Fixture.utoc")])
        );
        assert!(nested_adapter_owns_logical_destinations(&plan, "unknown-adapter").is_err());
    }
}
