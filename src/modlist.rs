use crate::archive::{sha256_bytes, sha256_file};
use crate::dependencies::game_is_running;
use crate::engine::{UpdateRequest, run_update};
use crate::game::validate_game_install;
use crate::preflight::{PreflightRequest, analyze_with_progress, stable_signature};
use crate::replacement::ARMOR_REPLACEMENT_ADAPTER;
use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const REPORT_SCHEMA: &str = "obr-modlist-batch-report";
const REPORT_VERSION: u32 = 3;

#[derive(Clone, Debug)]
pub struct ModlistRequest {
    pub game_root: PathBuf,
    pub backup_parent: PathBuf,
    pub dependency_inputs: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ModlistOutcome {
    pub backup_directory: PathBuf,
    pub report_path: PathBuf,
    pub scanned: usize,
    pub updated: usize,
    pub already_converted: usize,
    pub unsupported: usize,
    pub skipped: usize,
    pub failed: usize,
}

pub type ModlistProgressCallback<'a> = dyn FnMut(usize, usize, &str) + Send + 'a;

#[derive(Clone, Debug)]
struct InstalledContainer {
    relative_utoc: PathBuf,
    utoc: PathBuf,
    ucas: PathBuf,
    pak: PathBuf,
}

#[derive(Clone, Debug)]
struct IncompleteContainer {
    relative_stem: PathBuf,
    missing: Vec<String>,
}

#[derive(Clone, Debug)]
enum InventoryEntry {
    Complete(InstalledContainer),
    Incomplete(IncompleteContainer),
}

impl InventoryEntry {
    fn sort_key(&self) -> String {
        match self {
            Self::Complete(container) => path_for_report(&container.relative_utoc),
            Self::Incomplete(container) => path_for_report(&container.relative_stem),
        }
        .to_ascii_lowercase()
    }
}

#[derive(Default)]
struct ContainerGroup {
    relative_stem: PathBuf,
    utoc: Option<PathBuf>,
    ucas: Option<PathBuf>,
    pak: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchCounts {
    scanned: usize,
    complete_container_triples: usize,
    incomplete_container_sets: usize,
    updated: usize,
    already_converted: usize,
    unsupported: usize,
    skipped: usize,
    failed: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchEntry {
    container: String,
    status: String,
    adapter: Option<String>,
    package_count: usize,
    preflight_signature: Option<String>,
    preflight_report: Option<String>,
    original_sha256: BTreeMap<String, String>,
    rebuilt_sha256: BTreeMap<String, String>,
    installed_sha256: BTreeMap<String, String>,
    backup_files: Vec<String>,
    decision_evidence: Vec<String>,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchReport {
    schema: String,
    version: u32,
    application_version: String,
    generated_at: String,
    status: String,
    structurally_verified_only: bool,
    runtime_verified: bool,
    risk_acknowledged: bool,
    source: BatchSource,
    current_game_fingerprint: CurrentGameFingerprint,
    counts: BatchCounts,
    entries: Vec<BatchEntry>,
    note: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchSource {
    mods_root: String,
    backup_root: String,
    absolute_paths_included: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CurrentGameFingerprint {
    algorithm: String,
    combined_sha256: String,
    global_utoc_sha256: String,
    global_ucas_sha256: String,
    main_utoc_sha256: String,
    purpose: String,
}

#[derive(Clone, Debug)]
struct InstallRow {
    target: PathBuf,
    candidate: PathBuf,
    prepared: PathBuf,
    rollback: PathBuf,
    extension: String,
}

fn path_for_report(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn current_game_fingerprint(game_root: &Path) -> Result<CurrentGameFingerprint> {
    let paks = game_root.join(r"OblivionRemastered\Content\Paks");
    let global_utoc_sha256 = sha256_file(&paks.join("global.utoc"))?;
    let global_ucas_sha256 = sha256_file(&paks.join("global.ucas"))?;
    let main_utoc_sha256 = sha256_file(&paks.join("OblivionRemastered-Windows.utoc"))?;
    let combined_sha256 = sha256_bytes(
        format!(
            "global.utoc={global_utoc_sha256}\nglobal.ucas={global_ucas_sha256}\nmain.utoc={main_utoc_sha256}\n"
        )
        .as_bytes(),
    );
    Ok(CurrentGameFingerprint {
        algorithm: "sha256".to_owned(),
        combined_sha256,
        global_utoc_sha256,
        global_ucas_sha256,
        main_utoc_sha256,
        purpose: "Binds already-converted decisions to the currently installed game container metadata. A changed fingerprint forces a fresh rebuild and semantic no-op evaluation.".to_owned(),
    })
}

fn armor_semantic_noop_evidence(
    adapter: &str,
    report_path: &Path,
    game_fingerprint: &CurrentGameFingerprint,
) -> Result<Option<Vec<String>>> {
    if adapter != ARMOR_REPLACEMENT_ADAPTER {
        return Ok(None);
    }
    let report: Value = serde_json::from_slice(&fs::read(report_path)?)?;
    if report["schema"] != "obr-armor-replacement-update-report"
        || report["version"].as_u64().unwrap_or_default() < 6
        || report["adapter"] != ARMOR_REPLACEMENT_ADAPTER
        || report["structurallyVerified"] != true
        || report["target"]["globalUtocSha256"] != game_fingerprint.global_utoc_sha256
        || report["target"]["globalUcasSha256"] != game_fingerprint.global_ucas_sha256
        || report["target"]["gamePackageInventorySha256"] != game_fingerprint.main_utoc_sha256
    {
        return Ok(None);
    }
    let identity = &report["identity"];
    let aggregate_noop = identity["currentGamePathsAndPackageIdsMatched"] == true
        && identity["payloadMutationCount"].as_u64() == Some(0)
        && identity["retiredPhysicsAssetReferenceRepairCount"].as_u64() == Some(0)
        && identity["splitPackageImportCount"].as_u64() == Some(0)
        && identity["obsoleteSourceDependencyCount"].as_u64() == Some(0)
        && identity["auxiliaryImportFallbackCount"].as_u64() == Some(0)
        && identity["sourceExportPayloadsPreserved"] == true
        && identity["sourceSidecarsBytePreserved"] == true
        && identity["approvedPayloadMigrationRoundtripPreserved"] == true;
    let verification = &report["verification"];
    let verification_passed = verification["sourceContainersVerified"] == true
        && verification["rebuiltContainersVerified"] == true
        && verification["packagePathsAndIdsPreserved"] == true
        && verification["exportPayloadsPreserved"] == true
        && verification["sidecarsBytePreserved"] == true
        && verification["roundtripFileSetsPreserved"] == true
        && verification["approvedPayloadMigrationRoundtripPreserved"] == true;
    if !aggregate_noop || !verification_passed {
        return Ok(None);
    }
    let replacement_count = identity["replacementPackageCount"]
        .as_u64()
        .context("armor report has no replacementPackageCount")?
        as usize;
    let repairs = report["unreal"]["containers"]
        .as_array()
        .context("armor report has no container list")?
        .iter()
        .flat_map(|container| {
            container["materialImportRepairs"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .collect::<Vec<_>>();
    if repairs.len() != replacement_count
        || repairs.iter().any(|repair| {
            repair["retiredPhysicsAssetImportCount"].as_u64() != Some(0)
                || repair["staleCreateDependenciesRemoved"].as_u64() != Some(0)
                || repair["splitPackageImportCount"].as_u64() != Some(0)
                || repair["auxiliaryImportCount"].as_u64() != Some(0)
                || repair["missingSourceImportedPackageIds"]
                    .as_array()
                    .is_none_or(|ids| !ids.is_empty())
                || repair["sourceImportedPackageIds"] != repair["targetImportedPackageIds"]
                || repair["exportsByteIdentical"] != true
                || repair["uexpByteIdentical"] != true
        })
    {
        return Ok(None);
    }
    let tombstones = identity["alreadyRetiredPhysicsAssetTombstoneCount"]
        .as_u64()
        .unwrap_or_default();
    Ok(Some(vec![
        "The fresh armor conversion was a semantic no-op: zero payload mutations, package splits, new PhysicsAsset retirements, obsolete dependencies, or auxiliary fallbacks.".to_owned(),
        format!(
            "All {replacement_count} replacement packages already used the current game package IDs; {tombstones} structurally proven inactive PhysicsAsset tombstone(s) remained inactive."
        ),
        "Source exports and sidecars were byte-preserved through the verified rebuild roundtrip.".to_owned(),
    ]))
}

fn triple_hashes(
    container: &InstalledContainer,
    candidate_root: Option<&Path>,
) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    for (extension, installed) in [
        ("utoc", &container.utoc),
        ("ucas", &container.ucas),
        ("pak", &container.pak),
    ] {
        let path = if let Some(root) = candidate_root {
            root.join(
                installed
                    .file_name()
                    .context("installed container file has no filename")?,
            )
        } else {
            installed.to_path_buf()
        };
        if !path.is_file() {
            bail!("{extension} file is missing from the triple hash comparison");
        }
        hashes.insert(extension.to_owned(), sha256_file(&path)?);
    }
    Ok(hashes)
}

fn safe_leaf(path: &Path) -> String {
    let mut value = path_for_report(path)
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    while value.contains("--") {
        value = value.replace("--", "-");
    }
    let value = value.trim_matches('-');
    if value.is_empty() {
        "container".to_owned()
    } else {
        value.chars().take(120).collect()
    }
}

fn set_group_file(slot: &mut Option<PathBuf>, path: PathBuf, label: &str) -> Result<()> {
    if let Some(previous) = slot {
        bail!(
            "duplicate {label} files for one installed container: {} and {}",
            previous.display(),
            path.display()
        );
    }
    *slot = Some(path);
    Ok(())
}

fn discover_inventory(mods_root: &Path) -> Result<Vec<InventoryEntry>> {
    let mut groups = BTreeMap::<String, ContainerGroup>::new();
    for entry in WalkDir::new(mods_root).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "the installed modlist contains a filesystem link, which is unsafe for batch replacement: {}",
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
        if !matches!(extension.as_str(), "utoc" | "ucas" | "pak") {
            continue;
        }
        let relative = entry.path().strip_prefix(mods_root)?;
        let relative_stem = relative.with_extension("");
        let key = path_for_report(&relative_stem).to_ascii_lowercase();
        let group = groups.entry(key).or_insert_with(|| ContainerGroup {
            relative_stem,
            ..ContainerGroup::default()
        });
        match extension.as_str() {
            "utoc" => set_group_file(&mut group.utoc, entry.path().to_path_buf(), "UTOC")?,
            "ucas" => set_group_file(&mut group.ucas, entry.path().to_path_buf(), "UCAS")?,
            "pak" => set_group_file(&mut group.pak, entry.path().to_path_buf(), "PAK")?,
            _ => unreachable!(),
        }
    }

    let mut inventory = Vec::new();
    for (_, group) in groups {
        match (group.utoc, group.ucas, group.pak) {
            (Some(utoc), Some(ucas), Some(pak)) => {
                inventory.push(InventoryEntry::Complete(InstalledContainer {
                    relative_utoc: group.relative_stem.with_extension("utoc"),
                    utoc,
                    ucas,
                    pak,
                }));
            }
            (utoc, ucas, pak) => {
                let mut missing = Vec::new();
                if utoc.is_none() {
                    missing.push("UTOC".to_owned());
                }
                if ucas.is_none() {
                    missing.push("UCAS".to_owned());
                }
                if pak.is_none() {
                    missing.push("PAK".to_owned());
                }
                inventory.push(InventoryEntry::Incomplete(IncompleteContainer {
                    relative_stem: group.relative_stem,
                    missing,
                }));
            }
        }
    }
    inventory.sort_by_key(InventoryEntry::sort_key);
    Ok(inventory)
}

fn write_report(path: &Path, report: &BatchReport) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(report)?)
        .with_context(|| format!("writing batch report {}", path.display()))?;
    Ok(())
}

fn copy_verified(source: &Path, destination: &Path) -> Result<String> {
    fs::create_dir_all(
        destination
            .parent()
            .context("copy destination has no parent")?,
    )?;
    fs::copy(source, destination)
        .with_context(|| format!("copying {} to {}", source.display(), destination.display()))?;
    let source_hash = sha256_file(source)?;
    let destination_hash = sha256_file(destination)?;
    if source_hash != destination_hash {
        bail!(
            "copied file hash mismatch for {}",
            destination
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );
    }
    Ok(source_hash)
}

fn restore_swap(rows: &[InstallRow]) -> Result<()> {
    let mut errors = Vec::new();
    for row in rows {
        if row.rollback.is_file() {
            if row.target.exists() {
                if let Err(error) = fs::remove_file(&row.target) {
                    errors.push(format!(
                        "removing replacement {}: {error}",
                        row.target.display()
                    ));
                    continue;
                }
            }
            if let Err(error) = fs::rename(&row.rollback, &row.target) {
                errors.push(format!("restoring {}: {error}", row.target.display()));
            }
        }
        if row.prepared.exists() {
            let _ = fs::remove_file(&row.prepared);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("rollback encountered errors: {}", errors.join("; "))
    }
}

fn install_candidate(
    mods_root: &Path,
    backup_root: &Path,
    container: &InstalledContainer,
    candidate_root: &Path,
) -> Result<(
    BTreeMap<String, String>,
    BTreeMap<String, String>,
    Vec<String>,
)> {
    // Keep the original triple intact until the candidate and its backup have both been verified.
    let relative_ucas = container.relative_utoc.with_extension("ucas");
    let relative_pak = container.relative_utoc.with_extension("pak");
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_millis()
    );
    let sources = [
        (
            "utoc",
            &container.utoc,
            candidate_root.join(container.utoc.file_name().context("UTOC has no filename")?),
            container.relative_utoc.clone(),
        ),
        (
            "ucas",
            &container.ucas,
            candidate_root.join(container.ucas.file_name().context("UCAS has no filename")?),
            relative_ucas,
        ),
        (
            "pak",
            &container.pak,
            candidate_root.join(container.pak.file_name().context("PAK has no filename")?),
            relative_pak,
        ),
    ];
    let mut rows = Vec::new();
    let mut original_hashes = BTreeMap::new();
    let mut backup_files = Vec::new();
    for (index, (extension, target, candidate, relative)) in sources.into_iter().enumerate() {
        if !target.is_file() || !candidate.is_file() {
            bail!("source or candidate {extension} file is missing");
        }
        let expected_target = mods_root.join(&relative);
        if fs::canonicalize(target)? != fs::canonicalize(&expected_target)? {
            bail!("installed target escaped the validated ~mods inventory");
        }
        let backup = backup_root.join("originals").join(&relative);
        let source_hash = copy_verified(target, &backup)?;
        original_hashes.insert(extension.to_owned(), source_hash);
        backup_files.push(path_for_report(
            backup.strip_prefix(backup_root).unwrap_or(&backup),
        ));
        let filename = target
            .file_name()
            .context("installed container file has no filename")?
            .to_string_lossy();
        let parent = target
            .parent()
            .context("installed container file has no parent")?;
        rows.push(InstallRow {
            target: target.to_path_buf(),
            candidate,
            prepared: parent.join(format!(".{filename}.obr-new-{nonce}-{index}")),
            rollback: parent.join(format!(".{filename}.obr-rollback-{nonce}-{index}")),
            extension: extension.to_owned(),
        });
    }

    for row in &rows {
        if row.prepared.exists() || row.rollback.exists() {
            bail!("batch transaction side file already exists; refusing to overwrite it");
        }
    }
    for row in &rows {
        if let Err(error) = copy_verified(&row.candidate, &row.prepared) {
            for cleanup in &rows {
                if cleanup.prepared.exists() {
                    let _ = fs::remove_file(&cleanup.prepared);
                }
            }
            return Err(error.context("preparing rebuilt files beside their installed targets"));
        }
    }

    let swap_result = (|| -> Result<BTreeMap<String, String>> {
        for row in &rows {
            fs::rename(&row.target, &row.rollback).with_context(|| {
                format!(
                    "moving original {} into rollback position",
                    row.target.display()
                )
            })?;
        }
        for row in &rows {
            fs::rename(&row.prepared, &row.target)
                .with_context(|| format!("installing rebuilt {}", row.target.display()))?;
        }
        let mut installed_hashes = BTreeMap::new();
        for row in &rows {
            let expected = sha256_file(&row.candidate)?;
            let actual = sha256_file(&row.target)?;
            if expected != actual {
                bail!(
                    "installed {} hash did not match the rebuilt candidate",
                    row.extension
                );
            }
            installed_hashes.insert(row.extension.clone(), actual);
        }
        Ok(installed_hashes)
    })();

    let installed_hashes = match swap_result {
        Ok(hashes) => hashes,
        Err(error) => {
            let rollback = restore_swap(&rows);
            return match rollback {
                Ok(()) => Err(error.context("candidate installation failed; originals restored")),
                Err(rollback_error) => Err(anyhow!(
                    "candidate installation failed: {error:#}; automatic rollback also failed: {rollback_error:#}; restore from the verified backup"
                )),
            };
        }
    };

    for row in &rows {
        if row.rollback.exists() {
            let _ = fs::remove_file(&row.rollback);
        }
    }
    Ok((original_hashes, installed_hashes, backup_files))
}

fn redact_error(error: &anyhow::Error, request: &ModlistRequest, work: &Path) -> String {
    let mut text = format!("{error:#}");
    let temp_root = std::env::temp_dir();
    for (path, replacement) in [
        (request.game_root.as_path(), "<GAME_ROOT>"),
        (request.backup_parent.as_path(), "<OUTPUT_ROOT>"),
        (work, "<BATCH_WORK>"),
        (temp_root.as_path(), "<TEMP>"),
    ] {
        let raw = path.to_string_lossy();
        if !raw.is_empty() {
            text = text.replace(raw.as_ref(), replacement);
        }
    }
    text
}

fn stage_container(container: &InstalledContainer, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for source in [&container.utoc, &container.ucas, &container.pak] {
        let target = destination.join(
            source
                .file_name()
                .context("installed container file has no filename")?,
        );
        copy_verified(source, &target)?;
    }
    Ok(())
}

fn process_container(
    request: &ModlistRequest,
    mods_root: &Path,
    backup_root: &Path,
    reports_root: &Path,
    game_fingerprint: &CurrentGameFingerprint,
    container: &InstalledContainer,
    index: usize,
    progress_base: usize,
    progress_total: usize,
    callback: &mut ModlistProgressCallback<'_>,
) -> BatchEntry {
    let relative = path_for_report(&container.relative_utoc);
    callback(
        progress_base + 2,
        progress_total,
        &format!("Inspecting installed container {relative}"),
    );
    let work = match tempfile::Builder::new()
        .prefix("obr-modlist-item-")
        .tempdir()
    {
        Ok(work) => work,
        Err(error) => {
            return BatchEntry {
                container: relative.clone(),
                status: "failed".to_owned(),
                adapter: None,
                package_count: 0,
                preflight_signature: None,
                preflight_report: None,
                original_sha256: BTreeMap::new(),
                rebuilt_sha256: BTreeMap::new(),
                installed_sha256: BTreeMap::new(),
                backup_files: Vec::new(),
                decision_evidence: Vec::new(),
                message: format!("Could not create isolated batch work area: {error}"),
            };
        }
    };
    let mut recorded_adapter = None;
    let mut recorded_package_count = 0;
    let mut recorded_signature = None;
    let mut recorded_preflight_report = None;
    let result = (|| -> Result<BatchEntry> {
        let source = work.path().join("source");
        stage_container(container, &source)?;
        callback(
            progress_base + 8,
            progress_total,
            &format!("Running guarded preflight for {relative}"),
        );
        let preflight = analyze_with_progress(
            &PreflightRequest {
                mod_input: source.clone(),
                game_root: Some(request.game_root.clone()),
                output_parent: Some(backup_root.to_path_buf()),
                connected_tools: request.dependency_inputs.clone(),
            },
            &mut |message| {
                callback(
                    progress_base + 12,
                    progress_total,
                    &format!("{relative}: {message}"),
                );
            },
        );
        let signature = stable_signature(&preflight);
        let preflight_name = format!(
            "{:03}-{}-preflight.json",
            index + 1,
            safe_leaf(&container.relative_utoc)
        );
        let preflight_path = reports_root.join(&preflight_name);
        fs::write(&preflight_path, serde_json::to_vec_pretty(&preflight)?)?;
        recorded_package_count = preflight
            .unreal_replacement_probe
            .as_ref()
            .map(|probe| probe.package_count)
            .unwrap_or(0);
        recorded_signature = Some(signature.clone());
        recorded_preflight_report = Some(path_for_report(
            preflight_path
                .strip_prefix(backup_root)
                .unwrap_or(&preflight_path),
        ));
        if !preflight.can_update {
            callback(
                progress_base + 100,
                progress_total,
                &format!(
                    "[UNSUPPORTED] {relative}: no proven adapter passed every gate. Installed files left unchanged; continuing."
                ),
            );
            return Ok(BatchEntry {
                container: relative.clone(),
                status: "skipped-unsupported".to_owned(),
                adapter: preflight.selected_adapter,
                package_count: recorded_package_count,
                preflight_signature: Some(signature.clone()),
                preflight_report: recorded_preflight_report.clone(),
                original_sha256: BTreeMap::new(),
                rebuilt_sha256: BTreeMap::new(),
                installed_sha256: BTreeMap::new(),
                backup_files: Vec::new(),
                decision_evidence: vec![
                    format!("Preflight signature {signature}"),
                    "No proven adapter passed every safety gate; installed files were not opened for replacement.".to_owned(),
                ],
                message: format!(
                    "{} No files were changed because no proven adapter passed every gate.",
                    preflight.status
                ),
            });
        }
        let adapter = preflight
            .selected_adapter
            .clone()
            .context("passing preflight did not select an adapter")?;
        recorded_adapter = Some(adapter.clone());
        let candidate_parent = work.path().join("candidate");
        fs::create_dir_all(&candidate_parent)?;
        callback(
            progress_base + 20,
            progress_total,
            &format!("Rebuilding {relative} with {adapter}"),
        );
        let outcome = run_update(
            UpdateRequest {
                adapter: adapter.clone(),
                mod_input: source,
                game_root: request.game_root.clone(),
                output_parent: candidate_parent,
                dependency_inputs: request.dependency_inputs.clone(),
                installed_collision_exclusions: vec![container.utoc.clone()],
                persist_settings: false,
            },
            &mut |step, total, message| {
                let update_progress = 20 + (step * 60 / total.max(1));
                callback(
                    progress_base + update_progress,
                    progress_total,
                    &format!("{relative}: {message}"),
                );
            },
        )?;
        let installed_before = triple_hashes(container, None)?;
        let rebuilt_for_current_game = triple_hashes(container, Some(&outcome.output_directory))?;
        let raw_triple_exact = installed_before == rebuilt_for_current_game;
        let semantic_noop =
            armor_semantic_noop_evidence(&adapter, &outcome.report_path, game_fingerprint)?;
        if raw_triple_exact || semantic_noop.is_some() {
            let fingerprint = game_fingerprint.combined_sha256.clone();
            let mut decision_evidence = vec![
                format!("Current game fingerprint: {fingerprint}"),
                "The mod was rebuilt from scratch against that current game fingerprint and passed every structural output gate.".to_owned(),
            ];
            if raw_triple_exact {
                decision_evidence.push(
                    "The rebuilt PAK, UCAS, and UTOC SHA-256 hashes exactly matched the installed triple."
                        .to_owned(),
                );
            } else if let Some(evidence) = semantic_noop {
                decision_evidence.extend(evidence);
                decision_evidence.push(
                    "Raw rebuilt hashes were recorded but were not used as semantic identity because verified UTOC/UCAS emission is not byte-stable across no-op rebuilds."
                        .to_owned(),
                );
            }
            decision_evidence.push(
                "No backup or overwrite was necessary because the installed mod was already semantically current."
                    .to_owned(),
            );
            callback(
                progress_base + 100,
                progress_total,
                &format!(
                    "Already converted for the current game: {relative} (fingerprint {})",
                    &fingerprint[..12]
                ),
            );
            return Ok(BatchEntry {
                container: relative.clone(),
                status: "already-converted-for-current-game".to_owned(),
                adapter: Some(adapter),
                package_count: outcome.package_count,
                preflight_signature: Some(signature),
                preflight_report: recorded_preflight_report.clone(),
                original_sha256: installed_before.clone(),
                rebuilt_sha256: rebuilt_for_current_game,
                installed_sha256: installed_before,
                backup_files: Vec::new(),
                decision_evidence,
                message: "Already converted for the currently installed game. The installed triple was left unchanged.".to_owned(),
            });
        }
        callback(
            progress_base + 85,
            progress_total,
            &format!("Backing up and replacing {relative}"),
        );
        let (original_sha256, installed_sha256, backup_files) =
            install_candidate(mods_root, backup_root, container, &outcome.output_directory)?;
        callback(
            progress_base + 100,
            progress_total,
            &format!("Updated {relative}; originals preserved in the batch backup"),
        );
        Ok(BatchEntry {
            container: relative.clone(),
            status: "updated".to_owned(),
            adapter: Some(adapter),
            package_count: outcome.package_count,
            preflight_signature: Some(signature),
            preflight_report: Some(path_for_report(
                preflight_path.strip_prefix(backup_root).unwrap_or(&preflight_path),
            )),
            original_sha256,
            rebuilt_sha256: rebuilt_for_current_game,
            installed_sha256,
            backup_files,
            decision_evidence: vec![
                format!(
                    "Current game fingerprint: {}",
                    game_fingerprint.combined_sha256
                ),
                "A fresh structurally verified candidate was rebuilt against the current game.".to_owned(),
                "Candidate hashes differed from the installed triple, so verified originals were backed up before replacement.".to_owned(),
                "Post-install PAK, UCAS, and UTOC hashes match the rebuilt candidate.".to_owned(),
            ],
            message: "Structurally verified candidate installed over the original container. In-game testing is still required.".to_owned(),
        })
    })();
    result.unwrap_or_else(|error| {
        callback(
            progress_base + 100,
            progress_total,
            &format!("Failed {relative}; see the batch report"),
        );
        BatchEntry {
            container: relative,
            status: "failed".to_owned(),
            adapter: recorded_adapter,
            package_count: recorded_package_count,
            preflight_signature: recorded_signature.clone(),
            preflight_report: recorded_preflight_report,
            original_sha256: BTreeMap::new(),
            rebuilt_sha256: BTreeMap::new(),
            installed_sha256: BTreeMap::new(),
            backup_files: Vec::new(),
            decision_evidence: vec![
                recorded_signature
                    .as_ref()
                    .map(|signature| format!("Preflight signature: {signature}"))
                    .unwrap_or_else(|| "Preflight did not complete.".to_owned()),
                "The workflow stopped before verified installation; no candidate was written over this container.".to_owned(),
            ],
            message: redact_error(&error, request, work.path()),
        }
    })
}

fn record_batch_status(counts: &mut BatchCounts, status: &str) {
    match status {
        "updated" => counts.updated += 1,
        "already-converted-for-current-game" => counts.already_converted += 1,
        "skipped-unsupported" => {
            counts.unsupported += 1;
            counts.skipped += 1;
        }
        "failed" => counts.failed += 1,
        _ => counts.skipped += 1,
    }
}

pub fn run_modlist_update(
    request: ModlistRequest,
    callback: &mut ModlistProgressCallback<'_>,
) -> Result<ModlistOutcome> {
    let game = validate_game_install(&request.game_root, "installed modlist batch update");
    if !game.valid {
        bail!(
            "game installation is incomplete: {}",
            game.missing.join(", ")
        );
    }
    if game_is_running() {
        bail!(
            "Oblivion Remastered or OBSE appears to be running. Close the game before overwriting installed mods."
        );
    }
    if !request.backup_parent.is_dir() {
        bail!("the selected backup/report output folder does not exist");
    }
    let mods_root = game.root.join(r"OblivionRemastered\Content\Paks\~mods");
    if !mods_root.is_dir() {
        bail!("the game ~mods directory does not exist");
    }
    let canonical_mods = fs::canonicalize(&mods_root)?;
    let canonical_backup_parent = fs::canonicalize(&request.backup_parent)?;
    if canonical_backup_parent.starts_with(&canonical_mods) {
        bail!("choose a backup/report output folder outside the active game ~mods directory");
    }

    callback(0, 1, "Scanning the installed ~mods directory");
    let inventory = discover_inventory(&mods_root)?;
    callback(0, 1, "Fingerprinting the current game container metadata");
    let game_fingerprint = current_game_fingerprint(&game.root)?;
    let complete_count = inventory
        .iter()
        .filter(|entry| matches!(entry, InventoryEntry::Complete(_)))
        .count();
    let incomplete_count = inventory.len() - complete_count;
    let backup_directory = request.backup_parent.join(format!(
        "OBR-Modlist-Backup-{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S-%3f")
    ));
    let reports_root = backup_directory.join("reports");
    fs::create_dir_all(&reports_root)?;
    let report_path = backup_directory.join("modlist-update-report.json");
    let mut report = BatchReport {
        schema: REPORT_SCHEMA.to_owned(),
        version: REPORT_VERSION,
        application_version: env!("CARGO_PKG_VERSION").to_owned(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        status: "running".to_owned(),
        structurally_verified_only: true,
        runtime_verified: false,
        risk_acknowledged: true,
        source: BatchSource {
            mods_root: "<GAME_ROOT>/OblivionRemastered/Content/Paks/~mods".to_owned(),
            backup_root: format!(
                "<OUTPUT_ROOT>/{}",
                backup_directory
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            ),
            absolute_paths_included: false,
        },
        current_game_fingerprint: game_fingerprint.clone(),
        counts: BatchCounts {
            scanned: inventory.len(),
            complete_container_triples: complete_count,
            incomplete_container_sets: incomplete_count,
            ..BatchCounts::default()
        },
        entries: Vec::new(),
        note: "Only containers that pass a proven adapter are overwritten. Unsupported gameplay, mechanic, blueprint, script, and other report-only containers are recorded as skipped-unsupported, left byte-identical, and do not stop later eligible containers from being processed. An already-converted result requires a fresh rebuild against the recorded current-game fingerprint plus either exact triple equality or an adapter-specific verified semantic no-op. Armor no-op proof requires zero payload mutations, package splits, new PhysicsAsset retirements, obsolete dependencies, and auxiliary fallbacks; exact current package IDs; and preserved exports/sidecars through roundtrip verification. Raw installed and rebuilt hashes are recorded separately because verified UTOC/UCAS emission is not byte-stable across no-op rebuilds. Every changed original triple is hash-verified in a backup outside ~mods before replacement. Structural verification does not prove runtime compatibility.".to_owned(),
    };
    write_report(&report_path, &report)?;

    let progress_total = inventory.len().saturating_mul(100).saturating_add(1);
    for (index, entry) in inventory.iter().enumerate() {
        let progress_base = index * 100;
        let result = match entry {
            InventoryEntry::Complete(container) => process_container(
                &request,
                &mods_root,
                &backup_directory,
                &reports_root,
                &game_fingerprint,
                container,
                index,
                progress_base,
                progress_total,
                callback,
            ),
            InventoryEntry::Incomplete(container) => {
                let relative = path_for_report(&container.relative_stem);
                callback(
                    progress_base + 100,
                    progress_total,
                    &format!(
                        "[INCOMPLETE] {relative}: missing container partners. Installed files left unchanged; continuing."
                    ),
                );
                BatchEntry {
                    container: relative,
                    status: "skipped-incomplete".to_owned(),
                    adapter: None,
                    package_count: 0,
                    preflight_signature: None,
                    preflight_report: None,
                    original_sha256: BTreeMap::new(),
                    rebuilt_sha256: BTreeMap::new(),
                    installed_sha256: BTreeMap::new(),
                    backup_files: Vec::new(),
                    decision_evidence: vec![
                        format!(
                            "Missing container partners: {}",
                            container.missing.join(", ")
                        ),
                        "Incomplete container sets are never modified.".to_owned(),
                    ],
                    message: format!(
                        "Missing {}. Incomplete container sets are never modified.",
                        container.missing.join(", ")
                    ),
                }
            }
        };
        record_batch_status(&mut report.counts, &result.status);
        report.entries.push(result);
        write_report(&report_path, &report)?;
    }
    report.status = if report.counts.failed > 0 {
        "complete-with-errors".to_owned()
    } else {
        "complete".to_owned()
    };
    write_report(&report_path, &report)?;
    callback(
        progress_total,
        progress_total,
        "Installed modlist batch workflow complete",
    );
    Ok(ModlistOutcome {
        backup_directory,
        report_path,
        scanned: report.counts.scanned,
        updated: report.counts.updated,
        already_converted: report.counts.already_converted,
        unsupported: report.counts.unsupported,
        skipped: report.counts.skipped,
        failed: report.counts.failed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn inventory_separates_complete_and_incomplete_container_sets() {
        let root = tempfile::tempdir().unwrap();
        for extension in ["utoc", "ucas", "pak"] {
            write(
                &root.path().join(format!("Armor_P.{extension}")),
                extension.as_bytes(),
            );
        }
        write(&root.path().join("nested/Texture_P.utoc"), b"utoc");
        write(&root.path().join("nested/Texture_P.ucas"), b"ucas");
        write(&root.path().join("ignored.txt"), b"not a container");

        let inventory = discover_inventory(root.path()).unwrap();
        assert_eq!(inventory.len(), 2);
        assert!(matches!(inventory[0], InventoryEntry::Complete(_)));
        match &inventory[1] {
            InventoryEntry::Incomplete(container) => assert_eq!(container.missing, ["PAK"]),
            _ => panic!("expected incomplete container"),
        }
    }

    #[test]
    fn unsupported_entry_is_counted_and_does_not_block_a_following_update() {
        let mut counts = BatchCounts::default();

        record_batch_status(&mut counts, "skipped-unsupported");
        record_batch_status(&mut counts, "updated");
        record_batch_status(&mut counts, "skipped-incomplete");

        assert_eq!(counts.unsupported, 1);
        assert_eq!(counts.updated, 1);
        assert_eq!(counts.skipped, 2);
        assert_eq!(counts.failed, 0);
    }

    #[test]
    fn armor_semantic_noop_requires_current_game_and_zero_mutations() {
        let root = tempfile::tempdir().unwrap();
        let report_path = root.path().join("armor-report.json");
        let fingerprint = CurrentGameFingerprint {
            algorithm: "sha256".to_owned(),
            combined_sha256: "combined".to_owned(),
            global_utoc_sha256: "global-utoc".to_owned(),
            global_ucas_sha256: "global-ucas".to_owned(),
            main_utoc_sha256: "main-utoc".to_owned(),
            purpose: "test".to_owned(),
        };
        let repair = serde_json::json!({
            "retiredPhysicsAssetImportCount": 0,
            "staleCreateDependenciesRemoved": 0,
            "splitPackageImportCount": 0,
            "auxiliaryImportCount": 0,
            "missingSourceImportedPackageIds": [],
            "sourceImportedPackageIds": [1, 2],
            "targetImportedPackageIds": [1, 2],
            "exportsByteIdentical": true,
            "uexpByteIdentical": true
        });
        let mut report = serde_json::json!({
            "schema": "obr-armor-replacement-update-report",
            "version": 6,
            "adapter": ARMOR_REPLACEMENT_ADAPTER,
            "structurallyVerified": true,
            "target": {
                "globalUtocSha256": "global-utoc",
                "globalUcasSha256": "global-ucas",
                "gamePackageInventorySha256": "main-utoc"
            },
            "identity": {
                "currentGamePathsAndPackageIdsMatched": true,
                "payloadMutationCount": 0,
                "retiredPhysicsAssetReferenceRepairCount": 0,
                "splitPackageImportCount": 0,
                "obsoleteSourceDependencyCount": 0,
                "auxiliaryImportFallbackCount": 0,
                "sourceExportPayloadsPreserved": true,
                "sourceSidecarsBytePreserved": true,
                "approvedPayloadMigrationRoundtripPreserved": true,
                "replacementPackageCount": 1,
                "alreadyRetiredPhysicsAssetTombstoneCount": 1
            },
            "verification": {
                "sourceContainersVerified": true,
                "rebuiltContainersVerified": true,
                "packagePathsAndIdsPreserved": true,
                "exportPayloadsPreserved": true,
                "sidecarsBytePreserved": true,
                "roundtripFileSetsPreserved": true,
                "approvedPayloadMigrationRoundtripPreserved": true
            },
            "unreal": { "containers": [{ "materialImportRepairs": [repair] }] }
        });
        fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(
            armor_semantic_noop_evidence(ARMOR_REPLACEMENT_ADAPTER, &report_path, &fingerprint)
                .unwrap()
                .is_some()
        );

        report["identity"]["payloadMutationCount"] = Value::Number(1_u64.into());
        fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(
            armor_semantic_noop_evidence(ARMOR_REPLACEMENT_ADAPTER, &report_path, &fingerprint)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn candidate_install_backs_up_and_transactionally_replaces_a_triple() {
        let root = tempfile::tempdir().unwrap();
        let mods = root.path().join("~mods");
        let candidate = root.path().join("candidate");
        let backup = root.path().join("backup");
        fs::create_dir_all(&mods).unwrap();
        fs::create_dir_all(&candidate).unwrap();
        let utoc = mods.join("Test_P.utoc");
        let ucas = mods.join("Test_P.ucas");
        let pak = mods.join("Test_P.pak");
        for (path, bytes) in [
            (&utoc, b"old-utoc".as_slice()),
            (&ucas, b"old-ucas"),
            (&pak, b"old-pak"),
        ] {
            write(path, bytes);
        }
        for (name, bytes) in [
            ("Test_P.utoc", b"new-utoc".as_slice()),
            ("Test_P.ucas", b"new-ucas"),
            ("Test_P.pak", b"new-pak"),
        ] {
            write(&candidate.join(name), bytes);
        }
        let container = InstalledContainer {
            relative_utoc: PathBuf::from("Test_P.utoc"),
            utoc: utoc.clone(),
            ucas: ucas.clone(),
            pak: pak.clone(),
        };

        let (_, installed, backups) =
            install_candidate(&mods, &backup, &container, &candidate).unwrap();

        assert_eq!(fs::read(&utoc).unwrap(), b"new-utoc");
        assert_eq!(fs::read(&ucas).unwrap(), b"new-ucas");
        assert_eq!(fs::read(&pak).unwrap(), b"new-pak");
        assert_eq!(
            fs::read(backup.join("originals/Test_P.utoc")).unwrap(),
            b"old-utoc"
        );
        assert_eq!(backups.len(), 3);
        assert_eq!(installed.len(), 3);
    }
}
