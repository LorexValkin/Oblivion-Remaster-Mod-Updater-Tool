use crate::archive::{
    MAX_ARCHIVE_DECLARED_BYTES, MAX_ARCHIVE_ENTRIES, SELECTED_METADATA_EXTRACTION_API, rar_entries,
    sha256_bytes, sha256_file,
};
use crate::dependencies::{
    DependencyCandidate, DependencyKind, installed_state, scan_dependencies,
};
use crate::game::{normalize_install_root, validate_game_install};
use crate::plugin::{
    ADDITIVE_CONTRACT_API, AdditiveContractReport, PLUGIN_MANIFEST_API, PluginSetReport,
    inspect_additive_contract_input, inspect_plugin_input_at_root,
};
use crate::replacement::{
    ADDITIVE_STATIC_MESH_ADAPTER, ARMOR_REPLACEMENT_ADAPTER, MIXED_ARMOR_REPLACEMENT_ADAPTER,
    ReplacementProbeSummary, TEXTURE_REPLACEMENT_ADAPTER, probe_additive_static_mesh_input,
    probe_input, probe_mixed_armor_input, probe_texture_input,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

pub const REPORT_SCHEMA: &str = "obr-mod-preflight-report";
pub const REPORT_VERSION: u32 = 4;
pub const MAX_SCAN_ENTRIES: usize = MAX_ARCHIVE_ENTRIES;
pub const MAX_DECLARED_BYTES: u64 = MAX_ARCHIVE_DECLARED_BYTES;

#[derive(Clone, Debug)]
pub struct PreflightRequest {
    pub mod_input: PathBuf,
    pub game_root: Option<PathBuf>,
    pub output_parent: Option<PathBuf>,
    pub connected_tools: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputIdentity {
    pub name: String,
    pub input_type: String,
    pub source_sha256: Option<String>,
    pub absolute_paths_included: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModInventory {
    pub classification: String,
    pub file_count: usize,
    pub directory_count: usize,
    pub link_count: usize,
    pub total_declared_bytes: u64,
    pub metadata_manifest_sha256: String,
    pub extension_counts: BTreeMap<String, usize>,
    pub plugin_counts: BTreeMap<String, usize>,
    pub sync_map_ini_count: usize,
    pub io_store_utoc_count: usize,
    pub complete_container_triple_count: usize,
    pub incomplete_container_count: usize,
    pub script_or_loader_file_count: usize,
    pub loose_file_count: usize,
    pub functional_or_unknown_loose_file_count: usize,
    pub candidate_mod_root_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_mod_root: Option<String>,
    pub sample_files: Vec<String>,
    pub scan_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolComponent {
    pub name: String,
    pub bytes: usize,
    pub sha256: String,
    pub portable_executable: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolStatus {
    pub id: String,
    pub display_name: String,
    pub source: String,
    pub status: String,
    pub required_for_selected_adapter: bool,
    pub candidate_count: usize,
    pub components: Vec<ToolComponent>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: String,
    pub status: String,
    pub blocking: bool,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub id: String,
    pub available: bool,
    pub evidence_level: String,
    pub description: String,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceReport {
    pub elapsed_ms: u128,
    pub scan_entry_limit: usize,
    pub metadata_only_archive_scan: bool,
    pub large_file_hashing_streamed: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StressReport {
    pub requested_runs: usize,
    pub completed_runs: usize,
    pub deterministic: bool,
    pub stable_signature: String,
    pub min_elapsed_ms: u128,
    pub max_elapsed_ms: u128,
    pub mean_elapsed_ms: u128,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightReport {
    pub schema: String,
    pub version: u32,
    pub generated_at: String,
    pub application_version: String,
    pub target_os: String,
    pub target_arch: String,
    pub mode: String,
    pub privacy_note: String,
    pub input: InputIdentity,
    pub inventory: Option<ModInventory>,
    pub game_valid: bool,
    pub game_discovery_source: Option<String>,
    pub game_missing_components: Vec<String>,
    pub tools: Vec<ToolStatus>,
    pub checks: Vec<CheckResult>,
    pub capabilities: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_compatibility: Option<PluginSetReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additive_contract: Option<AdditiveContractReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreal_replacement_probe: Option<ReplacementProbeSummary>,
    pub selected_adapter: Option<String>,
    pub can_update: bool,
    pub status: String,
    pub performance: PerformanceReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stress: Option<StressReport>,
}

#[derive(Default)]
struct InventoryBuilder {
    file_count: usize,
    directory_count: usize,
    link_count: usize,
    total_bytes: u64,
    rows: Vec<String>,
    extensions: BTreeMap<String, usize>,
    plugins: BTreeMap<String, usize>,
    sync_maps: usize,
    scripts: usize,
    loose: usize,
    functional_or_unknown_loose: usize,
    samples: Vec<String>,
    containers: BTreeMap<String, BTreeSet<String>>,
    data_roots: BTreeSet<String>,
    pak_roots: BTreeSet<String>,
    truncated: bool,
}

fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn normalized_path(raw: &str) -> String {
    raw.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_owned()
}

fn root_before(path: &str, marker: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let marker = marker.trim_start_matches('/');
    if lower.starts_with(marker) {
        return Some(".".to_owned());
    }
    let index = lower.find(&format!("/{marker}"))?;
    let root = path[..index].trim_matches('/');
    Some(if root.is_empty() { "." } else { root }.to_owned())
}

impl InventoryBuilder {
    fn observe_directory(&mut self) {
        self.directory_count += 1;
    }

    fn observe_link(&mut self) {
        self.link_count += 1;
    }

    fn observe_file(&mut self, raw_path: &str, bytes: u64) {
        if self.file_count >= MAX_SCAN_ENTRIES {
            self.truncated = true;
            return;
        }
        let path = normalized_path(raw_path);
        self.file_count += 1;
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.rows.push(format!("{path}\t{bytes}"));
        if self.samples.len() < 40 {
            self.samples.push(path.clone());
        }
        let extension = Path::new(&path)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("(none)")
            .to_ascii_lowercase();
        *self.extensions.entry(extension.clone()).or_default() += 1;
        if matches!(extension.as_str(), "esp" | "esm" | "esl") {
            *self.plugins.entry(extension.clone()).or_default() += 1;
        }
        let lower = path.to_ascii_lowercase();
        if extension == "ini" && lower.contains("/syncmap/") {
            self.sync_maps += 1;
        }
        if matches!(
            extension.as_str(),
            "dll" | "asi" | "lua" | "exe" | "bat" | "cmd" | "ps1" | "vbs" | "js"
        ) || lower.contains("/obse/")
            || lower.contains("/ue4ss/")
        {
            self.scripts += 1;
        }
        if let Some(root) = root_before(&path, "/content/dev/obvdata/data/") {
            self.data_roots.insert(root);
        }
        if let Some(root) = root_before(&path, "/content/paks/~mods/") {
            self.pak_roots.insert(root);
        }
        if matches!(extension.as_str(), "pak" | "ucas" | "utoc") {
            let stem = Path::new(&path).with_extension("");
            let key = normalized_path(&stem.to_string_lossy()).to_ascii_lowercase();
            self.containers.entry(key).or_default().insert(extension);
        } else if !(matches!(extension.as_str(), "esp" | "esm" | "esl")
            || extension == "ini" && lower.contains("/syncmap/"))
        {
            self.loose += 1;
            let file_name = Path::new(&path)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let documentation = matches!(
                extension.as_str(),
                "txt" | "md" | "rtf" | "pdf" | "png" | "jpg" | "jpeg" | "gif" | "webp"
            ) || matches!(
                file_name.as_str(),
                "readme" | "license" | "licence" | "notice" | "changelog"
            ) || (lower.starts_with("fomod/") || lower.contains("/fomod/"))
                && extension == "xml";
            if !documentation {
                self.functional_or_unknown_loose += 1;
            }
        }
    }

    fn finish(mut self) -> ModInventory {
        self.rows.sort();
        self.samples.sort();
        let mut digest = Sha256::new();
        for row in &self.rows {
            digest.update(row.as_bytes());
            digest.update(b"\n");
        }
        let metadata_manifest_sha256 = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let complete = self
            .containers
            .values()
            .filter(|extensions| {
                ["pak", "ucas", "utoc"]
                    .iter()
                    .all(|value| extensions.contains(*value))
            })
            .count();
        let incomplete = self.containers.len().saturating_sub(complete);
        let candidate_roots = self
            .data_roots
            .intersection(&self.pak_roots)
            .cloned()
            .collect::<Vec<_>>();
        let roots = candidate_roots.len();
        let candidate_mod_root = (roots == 1).then(|| candidate_roots[0].clone());
        let esp = *self.plugins.get("esp").unwrap_or(&0);
        let plugin_total = self.plugins.values().sum::<usize>();
        let has_plugins = plugin_total > 0;
        let classification = if roots == 1
            && esp == 1
            && plugin_total == 1
            && self.sync_maps == 1
            && complete > 0
            && incomplete == 0
            && self.scripts == 0
            && self.functional_or_unknown_loose == 0
        {
            "additive-syncmap-iostore"
        } else if self.scripts > 0 && !has_plugins && self.containers.is_empty() {
            "script-or-loader"
        } else if has_plugins && self.containers.is_empty() && self.scripts == 0 {
            "plugin-only"
        } else if !has_plugins && !self.containers.is_empty() && self.scripts == 0 {
            "unreal-container-only"
        } else if self.file_count > 0
            && (has_plugins || !self.containers.is_empty() || self.scripts > 0)
        {
            "mixed-mod"
        } else if self.file_count > 0 {
            "loose-files-or-unknown"
        } else {
            "empty"
        };
        ModInventory {
            classification: classification.to_owned(),
            file_count: self.file_count,
            directory_count: self.directory_count,
            link_count: self.link_count,
            total_declared_bytes: self.total_bytes,
            metadata_manifest_sha256,
            extension_counts: self.extensions,
            plugin_counts: self.plugins,
            sync_map_ini_count: self.sync_maps,
            io_store_utoc_count: self
                .containers
                .values()
                .filter(|extensions| extensions.contains("utoc"))
                .count(),
            complete_container_triple_count: complete,
            incomplete_container_count: incomplete,
            script_or_loader_file_count: self.scripts,
            loose_file_count: self.loose,
            functional_or_unknown_loose_file_count: self.functional_or_unknown_loose,
            candidate_mod_root_count: roots,
            candidate_mod_root,
            sample_files: self.samples,
            scan_truncated: self.truncated,
        }
    }
}

fn scan_directory(path: &Path) -> Result<ModInventory> {
    let mut builder = InventoryBuilder::default();
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry.with_context(|| format!("walking {}", path.display()))?;
        if entry.path() == path {
            continue;
        }
        let relative = entry.path().strip_prefix(path)?;
        if entry.file_type().is_dir() {
            builder.observe_directory();
        } else if entry.file_type().is_symlink() {
            builder.observe_link();
        } else if entry.file_type().is_file() {
            builder.observe_file(&relative.to_string_lossy(), entry.metadata()?.len());
        }
        if builder.truncated {
            break;
        }
    }
    Ok(builder.finish())
}

fn scan_zip(path: &Path) -> Result<ModInventory> {
    let mut archive = zip::ZipArchive::new(File::open(path)?)
        .with_context(|| format!("reading ZIP metadata for {}", path.display()))?;
    let mut builder = InventoryBuilder::default();
    for index in 0..archive.len() {
        if index >= MAX_SCAN_ENTRIES {
            builder.truncated = true;
            break;
        }
        let entry = archive.by_index(index)?;
        let enclosed = entry
            .enclosed_name()
            .filter(|value| safe_relative(value))
            .with_context(|| format!("ZIP contains unsafe path: {}", entry.name()))?;
        if entry.is_dir() {
            builder.observe_directory();
        } else {
            builder.observe_file(&enclosed.to_string_lossy(), entry.size());
        }
    }
    Ok(builder.finish())
}

fn scan_7z(path: &Path) -> Result<ModInventory> {
    let reader = sevenz_rust::SevenZReader::open(path, sevenz_rust::Password::empty())
        .with_context(|| format!("reading 7Z metadata for {}", path.display()))?;
    let mut builder = InventoryBuilder::default();
    for (index, entry) in reader.archive().files.iter().enumerate() {
        if index >= MAX_SCAN_ENTRIES {
            builder.truncated = true;
            break;
        }
        let relative = Path::new(entry.name());
        if !safe_relative(relative) {
            bail!("7Z contains unsafe path: {}", entry.name());
        }
        if entry.is_directory() {
            builder.observe_directory();
        } else {
            builder.observe_file(entry.name(), entry.size());
        }
    }
    Ok(builder.finish())
}

fn scan_rar(path: &Path) -> Result<ModInventory> {
    let entries = rar_entries(path)?;
    let mut builder = InventoryBuilder::default();
    for entry in entries {
        if entry.is_directory {
            builder.observe_directory();
        } else {
            builder.observe_file(&entry.path.to_string_lossy(), entry.unpacked_size);
        }
    }
    Ok(builder.finish())
}

fn scan_input(path: &Path) -> Result<ModInventory> {
    if path.is_dir() {
        return scan_directory(path);
    }
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "zip" => scan_zip(path),
        "7z" => scan_7z(path),
        "rar" => scan_rar(path),
        extension => bail!("unsupported mod input extension: {extension}"),
    }
}

fn candidate_count(candidates: &[DependencyCandidate], kind: DependencyKind) -> usize {
    candidates
        .iter()
        .filter(|candidate| candidate.kinds.contains(&kind))
        .count()
}

fn connected_components(
    candidates: &[DependencyCandidate],
    kind: DependencyKind,
) -> Vec<ToolComponent> {
    candidates
        .iter()
        .filter(|candidate| candidate.kinds.contains(&kind))
        .map(|candidate| ToolComponent {
            name: candidate
                .path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("connected-tool")
                .to_owned(),
            bytes: candidate
                .path
                .metadata()
                .map(|metadata| metadata.len() as usize)
                .unwrap_or(0),
            sha256: candidate
                .sha256
                .clone()
                .unwrap_or_else(|| "directory-payload".to_owned()),
            portable_executable: true,
        })
        .collect()
}

fn built_in_tool(
    id: &str,
    name: &str,
    fingerprints: Vec<(&'static str, usize, String, bool)>,
    required: bool,
) -> ToolStatus {
    let ready = fingerprints
        .iter()
        .all(|(_, bytes, _, portable_executable)| *bytes > 0 && *portable_executable);
    ToolStatus {
        id: id.to_owned(),
        display_name: name.to_owned(),
        source: "embedded".to_owned(),
        status: if ready { "ready" } else { "invalid" }.to_owned(),
        required_for_selected_adapter: required,
        candidate_count: usize::from(ready),
        components: fingerprints
            .into_iter()
            .map(|(name, bytes, sha256, portable_executable)| ToolComponent {
                name: name.to_owned(),
                bytes,
                sha256,
                portable_executable,
            })
            .collect(),
    }
}

fn check(
    id: &str,
    passed: bool,
    blocking: bool,
    pass: impl Into<String>,
    fail: impl Into<String>,
    remediation: Option<&str>,
) -> CheckResult {
    CheckResult {
        id: id.to_owned(),
        status: if passed { "pass" } else { "fail" }.to_owned(),
        blocking: blocking && !passed,
        message: if passed { pass.into() } else { fail.into() },
        remediation: (!passed).then(|| remediation.map(str::to_owned)).flatten(),
    }
}

fn input_type(path: &Path) -> String {
    if path.is_dir() {
        "directory".to_owned()
    } else {
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("file")
            .to_ascii_lowercase()
    }
}

fn existing_absolute(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn output_isolated(request: &PreflightRequest) -> bool {
    let Some(output) = request
        .output_parent
        .as_deref()
        .filter(|path| path.is_dir())
    else {
        return false;
    };
    let output = existing_absolute(output);
    let mod_input = existing_absolute(&request.mod_input);
    if mod_input.is_dir() && output.starts_with(&mod_input) {
        return false;
    }
    if let Some(game) = request.game_root.as_deref() {
        let game = existing_absolute(game);
        if output.starts_with(game) {
            return false;
        }
    }
    true
}

pub fn analyze(request: &PreflightRequest) -> PreflightReport {
    analyze_with_progress(request, &mut |_| {})
}

pub fn analyze_with_progress(
    request: &PreflightRequest,
    progress: &mut dyn FnMut(&str),
) -> PreflightReport {
    // Treat every run as a fresh snapshot. Saved setup is convenient, but it is never proof that the current input is safe.
    let started = Instant::now();
    progress("Reading bounded mod metadata and source identity");
    let name = request
        .mod_input
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("mod-input")
        .to_owned();
    let exists = request.mod_input.exists();
    let source_sha256 = request
        .mod_input
        .is_file()
        .then(|| sha256_file(&request.mod_input).ok())
        .flatten();
    let scan = if exists {
        scan_input(&request.mod_input)
    } else {
        Err(anyhow::anyhow!("mod input does not exist"))
    };
    let (inventory, scan_error) = match scan {
        Ok(inventory) => (Some(inventory), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    progress(
        &inventory
            .as_ref()
            .map(|value| {
                format!(
                    "Classified {} file(s) as {}",
                    value.file_count, value.classification
                )
            })
            .unwrap_or_else(|| "Mod inventory could not be completed".to_owned()),
    );
    let expected_plugin_count = inventory
        .as_ref()
        .map(|value| value.plugin_counts.values().sum::<usize>())
        .unwrap_or(0);
    let additive_layout = inventory.as_ref().is_some_and(|value| {
        value.classification == "additive-syncmap-iostore"
            && value.incomplete_container_count == 0
            && value.link_count == 0
            && !value.scan_truncated
    });
    let candidate_mod_root = inventory
        .as_ref()
        .and_then(|value| value.candidate_mod_root.as_deref());
    let current_esm = request
        .game_root
        .as_deref()
        .map(normalize_install_root)
        .map(|root| root.join(r"OblivionRemastered\Content\Dev\ObvData\Data\Oblivion.esm"));
    let (plugin_compatibility, additive_contract) = if expected_plugin_count > 0
        && inventory
            .as_ref()
            .is_some_and(|value| !value.scan_truncated)
    {
        progress("Reading plugin headers, masters, FormIDs, and record domains");
        if additive_layout {
            match inspect_additive_contract_input(
                &request.mod_input,
                candidate_mod_root,
                current_esm.as_deref(),
            ) {
                Ok((plugin_set, contract)) => (Some(plugin_set), Some(contract)),
                Err(_) => (
                    Some(PluginSetReport::unavailable(expected_plugin_count)),
                    None,
                ),
            }
        } else {
            (
                Some(
                    inspect_plugin_input_at_root(&request.mod_input, candidate_mod_root)
                        .unwrap_or_else(|_| PluginSetReport::unavailable(expected_plugin_count)),
                ),
                None,
            )
        }
    } else if expected_plugin_count > 0 {
        (
            Some(PluginSetReport::unavailable(expected_plugin_count)),
            None,
        )
    } else {
        (None, None)
    };
    let additive_shape = additive_layout
        && plugin_compatibility
            .as_ref()
            .is_some_and(|value| value.additive_syncmap_v1.compatible)
        && additive_contract
            .as_ref()
            .is_some_and(|value| value.compatible);
    let replacement_shape = inventory.as_ref().is_some_and(|value| {
        value.classification == "unreal-container-only"
            && value.complete_container_triple_count > 0
            && value.incomplete_container_count == 0
            && value.link_count == 0
            && !value.scan_truncated
            && value.loose_file_count == 0
            && value.file_count == value.complete_container_triple_count * 3
    });
    let requires_adapter = additive_layout || replacement_shape;
    let requires_runtime = additive_shape;

    progress("Validating the selected game installation and current metadata");
    let game = request
        .game_root
        .as_deref()
        .map(|path| validate_game_install(path, "preflight"));
    let game_valid = game.as_ref().is_some_and(|value| value.valid);
    let (
        armor_probe,
        armor_probe_error,
        mixed_armor_probe,
        mixed_armor_probe_error,
        texture_probe,
        texture_probe_error,
        additive_static_mesh_probe,
        additive_static_mesh_probe_error,
    ) = if replacement_shape {
        progress("Classifying replacement assets and comparing them with the current game");
        if let Some(game) = game.as_ref().filter(|value| value.valid) {
            match probe_input(&request.mod_input, &game.root) {
                Ok(summary) => (Some(summary), None, None, None, None, None, None, None),
                Err(armor_error) => match probe_mixed_armor_input(&request.mod_input, &game.root) {
                    Ok(summary) => (
                        None,
                        Some(format!("{armor_error:#}")),
                        Some(summary),
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                    Err(mixed_error) => match probe_texture_input(&request.mod_input, &game.root) {
                        Ok(summary) => (
                            None,
                            Some(format!("{armor_error:#}")),
                            None,
                            Some(format!("{mixed_error:#}")),
                            Some(summary),
                            None,
                            None,
                            None,
                        ),
                        Err(texture_error) => {
                            match probe_additive_static_mesh_input(&request.mod_input, &game.root) {
                                Ok(summary) => (
                                    None,
                                    Some(format!("{armor_error:#}")),
                                    None,
                                    Some(format!("{mixed_error:#}")),
                                    None,
                                    Some(format!("{texture_error:#}")),
                                    Some(summary),
                                    None,
                                ),
                                Err(static_error) => (
                                    None,
                                    Some(format!("{armor_error:#}")),
                                    None,
                                    Some(format!("{mixed_error:#}")),
                                    None,
                                    Some(format!("{texture_error:#}")),
                                    None,
                                    Some(format!("{static_error:#}")),
                                ),
                            }
                        }
                    },
                },
            }
        } else {
            let message = "A complete target game is required to prove replacement package paths, IDs, classes, formats, and dependencies.".to_owned();
            (
                None,
                Some(message.clone()),
                None,
                Some(message.clone()),
                None,
                Some(message.clone()),
                None,
                Some(message),
            )
        }
    } else {
        (None, None, None, None, None, None, None, None)
    };
    let replacement_probe = armor_probe
        .as_ref()
        .or(mixed_armor_probe.as_ref())
        .or(texture_probe.as_ref())
        .or(additive_static_mesh_probe.as_ref())
        .cloned();
    progress("Checking embedded engines and connected runtime tools");
    let candidates = if exists {
        scan_dependencies(&request.connected_tools, Some(&request.mod_input))
    } else {
        Vec::new()
    };
    let installed = game
        .as_ref()
        .filter(|value| value.valid)
        .map(|value| installed_state(&value.root));
    let ue4ss_candidates = candidate_count(&candidates, DependencyKind::UE4SS);
    let injector_candidates = candidate_count(&candidates, DependencyKind::TesSyncMapInjector);
    let ue4ss_ready = installed
        .as_ref()
        .is_some_and(|value| value.ue4ss.installed)
        || ue4ss_candidates > 0;
    let injector_ready = installed
        .as_ref()
        .is_some_and(|value| value.tes_sync_map_injector.installed)
        || injector_candidates > 0;
    let output_valid = request.output_parent.as_deref().is_some_and(Path::is_dir);
    let output_isolated = output_isolated(request);

    progress("Evaluating fail-closed adapter and output safety gates");
    let mut tools = vec![
        built_in_tool(
            "retoc",
            "retoc IoStore engine",
            crate::retoc::embedded_fingerprints(),
            requires_adapter,
        ),
        built_in_tool(
            "uassetgui",
            "UAssetGUI package engine",
            crate::uasset::embedded_fingerprints(),
            requires_adapter,
        ),
    ];
    for (id, display_name, kind, installed_ready, candidate_total) in [
        (
            "ue4ss",
            "UE4SS",
            DependencyKind::UE4SS,
            installed
                .as_ref()
                .is_some_and(|value| value.ue4ss.installed),
            ue4ss_candidates,
        ),
        (
            "tes-sync-map-injector",
            "TesSyncMapInjector",
            DependencyKind::TesSyncMapInjector,
            installed
                .as_ref()
                .is_some_and(|value| value.tes_sync_map_injector.installed),
            injector_candidates,
        ),
    ] {
        let status = if !requires_runtime {
            "not-required"
        } else if installed_ready {
            "installed"
        } else if candidate_total > 0 {
            "connected-for-install"
        } else {
            "missing"
        };
        tools.push(ToolStatus {
            id: id.to_owned(),
            display_name: display_name.to_owned(),
            source: if installed_ready {
                "game-install"
            } else {
                "user-or-nearby"
            }
            .to_owned(),
            status: status.to_owned(),
            required_for_selected_adapter: requires_runtime,
            candidate_count: candidate_total,
            components: connected_components(&candidates, kind),
        });
    }

    let mut checks = vec![
        check(
            "mod-input-readable",
            inventory.is_some(),
            true,
            "Mod input metadata was read without changing the source.",
            scan_error
                .clone()
                .unwrap_or_else(|| "Mod input could not be read.".to_owned()),
            Some("Choose a readable ZIP, 7Z, single-volume RAR, or extracted mod folder."),
        ),
        check(
            "inventory-complete",
            inventory
                .as_ref()
                .is_some_and(|value| !value.scan_truncated),
            true,
            "The complete mod inventory fit within the bounded scan limit.",
            format!("The inventory exceeded the {MAX_SCAN_ENTRIES} entry safety limit."),
            Some("Reduce generated/cache files in the mod package before updating."),
        ),
        check(
            "archive-links-absent",
            inventory
                .as_ref()
                .is_some_and(|value| value.link_count == 0),
            true,
            "No filesystem links were found in the selected input.",
            "Filesystem links are not accepted in update inputs.",
            Some("Replace links with ordinary files in a clean mod staging folder."),
        ),
        check(
            "declared-size-bounded",
            inventory
                .as_ref()
                .is_some_and(|value| value.total_declared_bytes <= MAX_DECLARED_BYTES),
            true,
            "Declared mod size is within the 128 GiB processing safety bound.",
            "Declared mod size exceeds the 128 GiB processing safety bound.",
            Some("Remove unrelated/generated content or split the input before updating."),
        ),
        check(
            "game-install",
            game_valid,
            requires_adapter,
            "The target game contains the required executable, ESM, and IoStore metadata.",
            "A complete target game installation was not connected.",
            Some("Use Find game or connect the game installation folder in Setup."),
        ),
        check(
            "output-folder",
            output_valid,
            requires_adapter,
            "The selected report/output parent exists.",
            "The selected report/output parent does not exist.",
            Some("Choose an existing writable output folder."),
        ),
        check(
            "output-isolated",
            output_isolated,
            requires_adapter,
            "Reports and candidates will be written outside the source mod and game trees.",
            "The output folder is inside the source mod or game tree.",
            Some("Choose a separate report/output folder."),
        ),
        check(
            "ue4ss-connection",
            !requires_runtime || ue4ss_ready,
            requires_runtime,
            if requires_runtime {
                "UE4SS is installed or connected for a backed-up install."
            } else {
                "UE4SS is not required by the selected adapter."
            },
            "UE4SS is required by the selected additive SyncMap adapter but is not installed or connected.",
            Some("Connect an original UE4SS archive/folder in Setup."),
        ),
        check(
            "sync-map-injector-connection",
            !requires_runtime || injector_ready,
            requires_runtime,
            if requires_runtime {
                "TesSyncMapInjector is installed or connected for a backed-up install."
            } else {
                "TesSyncMapInjector is not required by the selected adapter."
            },
            "TesSyncMapInjector is required by the selected adapter but is not installed or connected.",
            Some("Connect an original TesSyncMapInjector archive/folder in Setup."),
        ),
    ];
    if let Some(plugin_report) = plugin_compatibility.as_ref() {
        checks.push(check(
            "plugin-content-analysis",
            plugin_report.status == "complete"
                && plugin_report.parsed_plugin_count == plugin_report.plugin_count,
            additive_layout,
            format!(
                "Parsed and fingerprinted {} plugin file(s) without rewriting them.",
                plugin_report.plugin_count
            ),
            "One or more ESP/ESM/ESL files could not be parsed safely.",
            Some("Repair or replace malformed plugins before attempting an update."),
        ));
        checks.push(check(
            "plugin-structural-safety",
            plugin_report.blockers.is_empty(),
            additive_layout,
            "Plugin record identities, master graph, and full-plugin FormID ranges passed the structural checks.",
            if plugin_report.blockers.is_empty() {
                "Plugin structure was inspected.".to_owned()
            } else {
                format!(
                    "Plugin structure has blocker(s): {}",
                    plugin_report.blockers.join(", ")
                )
            },
            Some("Keep this mod report-only until each structural blocker has a dedicated, verified repair."),
        ));
        if additive_layout {
            checks.push(check(
                "plugin-additive-syncmap-policy",
                plugin_report.additive_syncmap_v1.compatible,
                true,
                "The plugin matches the one-ESP, one-Oblivion.esm, CONT-only additive policy.",
                format!(
                    "The plugin does not match the proven additive policy: {}",
                    plugin_report.additive_syncmap_v1.blockers.join(", ")
                ),
                Some("Unsupported ESP/ESM/ESL and record-change scenarios remain report-only until a versioned plugin adapter exists."),
            ));
            checks.push(check(
                "additive-plugin-syncmap-contract",
                additive_contract
                    .as_ref()
                    .is_some_and(|value| value.compatible),
                true,
                "The SyncMap is non-empty, every mapped FormID is plugin-owned, and every CONT override is additive against the current Oblivion.esm.",
                additive_contract
                    .as_ref()
                    .map(|value| {
                        format!(
                            "The additive plugin/SyncMap contract is blocked: {}",
                            value.blockers.join(", ")
                        )
                    })
                    .unwrap_or_else(|| {
                        "The additive plugin/SyncMap contract could not be inspected safely."
                            .to_owned()
                    }),
                Some("Use a non-empty SyncMap whose local IDs exist in the ESP, and rebase CONT overrides against the current Oblivion.esm without changing or removing existing content."),
            ));
        }
    }
    if replacement_shape {
        let passed = replacement_probe.is_some();
        let success = armor_probe
            .as_ref()
            .map(|summary| {
                format!(
                    "The input is a pure armor skeletal-mesh replacement: {} package(s) in {} complete container(s), all with matching current-game paths and package IDs.",
                    summary.package_count, summary.container_count
                )
            })
            .or_else(|| {
                mixed_armor_probe.as_ref().map(|summary| {
                    format!(
                        "The input is a guarded mixed armor expansion/replacement: {} package(s) in {} separated mesh and companion container(s). Additive _f meshes have one current-game sibling donor; companion form paths, IDs, and dependency closure match the current game.",
                        summary.package_count, summary.container_count
                    )
                })
            })
            .or_else(|| {
                texture_probe.as_ref().map(|summary| {
                    let warning_count = summary
                        .texture_assets
                        .iter()
                        .map(|asset| asset.warnings.len())
                        .sum::<usize>();
                    format!(
                        "The input is a pure Texture2D replacement: {} package(s) in {} complete container(s), with matching current-game paths, IDs, object identities, pixel formats, and dependency-free package stores ({} diagnostic warning(s)).",
                        summary.package_count,
                        summary.container_count,
                        warning_count
                    )
                })
            })
            .or_else(|| {
                additive_static_mesh_probe.as_ref().map(|summary| {
                    format!(
                        "The input contains {} structurally proven StaticMesh package(s) in {} complete container(s). Package path and ID evidence classified it as {}; names and folder conventions were not used.",
                        summary.package_count, summary.container_count, summary.asset_kind
                    )
                })
            });
        let failure = format!(
            "No proven content adapter accepted every package. Armor: {} Mixed armor: {} Texture2D: {} StaticMesh: {}",
            armor_probe_error
                .as_deref()
                .unwrap_or("not evaluated as armor."),
            mixed_armor_probe_error
                .as_deref()
                .unwrap_or("not evaluated as mixed armor."),
            texture_probe_error
                .as_deref()
                .unwrap_or("not evaluated as Texture2D."),
            additive_static_mesh_probe_error
                .as_deref()
                .unwrap_or("not evaluated as a StaticMesh container.")
        );
        checks.push(check(
            "replacement-contract",
            passed,
            true,
            success
                .as_deref()
                .unwrap_or("A guarded replacement contract passed."),
            failure,
            Some(
                "Unsupported export classes, ambiguous package identities, unresolved dependencies, scripts, and loose files remain report-only until a structural capability is available.",
            ),
        ));
    }
    let adapter_blockers = checks
        .iter()
        .filter(|value| value.blocking)
        .map(|value| value.id.clone())
        .collect::<Vec<_>>();
    let additive_can_update = additive_shape && adapter_blockers.is_empty();
    let armor_can_update =
        replacement_shape && armor_probe.is_some() && adapter_blockers.is_empty();
    let mixed_armor_can_update =
        replacement_shape && mixed_armor_probe.is_some() && adapter_blockers.is_empty();
    let texture_can_update =
        replacement_shape && texture_probe.is_some() && adapter_blockers.is_empty();
    let additive_static_mesh_can_update =
        replacement_shape && additive_static_mesh_probe.is_some() && adapter_blockers.is_empty();
    let can_update = additive_can_update
        || armor_can_update
        || mixed_armor_can_update
        || texture_can_update
        || additive_static_mesh_can_update;
    let mut capabilities = vec![Capability {
        id: "report-only-v1".to_owned(),
        available: inventory.is_some(),
        evidence_level: "metadata-inventory".to_owned(),
        description: "Non-mutating inventory, classification, tool status, and shareable diagnostics for ZIP, 7Z, single-volume RAR, and folder inputs.".to_owned(),
        blockers: if inventory.is_none() {
            vec!["mod-input-readable".to_owned()]
        } else {
            Vec::new()
        },
    }];
    capabilities.push(Capability {
        id: SELECTED_METADATA_EXTRACTION_API.to_owned(),
        available: inventory
            .as_ref()
            .is_some_and(|value| !value.scan_truncated),
        evidence_level: "validated-bounded-archive-selection".to_owned(),
        description: "Validates the complete ZIP/7Z/RAR path and size inventory while extracting only bounded ESP/ESM/ESL/INI metadata for plugin preflight; large PAK/UCAS/UTOC payloads are not materialized by this probe.".to_owned(),
        blockers: inventory
            .as_ref()
            .filter(|value| !value.scan_truncated)
            .map(|_| Vec::new())
            .unwrap_or_else(|| vec!["inventory-incomplete".to_owned()]),
    });
    capabilities.push(Capability {
        id: PLUGIN_MANIFEST_API.to_owned(),
        available: plugin_compatibility
            .as_ref()
            .is_some_and(|value| value.status == "complete"),
        evidence_level: "content-hashed-structural-report".to_owned(),
        description: "Reads and fingerprints every ESP/ESM/ESL, reports ordered masters, record domains, FormID ownership, deleted/compressed records, and bundled master edges. This capability does not generically rewrite plugins; unsupported semantics remain report-only.".to_owned(),
        blockers: plugin_compatibility
            .as_ref()
            .map(|value| value.blockers.clone())
            .unwrap_or_else(|| vec!["no-plugin-files".to_owned()]),
    });
    capabilities.push(Capability {
        id: ADDITIVE_CONTRACT_API.to_owned(),
        available: additive_contract
            .as_ref()
            .is_some_and(|value| value.compatible),
        evidence_level: "current-master-field-aware-validation".to_owned(),
        description: "Binds the unique candidate root, ESP, SyncMap, and current Oblivion.esm; rejects empty or duplicate mappings, unmapped plugin-local IDs, and CONT overrides that remove or functionally change current content.".to_owned(),
        blockers: additive_contract
            .as_ref()
            .map(|value| value.blockers.clone())
            .unwrap_or_else(|| vec!["additive-contract-not-applicable".to_owned()]),
    });
    capabilities.push(Capability {
        id: "native-additive-syncmap-v1".to_owned(),
        available: additive_can_update,
        evidence_level: "guarded-structural-adapter".to_owned(),
        description: "Existing fail-closed additive ESP + SyncMap + IoStore rebuild lane. Output remains a runtime-test candidate.".to_owned(),
        blockers: if additive_layout {
            adapter_blockers.clone()
        } else {
            vec!["mod-layout-does-not-match-proven-additive-adapter".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: ARMOR_REPLACEMENT_ADAPTER.to_owned(),
        available: armor_can_update,
        evidence_level: "guarded-payload-preserving-rebase".to_owned(),
        description: "Pure existing SK_ armor replacements resolve serialized FSkeletalMaterial slots by name, migrate the skeleton separately, and null a retired PhysicsAsset only when current-donor and serialized-property evidence prove that role. Unknown auxiliary imports stop instead of becoming materials. The approved payload migration is roundtripped through current Zen metadata, and output remains a runtime-test candidate.".to_owned(),
        blockers: if armor_probe.is_some() {
            adapter_blockers.clone()
        } else {
            vec!["mod-layout-does-not-match-proven-armor-replacement-adapter".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: MIXED_ARMOR_REPLACEMENT_ADAPTER.to_owned(),
        available: mixed_armor_can_update,
        evidence_level: "guarded-mixed-armor-expansion-rebase".to_owned(),
        description: "Separated SK_ armor-mesh and /Forms/items/armor companion containers are accepted when every companion path, package ID, and dependency resolves. Existing meshes use their exact current donor; additive _f meshes require exactly one same-directory _m or unsuffixed current-game sibling donor. Generic exposed-body slots can use exactly one installed or connected custom-body profile to rebind the current body material and skeleton automatically. Mesh geometry, skin weights, and companion containers are preserved; external body shape, morph, cloth, and runtime physics compatibility are disclosed but not claimed.".to_owned(),
        blockers: if mixed_armor_probe.is_some() {
            adapter_blockers.clone()
        } else {
            vec!["mod-layout-does-not-match-guarded-mixed-armor-adapter".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: TEXTURE_REPLACEMENT_ADAPTER.to_owned(),
        available: texture_can_update,
        evidence_level: "guarded-byte-preserving-texture-rebase".to_owned(),
        description: "Pure existing Texture2D replacements require matching current paths, package IDs, object identities, pixel formats, and dependency-free package stores. UEXP/UBULK and raw export payloads are preserved through a verified current-Zen roundtrip; mixed MIC, blueprint, CCA, and shader closures remain report-only.".to_owned(),
        blockers: if texture_probe.is_some() {
            adapter_blockers.clone()
        } else {
            vec!["mod-layout-does-not-match-proven-texture-replacement-adapter".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: ADDITIVE_STATIC_MESH_ADAPTER.to_owned(),
        available: additive_static_mesh_can_update,
        evidence_level: "guarded-content-proven-static-mesh-rebase".to_owned(),
        description: "StaticMesh containers are classified from export structure and package identity rather than project, folder, or filename conventions. Existing-game packages require an exact current path and package ID; additive packages must avoid current identity collisions. Every dependency must resolve, each package is extracted exactly, and the rebuilt inventory and raw exports must survive a current-Zen roundtrip.".to_owned(),
        blockers: if additive_static_mesh_probe.is_some() {
            adapter_blockers.clone()
        } else {
            vec!["packages-did-not-pass-structural-static-mesh-capability".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: "pinned-offhand-staff-a-v1".to_owned(),
        available: false,
        evidence_level: "separate-audited-donor-cli".to_owned(),
        description: "The Staff A donor repair remains available only through its separately pinned console lane and cannot be inferred from a generic mod input.".to_owned(),
        blockers: vec!["audited-donor-selection-required".to_owned()],
    });
    if !additive_shape && replacement_probe.is_none() && inventory.is_some() {
        checks.push(CheckResult {
            id: "proven-update-adapter".to_owned(),
            status: "warning".to_owned(),
            blocking: false,
            message: "This mod type is reportable, but no proven mutation adapter matches it. No update will be attempted.".to_owned(),
            remediation: Some(
                "Send this report with the mod link so a dedicated fail-closed adapter can be implemented and verified.".to_owned(),
            ),
        });
    }
    let status = if can_update {
        "ready-for-guarded-update"
    } else if inventory.is_some() {
        "report-only"
    } else {
        "input-error"
    };
    PreflightReport {
        schema: REPORT_SCHEMA.to_owned(),
        version: REPORT_VERSION,
        generated_at: chrono::Utc::now().to_rfc3339(),
        application_version: env!("CARGO_PKG_VERSION").to_owned(),
        target_os: std::env::consts::OS.to_owned(),
        target_arch: std::env::consts::ARCH.to_owned(),
        mode: "report-only-no-source-or-game-mutation".to_owned(),
        privacy_note: "Absolute mod, game, output, and connected-tool paths are omitted. Relative mod paths, hashes, sizes, platform, and capability results remain so reports can be compared safely.".to_owned(),
        input: InputIdentity {
            name,
            input_type: input_type(&request.mod_input),
            source_sha256,
            absolute_paths_included: false,
        },
        inventory,
        game_valid,
        game_discovery_source: game.as_ref().map(|value| value.source.clone()),
        game_missing_components: game
            .map(|value| value.missing)
            .unwrap_or_else(|| {
                crate::game::REQUIRED_GAME_FILES
                    .iter()
                    .map(|(_, path)| (*path).to_owned())
                    .collect()
            }),
        tools,
        checks,
        capabilities,
        plugin_compatibility,
        additive_contract,
        unreal_replacement_probe: replacement_probe,
        selected_adapter: if additive_shape {
            Some("native-additive-syncmap-v1".to_owned())
        } else if armor_can_update {
            Some(ARMOR_REPLACEMENT_ADAPTER.to_owned())
        } else if mixed_armor_can_update {
            Some(MIXED_ARMOR_REPLACEMENT_ADAPTER.to_owned())
        } else if texture_can_update {
            Some(TEXTURE_REPLACEMENT_ADAPTER.to_owned())
        } else if additive_static_mesh_can_update {
            Some(ADDITIVE_STATIC_MESH_ADAPTER.to_owned())
        } else {
            None
        },
        can_update,
        status: status.to_owned(),
        performance: PerformanceReport {
            elapsed_ms: started.elapsed().as_millis(),
            scan_entry_limit: MAX_SCAN_ENTRIES,
            metadata_only_archive_scan: !replacement_shape,
            large_file_hashing_streamed: true,
        },
        stress: None,
    }
}

pub fn stable_signature(report: &PreflightReport) -> String {
    let inventory = report.inventory.as_ref();
    let value = serde_json::json!({
        "schema": report.schema,
        "version": report.version,
        "applicationVersion": report.application_version,
        "targetOs": report.target_os,
        "targetArch": report.target_arch,
        "inputType": report.input.input_type,
        "sourceSha256": report.input.source_sha256,
        "classification": inventory.map(|value| &value.classification),
        "manifest": inventory.map(|value| &value.metadata_manifest_sha256),
        "pluginManifest": report
            .plugin_compatibility
            .as_ref()
            .map(|value| (&value.status, &value.manifest_sha256)),
        "additivePluginPolicy": report
            .plugin_compatibility
            .as_ref()
            .map(|value| value.additive_syncmap_v1.compatible),
        "additiveContract": report
            .additive_contract
            .as_ref()
            .map(|value| (&value.status, value.compatible, &value.sync_map_sha256)),
        "gameValid": report.game_valid,
        "toolStatus": report
            .tools
            .iter()
            .map(|value| (&value.id, &value.status))
            .collect::<Vec<_>>(),
        "capabilities": report
            .capabilities
            .iter()
            .map(|value| (&value.id, value.available))
            .collect::<Vec<_>>(),
    });
    sha256_bytes(&serde_json::to_vec(&value).expect("stable signature JSON is serializable"))
}

pub fn attach_stress(
    report: &mut PreflightReport,
    requested_runs: usize,
    timings: &[u128],
    signatures: &[String],
) {
    let signature = signatures.first().cloned().unwrap_or_default();
    let total = timings.iter().sum::<u128>();
    report.stress = Some(StressReport {
        requested_runs,
        completed_runs: signatures.len(),
        deterministic: !signatures.is_empty() && signatures.iter().all(|value| value == &signature),
        stable_signature: signature,
        min_elapsed_ms: timings.iter().copied().min().unwrap_or(0),
        max_elapsed_ms: timings.iter().copied().max().unwrap_or(0),
        mean_elapsed_ms: total.checked_div(timings.len() as u128).unwrap_or(0),
    });
}

pub fn write_report(report: &PreflightReport, output: &Path) -> Result<PathBuf> {
    if report
        .checks
        .iter()
        .any(|check| check.id == "output-isolated" && check.status != "pass")
    {
        bail!("refusing to write a report inside the source mod or game tree");
    }
    let path = if output
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("json"))
    {
        output.to_path_buf()
    } else {
        let stem = Path::new(&report.input.name)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("mod")
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                    character
                } else {
                    '-'
                }
            })
            .collect::<String>();
        output.join(format!(
            "{}-preflight-{}.json",
            stem.trim_matches('-'),
            chrono::Local::now().format("%Y%m%d-%H%M%S-%3f")
        ))
    };
    let parent = path.parent().context("report output has no parent")?;
    if !parent.is_dir() {
        bail!("report output parent does not exist: {}", parent.display());
    }
    fs::write(&path, serde_json::to_vec_pretty(report)?)
        .with_context(|| format!("writing preflight report {}", path.display()))?;
    Ok(path)
}

pub fn human_summary(report: &PreflightReport) -> String {
    let inventory = report.inventory.as_ref();
    let failures = report
        .checks
        .iter()
        .filter(|value| value.status == "fail")
        .count();
    let warnings = report
        .checks
        .iter()
        .filter(|value| value.status == "warning")
        .count();
    format!(
        "Preflight status: {}\nClassification: {}\nFiles: {}\nDeclared bytes: {}\nPlugin analysis: {}\nChecks: {} failure(s), {} warning(s)\nGuarded update enabled: {}\nRuntime verification: not claimed",
        report.status,
        inventory
            .map(|value| value.classification.as_str())
            .unwrap_or("unreadable"),
        inventory.map(|value| value.file_count).unwrap_or(0),
        inventory
            .map(|value| value.total_declared_bytes)
            .unwrap_or(0),
        report
            .plugin_compatibility
            .as_ref()
            .map(|value| format!(
                "{} ({} of {} parsed)",
                value.status, value.parsed_plugin_count, value.plugin_count
            ))
            .unwrap_or_else(|| "not present".to_owned()),
        failures,
        warnings,
        report.can_update,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tes4_subrecord(kind: &str, data: &[u8]) -> Vec<u8> {
        let mut bytes = kind.as_bytes().to_vec();
        bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    fn valid_plugin_bytes() -> Vec<u8> {
        let mut header_data = Vec::new();
        let mut hedr = 0.8_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&1_u32.to_le_bytes());
        hedr.extend_from_slice(&0x801_u32.to_le_bytes());
        header_data.extend(tes4_subrecord("HEDR", &hedr));
        header_data.extend(tes4_subrecord("MAST", b"Oblivion.esm\0"));
        header_data.extend(tes4_subrecord("DATA", &[0; 8]));
        let mut bytes = b"TES4".to_vec();
        bytes.extend_from_slice(&(header_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&header_data);
        let record_data = tes4_subrecord("EDID", b"Fixture\0");
        bytes.extend_from_slice(b"STAT");
        bytes.extend_from_slice(&(record_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0x0100_0800_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&record_data);
        bytes
    }

    fn tes4_record_bytes(kind: &str, form_id: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = kind.as_bytes().to_vec();
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&form_id.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    fn invalid_cont_override_plugin_bytes() -> Vec<u8> {
        let mut header_data = Vec::new();
        let mut hedr = 0.8_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&2_u32.to_le_bytes());
        hedr.extend_from_slice(&0x801_u32.to_le_bytes());
        header_data.extend(tes4_subrecord("HEDR", &hedr));
        header_data.extend(tes4_subrecord("MAST", b"Oblivion.esm\0"));
        header_data.extend(tes4_subrecord("DATA", &[0; 8]));
        let mut bytes = b"TES4".to_vec();
        bytes.extend_from_slice(&(header_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&header_data);
        bytes.extend(tes4_record_bytes(
            "STAT",
            0x0100_0800,
            &tes4_subrecord("EDID", b"Fixture\0"),
        ));
        let mut container = tes4_subrecord("EDID", b"ChangedContainer\0");
        let mut inventory = 0x0100_0800_u32.to_le_bytes().to_vec();
        inventory.extend_from_slice(&1_i32.to_le_bytes());
        container.extend(tes4_subrecord("CNTO", &inventory));
        bytes.extend(tes4_record_bytes("CONT", 0x0009_2285, &container));
        bytes
    }

    fn current_master_with_container_bytes() -> Vec<u8> {
        let mut hedr = 0.8_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&1_u32.to_le_bytes());
        hedr.extend_from_slice(&0x800_u32.to_le_bytes());
        let header_data = tes4_subrecord("HEDR", &hedr);
        let mut bytes = tes4_record_bytes("TES4", 0, &header_data);
        let container = tes4_subrecord("EDID", b"CurrentContainer\0");
        bytes.extend(tes4_record_bytes("CONT", 0x0009_2285, &container));
        bytes
    }

    fn additive_fixture(root: &Path) {
        let data = root.join(r"Fixture\Content\Dev\ObvData\Data");
        let paks = root.join(r"Fixture\Content\Paks\~mods");
        fs::create_dir_all(data.join("SyncMap")).unwrap();
        fs::create_dir_all(&paks).unwrap();
        fs::write(data.join("Fixture.esp"), valid_plugin_bytes()).unwrap();
        fs::write(
            data.join(r"SyncMap\Fixture.ini"),
            b"[Meshes]\n000800=../../../OblivionRemastered/Content/Fixture/SM_Fixture.SM_Fixture\n",
        )
        .unwrap();
        for extension in ["pak", "ucas", "utoc"] {
            fs::write(paks.join(format!("AAAA_Fixture_P.{extension}")), extension).unwrap();
        }
    }

    fn game_fixture(root: &Path) {
        for (_, relative) in crate::game::REQUIRED_GAME_FILES {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }
    }

    fn runtime_tools_fixture(root: &Path) {
        fs::create_dir_all(root.join(r"ue4ss\Mods\TesSyncMapInjector\Scripts")).unwrap();
        fs::write(root.join("dwmapi.dll"), b"proxy").unwrap();
        fs::write(root.join(r"ue4ss\UE4SS.dll"), b"ue4ss").unwrap();
        fs::write(
            root.join(r"ue4ss\Mods\TesSyncMapInjector\Scripts\main.lua"),
            b"injector",
        )
        .unwrap();
        fs::write(
            root.join(r"ue4ss\Mods\TesSyncMapInjector\enabled.txt"),
            b"enabled",
        )
        .unwrap();
    }

    #[test]
    fn classifies_additive_layout_without_reading_file_contents() {
        let temp = tempfile::tempdir().unwrap();
        additive_fixture(temp.path());
        let inventory = scan_directory(temp.path()).unwrap();
        assert_eq!(inventory.classification, "additive-syncmap-iostore");
        assert_eq!(inventory.complete_container_triple_count, 1);
        assert_eq!(inventory.candidate_mod_root_count, 1);
        assert!(!inventory.scan_truncated);

        let direct = tempfile::tempdir().unwrap();
        additive_fixture(direct.path());
        let wrapped = direct.path().join("Fixture");
        let inventory = scan_directory(&wrapped).unwrap();
        assert_eq!(inventory.classification, "additive-syncmap-iostore");
        assert_eq!(inventory.candidate_mod_root_count, 1);
    }

    fn assert_extra_payload_is_report_only(relative: &str, payload: &[u8]) {
        let temp = tempfile::tempdir().unwrap();
        additive_fixture(temp.path());
        let extra = temp.path().join(relative);
        fs::create_dir_all(extra.parent().unwrap()).unwrap();
        fs::write(extra, payload).unwrap();
        let report = analyze(&PreflightRequest {
            mod_input: temp.path().to_path_buf(),
            game_root: None,
            output_parent: None,
            connected_tools: Vec::new(),
        });
        assert_eq!(
            report.inventory.as_ref().unwrap().classification,
            "mixed-mod"
        );
        assert!(!report.can_update);
        assert_ne!(
            report.selected_adapter.as_deref(),
            Some("native-additive-syncmap-v1")
        );
    }

    #[test]
    fn extra_esm_never_selects_the_additive_adapter() {
        assert_extra_payload_is_report_only(
            r"Fixture\Content\Dev\ObvData\Data\Extra.esm",
            &valid_plugin_bytes(),
        );
    }

    #[test]
    fn extra_esl_never_selects_the_additive_adapter() {
        assert_extra_payload_is_report_only(
            r"Fixture\Content\Dev\ObvData\Data\Extra.esl",
            &valid_plugin_bytes(),
        );
    }

    #[test]
    fn loader_never_selects_the_additive_adapter() {
        assert_extra_payload_is_report_only("loader.dll", b"loader");
    }

    #[test]
    fn functional_loose_file_never_selects_the_additive_adapter() {
        assert_extra_payload_is_report_only(
            r"Fixture\Content\Dev\ObvData\Data\Extra.ini",
            b"[Settings]\nEnabled=true\n",
        );
    }

    #[test]
    fn malformed_esp_blocks_shape_correct_additive_input() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        let game_root = temp.path().join("game");
        let tools_root = temp.path().join("tools");
        fs::create_dir_all(&mod_root).unwrap();
        additive_fixture(&mod_root);
        fs::write(
            mod_root.join(r"Fixture\Content\Dev\ObvData\Data\Fixture.esp"),
            b"not-a-plugin",
        )
        .unwrap();
        game_fixture(&game_root);
        runtime_tools_fixture(&tools_root);
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: vec![tools_root],
        });
        assert!(!report.can_update);
        assert!(report.checks.iter().any(|check| {
            check.id == "plugin-content-analysis" && check.status == "fail" && check.blocking
        }));
    }

    #[test]
    fn empty_syncmap_is_report_only_even_when_layout_matches() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        let game_root = temp.path().join("game");
        let tools_root = temp.path().join("tools");
        fs::create_dir_all(&mod_root).unwrap();
        additive_fixture(&mod_root);
        fs::write(
            mod_root.join(r"Fixture\Content\Dev\ObvData\Data\SyncMap\Fixture.ini"),
            b"[Meshes]\n",
        )
        .unwrap();
        game_fixture(&game_root);
        runtime_tools_fixture(&tools_root);
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: vec![tools_root],
        });
        assert!(!report.can_update);
        assert!(report.checks.iter().any(|check| {
            check.id == "additive-plugin-syncmap-contract"
                && check.status == "fail"
                && check.blocking
        }));
    }

    #[test]
    fn functional_cont_override_change_is_blocked_against_current_master() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        let game_root = temp.path().join("game");
        let tools_root = temp.path().join("tools");
        fs::create_dir_all(&mod_root).unwrap();
        additive_fixture(&mod_root);
        fs::write(
            mod_root.join(r"Fixture\Content\Dev\ObvData\Data\Fixture.esp"),
            invalid_cont_override_plugin_bytes(),
        )
        .unwrap();
        game_fixture(&game_root);
        fs::write(
            game_root.join(r"OblivionRemastered\Content\Dev\ObvData\Data\Oblivion.esm"),
            current_master_with_container_bytes(),
        )
        .unwrap();
        runtime_tools_fixture(&tools_root);
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: vec![tools_root],
        });
        assert!(!report.can_update);
        let contract = report.additive_contract.as_ref().unwrap();
        assert!(
            contract
                .blockers
                .iter()
                .any(|blocker| { blocker.contains("functional non-inventory fields") })
        );
    }

    #[test]
    fn plugin_must_belong_to_the_unique_data_and_paks_root() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        let game_root = temp.path().join("game");
        let tools_root = temp.path().join("tools");
        fs::create_dir_all(&mod_root).unwrap();
        additive_fixture(&mod_root);
        let original = mod_root.join(r"Fixture\Content\Dev\ObvData\Data\Fixture.esp");
        let misplaced = mod_root.join(r"Other\Content\Dev\ObvData\Data\Fixture.esp");
        fs::create_dir_all(misplaced.parent().unwrap()).unwrap();
        fs::rename(original, misplaced).unwrap();
        game_fixture(&game_root);
        runtime_tools_fixture(&tools_root);
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: vec![tools_root],
        });
        assert_eq!(
            report
                .inventory
                .as_ref()
                .unwrap()
                .candidate_mod_root
                .as_deref(),
            Some("Fixture")
        );
        assert!(!report.can_update);
        assert!(report.checks.iter().any(|check| {
            check.id == "plugin-additive-syncmap-policy" && check.status == "fail" && check.blocking
        }));
    }

    #[test]
    fn plugin_content_changes_the_stable_signature_even_when_size_is_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        let output = temp.path().join("output");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&output).unwrap();
        let plugin_path = input.join("Fixture.esp");
        let original = valid_plugin_bytes();
        fs::write(&plugin_path, &original).unwrap();
        let request = PreflightRequest {
            mod_input: input,
            game_root: None,
            output_parent: Some(output),
            connected_tools: Vec::new(),
        };
        let first = analyze(&request);
        let mut changed = original;
        let position = changed
            .windows(b"Fixture".len())
            .position(|window| window == b"Fixture")
            .unwrap();
        changed[position] = b'G';
        fs::write(&plugin_path, changed).unwrap();
        let second = analyze(&request);
        assert_ne!(stable_signature(&first), stable_signature(&second));
    }

    #[test]
    fn report_signature_ignores_timing_and_generation_time() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("readme.txt"), b"fixture").unwrap();
        let request = PreflightRequest {
            mod_input: temp.path().to_path_buf(),
            game_root: None,
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        };
        let first = analyze(&request);
        let mut second = analyze(&request);
        second.generated_at = "changed".to_owned();
        second.performance.elapsed_ms += 1000;
        assert_eq!(stable_signature(&first), stable_signature(&second));
        assert_eq!(first.status, "report-only");
        assert!(!first.can_update);
    }

    #[test]
    fn shareable_report_omits_absolute_paths() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("readme.txt"), b"fixture").unwrap();
        let report = analyze(&PreflightRequest {
            mod_input: temp.path().to_path_buf(),
            game_root: Some(temp.path().join("game")),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(&temp.path().to_string_lossy().to_string()));
        assert!(!report.input.absolute_paths_included);
    }

    #[test]
    fn supported_adapter_requires_content_validated_tool_connections() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        let game_root = temp.path().join("game");
        let tools_root = temp.path().join("tools-anywhere");
        fs::create_dir_all(&mod_root).unwrap();
        additive_fixture(&mod_root);
        game_fixture(&game_root);
        runtime_tools_fixture(&tools_root);
        let mut request = PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        };
        let missing = analyze(&request);
        assert!(!missing.can_update);
        assert!(
            missing
                .checks
                .iter()
                .any(|check| check.id == "ue4ss-connection" && check.blocking)
        );

        request.connected_tools.push(tools_root);
        let connected = analyze(&request);
        assert!(connected.can_update);
        assert_eq!(
            connected.selected_adapter.as_deref(),
            Some("native-additive-syncmap-v1")
        );
        assert!(
            connected
                .tools
                .iter()
                .filter(|tool| tool.required_for_selected_adapter)
                .all(|tool| tool.status != "missing")
        );
    }

    #[test]
    fn additive_zip_reads_only_selected_metadata_and_remains_updatable() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let game_root = temp.path().join("game");
        let tools_root = temp.path().join("tools");
        let output = temp.path().join("output");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&output).unwrap();
        additive_fixture(&source);
        game_fixture(&game_root);
        runtime_tools_fixture(&tools_root);
        let archive = temp.path().join("additive.zip");
        crate::archive::create_zip_from_paths(&archive, &source, &[source.join("Fixture")])
            .unwrap();

        let report = analyze(&PreflightRequest {
            mod_input: archive,
            game_root: Some(game_root),
            output_parent: Some(output),
            connected_tools: vec![tools_root],
        });
        assert!(report.can_update);
        assert!(report.performance.metadata_only_archive_scan);
        assert_eq!(
            report.plugin_compatibility.as_ref().unwrap().scan_mode,
            "validated-selected-entry-extraction"
        );
    }

    #[test]
    fn additive_preflight_accepts_the_inner_project_game_folder() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        let game_root = temp.path().join("game");
        let tools_root = temp.path().join("tools");
        fs::create_dir_all(&mod_root).unwrap();
        additive_fixture(&mod_root);
        game_fixture(&game_root);
        runtime_tools_fixture(&tools_root);

        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root.join("OblivionRemastered")),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: vec![tools_root],
        });

        assert!(report.can_update);
        assert!(
            report
                .additive_contract
                .as_ref()
                .is_some_and(|contract| contract.current_master_checked && contract.compatible)
        );
    }

    #[test]
    fn refuses_to_write_a_report_inside_the_source_mod() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("readme.txt"), b"fixture").unwrap();
        let report = analyze(&PreflightRequest {
            mod_input: temp.path().to_path_buf(),
            game_root: None,
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        assert!(write_report(&report, temp.path()).is_err());
        assert!(!temp.path().join("preflight.json").exists());
    }
}
