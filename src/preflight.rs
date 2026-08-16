use crate::archive::{
    MAX_ARCHIVE_DECLARED_BYTES, MAX_ARCHIVE_ENTRIES, SELECTED_METADATA_EXTRACTION_API, rar_entries,
    sha256_bytes, sha256_file,
};
use crate::dependencies::{
    DependencyCandidate, DependencyKind, installed_state, scan_dependencies,
};
use crate::dependency_layers::{
    LAYERED_IOSTORE_DEPENDENCY_API, LayeredIoStoreDependencyReport,
    probe_layered_iostore_dependencies,
};
use crate::game::{normalize_install_root, validate_game_install};
use crate::install_plan::{
    InstallPlan, LOGICAL_INSTALL_PUBLICATION_API, logical_install_adapter_id,
    resolve_staged_install_view, supports_logical_install_publication,
};
use crate::mixed::{
    MIXED_IOSTORE_DEPENDENCY_PROBE_API, MixedIoStoreDependencyReport,
    probe_mixed_iostore_dependencies,
};
use crate::pak::{
    LEGACY_PAK_PASSTHROUGH_ADAPTER, PakPassthroughProbeSummary, WWISE_AUDIO_MEDIA_PLANE,
    probe_legacy_pak_passthrough_input,
};
use crate::plugin_only::{PLUGIN_ONLY_ADAPTER, evaluate_plugin_only_lane};
use crate::plugin::{
    ADDITIVE_CONTRACT_API, AdditiveContractReport, MagicLoaderSyncMapGate, PLUGIN_MANIFEST_API,
    PluginSetReport, WORLDSPACE_MASTER_PROBE_API, WorldspaceMasterProbeReport,
    inspect_additive_contract_input, inspect_magicloader_syncmap_gate,
    inspect_plugin_input_at_root, inspect_worldspace_master_probe_input,
};
use crate::replacement::{
    ADDITIVE_STATIC_MESH_ADAPTER, ARMOR_REPLACEMENT_ADAPTER, COMPOSITE_PACKAGE_REBASE_ADAPTER,
    HETEROGENEOUS_REPLACEMENT_ADAPTER, HeterogeneousReplacementProbeSummary,
    IDENTITY_ALIAS_RECOVERY_PROBE_API, IdentityAliasRecoveryProbeSummary,
    MIXED_ARMOR_REPLACEMENT_ADAPTER, MIXED_REPLACEMENT_PACKAGE_DIAGNOSTIC_API,
    MixedReplacementPackageDiagnosticReport, ReplacementProbeSummary, TEXTURE_REPLACEMENT_ADAPTER,
    diagnose_mixed_replacement_input, probe_additive_static_mesh_input,
    probe_composite_package_input, probe_heterogeneous_replacement_input,
    probe_identity_alias_recovery, probe_input, probe_mixed_armor_input, probe_texture_input,
    stage_input,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

pub const REPORT_SCHEMA: &str = "obr-mod-preflight-report";
pub const REPORT_VERSION: u32 = 8;
pub const MAGIC_LOADER_SIDECAR_API: &str = "magicloader-config-sidecar-v1";
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
    pub magic_loader_config_count: usize,
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
pub struct UpdateDisposition {
    pub code: String,
    pub automatic_update: bool,
    pub runtime_validation_required: bool,
    pub reason: String,
    pub blocker_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalInstallAnalysis {
    pub inventory: Option<ModInventory>,
    pub checks: Vec<CheckResult>,
    pub capabilities: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_compatibility: Option<PluginSetReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additive_contract: Option<AdditiveContractReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_iostore_dependency_probe: Option<MixedIoStoreDependencyReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_replacement_package_diagnostic: Option<MixedReplacementPackageDiagnosticReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layered_iostore_dependency_probe: Option<LayeredIoStoreDependencyReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreal_replacement_probe: Option<ReplacementProbeSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heterogeneous_replacement_probe: Option<HeterogeneousReplacementProbeSummary>,
    pub selected_adapter: Option<String>,
    pub can_update: bool,
    pub status: String,
    pub disposition: UpdateDisposition,
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
    pub worldspace_master_probe: Option<WorldspaceMasterProbeReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_iostore_dependency_probe: Option<MixedIoStoreDependencyReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_replacement_package_diagnostic: Option<MixedReplacementPackageDiagnosticReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layered_iostore_dependency_probe: Option<LayeredIoStoreDependencyReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_alias_recovery_probe: Option<IdentityAliasRecoveryProbeSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magicloader_syncmap_gate: Option<MagicLoaderSyncMapGate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_plan: Option<InstallPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_install_analysis: Option<LogicalInstallAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_pak_passthrough_probe: Option<PakPassthroughProbeSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreal_replacement_probe: Option<ReplacementProbeSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heterogeneous_replacement_probe: Option<HeterogeneousReplacementProbeSummary>,
    pub selected_adapter: Option<String>,
    pub can_update: bool,
    pub status: String,
    pub disposition: UpdateDisposition,
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
    magic_loader_configs_by_root: BTreeMap<String, usize>,
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

fn direct_magic_loader_config_root(path: &str, extension: &str) -> Option<String> {
    if extension != "json" {
        return None;
    }
    let normalized = normalized_path(path);
    let lower = normalized.to_ascii_lowercase();
    let marker = "content/dev/obvdata/data/magicloader/";
    let (root, tail) = if let Some(tail) = lower.strip_prefix(marker) {
        (".".to_owned(), tail)
    } else {
        let needle = format!("/{marker}");
        let index = lower.find(&needle)?;
        (
            normalized[..index].trim_matches('/').to_owned(),
            &lower[index + needle.len()..],
        )
    };
    (!tail.is_empty() && !tail.contains('/')).then_some(if root.is_empty() {
        ".".to_owned()
    } else {
        root
    })
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
        // A mod's IoStore triples may live in `Paks/~mods`, `Paks/mods`, or an
        // author-named subdirectory. The candidate root is the stable
        // `Content/Paks` boundary; later inventory and adapter checks still
        // require complete triples and reject loose functional payloads.
        if let Some(root) = root_before(&path, "/content/paks/") {
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
            if let Some(root) = direct_magic_loader_config_root(&path, &extension) {
                *self.magic_loader_configs_by_root.entry(root).or_default() += 1;
            } else if !documentation {
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
        let esp = *self.plugins.get("esp").unwrap_or(&0);
        let plugin_total = self.plugins.values().sum::<usize>();
        let has_plugins = plugin_total > 0;
        let plugin_only_shape = has_plugins && self.containers.is_empty() && self.scripts == 0;
        // A mod that ships IoStore containers binds its candidate root where the
        // Data and Paks planes agree. A plugin-only mod has no Paks plane at all,
        // so its canonical wrapper root is proven by the Data plane alone; other
        // classifications keep the stricter two-plane binding so the logical
        // install-plan analysis still runs for unrooted mixed layouts.
        let candidate_roots = if plugin_only_shape && self.pak_roots.is_empty() {
            self.data_roots.iter().cloned().collect::<Vec<_>>()
        } else {
            self.data_roots
                .intersection(&self.pak_roots)
                .cloned()
                .collect::<Vec<_>>()
        };
        let roots = candidate_roots.len();
        let candidate_mod_root = (roots == 1).then(|| candidate_roots[0].clone());
        let magic_loader_total = self.magic_loader_configs_by_root.values().sum::<usize>();
        let magic_loader_config_count = candidate_mod_root
            .as_ref()
            .and_then(|root| self.magic_loader_configs_by_root.get(root))
            .copied()
            .unwrap_or(0);
        self.functional_or_unknown_loose +=
            magic_loader_total.saturating_sub(magic_loader_config_count);
        let syncmap_iostore_shape = roots == 1
            && esp == 1
            && plugin_total == 1
            && self.sync_maps == 1
            && complete > 0
            && incomplete == 0
            && self.scripts == 0
            && self.functional_or_unknown_loose == 0;
        let classification = if syncmap_iostore_shape && magic_loader_config_count == 0 {
            "additive-syncmap-iostore"
        } else if syncmap_iostore_shape && magic_loader_config_count > 0 {
            "magicloader-syncmap-iostore"
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
            magic_loader_config_count,
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

fn is_replacement_shape(inventory: &ModInventory) -> bool {
    inventory.classification == "unreal-container-only"
        && inventory.complete_container_triple_count > 0
        && inventory.incomplete_container_count == 0
        && inventory.link_count == 0
        && !inventory.scan_truncated
        && inventory.functional_or_unknown_loose_file_count == 0
        && inventory.file_count
            == inventory.complete_container_triple_count * 3 + inventory.loose_file_count
}

fn inventory_extension_count(inventory: &ModInventory, extension: &str) -> usize {
    inventory
        .extension_counts
        .get(extension)
        .copied()
        .unwrap_or(0)
}

/// A container-only payload made purely of legacy `.pak` files (no IoStore
/// UTOC/UCAS siblings): the shape the legacy pak passthrough lane may prove.
fn is_legacy_pak_only_shape(inventory: &ModInventory) -> bool {
    inventory.classification == "unreal-container-only"
        && inventory_extension_count(inventory, "pak") > 0
        && inventory_extension_count(inventory, "utoc") == 0
        && inventory_extension_count(inventory, "ucas") == 0
        && inventory.complete_container_triple_count == 0
        && inventory.link_count == 0
        && !inventory.scan_truncated
        && inventory.functional_or_unknown_loose_file_count == 0
}

/// A pure UE4SS Lua scripting payload: runtime code the updater must never
/// auto-install, distinct from a standalone tool executable.
fn is_ue4ss_script_payload_shape(inventory: &ModInventory) -> bool {
    inventory.classification == "script-or-loader"
        && inventory_extension_count(inventory, "lua") > 0
        && inventory_extension_count(inventory, "exe") == 0
}

/// A standalone executable tool payload (EXE, optionally with DLLs) with no
/// Lua scripting plane: not mod content that installs into the game.
fn is_standalone_tool_shape(inventory: &ModInventory) -> bool {
    inventory.classification == "script-or-loader"
        && inventory_extension_count(inventory, "exe") > 0
        && inventory_extension_count(inventory, "lua") == 0
}

const AUTHORING_SOURCE_EXTENSIONS: &[&str] = &[
    "fbx", "obj", "blend", "psk", "pskx", "psa", "gltf", "glb", "dae", "3ds", "max", "ma", "mb",
];
const AUTHORING_SIDECAR_EXTENSIONS: &[&str] = &["json", "txt", "xml", "csv"];
const DOCUMENTATION_EXTENSIONS: &[&str] =
    &["txt", "md", "rtf", "pdf", "png", "jpg", "jpeg", "gif", "webp"];

/// A source authoring resource: DCC/editor inputs (FBX, PSK, and similar)
/// plus sidecars and documentation, with nothing that installs into the game.
fn is_authoring_resource_shape(inventory: &ModInventory) -> bool {
    if inventory.classification != "loose-files-or-unknown"
        || inventory.link_count != 0
        || inventory.scan_truncated
    {
        return false;
    }
    let source_count = AUTHORING_SOURCE_EXTENSIONS
        .iter()
        .map(|extension| inventory_extension_count(inventory, extension))
        .sum::<usize>();
    source_count > 0
        && inventory.extension_counts.keys().all(|extension| {
            AUTHORING_SOURCE_EXTENSIONS.contains(&extension.as_str())
                || AUTHORING_SIDECAR_EXTENSIONS.contains(&extension.as_str())
                || DOCUMENTATION_EXTENSIONS.contains(&extension.as_str())
        })
}

fn inspect_logical_install_input(
    request: &PreflightRequest,
) -> Result<(InstallPlan, LogicalInstallAnalysis)> {
    let temporary = tempfile::Builder::new()
        .prefix("obr-install-plan-")
        .tempdir()?;
    let staged = temporary.path().join("physical");
    stage_input(&request.mod_input, &staged)
        .context("staging the selected source for install-layout analysis")?;
    let resolved = resolve_staged_install_view(&staged)?;
    let logical_request = PreflightRequest {
        mod_input: resolved.view.root().to_path_buf(),
        game_root: request.game_root.clone(),
        output_parent: request.output_parent.clone(),
        connected_tools: request.connected_tools.clone(),
    };
    // A materialized logical view is the terminal analysis boundary. If its
    // topology is still noncanonical, reporting that result is useful, but
    // recursively planning the derived view would reproduce the same mapping
    // forever (and could overflow the process stack).
    let report = analyze_internal(&logical_request, &mut |_| {}, false);
    Ok((
        resolved.plan,
        LogicalInstallAnalysis {
            inventory: report.inventory,
            checks: report.checks,
            capabilities: report.capabilities,
            plugin_compatibility: report.plugin_compatibility,
            additive_contract: report.additive_contract,
            mixed_iostore_dependency_probe: report.mixed_iostore_dependency_probe,
            mixed_replacement_package_diagnostic: report.mixed_replacement_package_diagnostic,
            layered_iostore_dependency_probe: report.layered_iostore_dependency_probe,
            unreal_replacement_probe: report.unreal_replacement_probe,
            heterogeneous_replacement_probe: report.heterogeneous_replacement_probe,
            selected_adapter: report.selected_adapter,
            can_update: report.can_update,
            status: report.status,
            disposition: report.disposition,
        },
    ))
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

fn has_portable_executable_magic(path: &Path) -> bool {
    let mut magic = [0_u8; 2];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok()
        && magic == *b"MZ"
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

fn comparable_absolute_path(path: &Path) -> String {
    existing_absolute(path)
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn selects_active_game_mods(request: &PreflightRequest) -> bool {
    if !request.mod_input.is_dir() {
        return false;
    }
    request.game_root.as_deref().is_some_and(|game_root| {
        let active_mods =
            normalize_install_root(game_root).join(r"OblivionRemastered\Content\Paks\~mods");
        active_mods.is_dir()
            && comparable_absolute_path(&request.mod_input)
                == comparable_absolute_path(&active_mods)
    })
}

fn is_direct_mod_container_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts.len() == 4
        && parts[0].eq_ignore_ascii_case("Content")
        && parts[1].eq_ignore_ascii_case("Paks")
        && !parts[2].is_empty()
        && !matches!(parts[2], "." | "..")
        && !parts[2].contains(':')
        && !parts[2].chars().any(char::is_control)
        && Path::new(parts[3])
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("utoc"))
}

fn path_redaction_variants(path: &Path) -> Vec<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|root| root.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut paths = vec![absolute.clone(), existing_absolute(&absolute)];
    if let Some(normalized) = absolute
        .to_string_lossy()
        .strip_prefix(r"\\?\")
        .map(PathBuf::from)
    {
        paths.push(normalized);
    }
    let mut variants = BTreeSet::new();
    for candidate in paths {
        let raw = candidate.to_string_lossy();
        if raw.len() >= 3 {
            variants.insert(raw.to_string());
            variants.insert(raw.replace('\\', "/"));
            variants.insert(raw.replace('/', "\\"));
        }
    }
    let mut variants = variants.into_iter().collect::<Vec<_>>();
    variants.sort_by_key(|value| std::cmp::Reverse(value.len()));
    variants
}

fn redact_preflight_error(error: &anyhow::Error, request: &PreflightRequest) -> String {
    let mut text = format!("{error:#}");
    let temp_root = std::env::temp_dir();
    let mut roots: Vec<(&Path, &str)> = vec![
        (request.mod_input.as_path(), "<MOD_INPUT>"),
        (temp_root.as_path(), "<TEMP>"),
    ];
    if let Some(game_root) = request.game_root.as_ref() {
        roots.push((game_root.as_path(), "<GAME_ROOT>"));
    }
    if let Some(output_root) = request.output_parent.as_ref() {
        roots.push((output_root.as_path(), "<OUTPUT_ROOT>"));
    }
    for tool in &request.connected_tools {
        roots.push((tool.as_path(), "<CONNECTED_TOOL>"));
    }
    let mut redactions = Vec::new();
    for (root, replacement) in roots {
        for variant in path_redaction_variants(root) {
            redactions.push((variant, replacement));
        }
    }
    redactions.sort_by_key(|(variant, _)| std::cmp::Reverse(variant.len()));
    for (variant, replacement) in redactions {
        let pattern = regex::RegexBuilder::new(&regex::escape(&variant))
            .case_insensitive(true)
            .build();
        if let Ok(pattern) = pattern {
            text = pattern.replace_all(&text, replacement).into_owned();
        }
    }
    text
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
    analyze_internal(request, &mut |_| {}, true)
}

pub fn analyze_with_progress(
    request: &PreflightRequest,
    progress: &mut dyn FnMut(&str),
) -> PreflightReport {
    analyze_internal(request, progress, true)
}

fn analyze_internal(
    request: &PreflightRequest,
    progress: &mut dyn FnMut(&str),
    allow_install_plan: bool,
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
        Err(error) => (None, Some(redact_preflight_error(&error, request))),
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
    let needs_install_plan = allow_install_plan
        && inventory.as_ref().is_some_and(|value| {
            value.candidate_mod_root_count == 0
                && !value.scan_truncated
                && matches!(
                    value.classification.as_str(),
                    "mixed-mod" | "loose-files-or-unknown"
                )
        });
    let (install_plan, logical_install_analysis, install_plan_error) = if needs_install_plan {
        progress("Resolving the physical archive layout into a logical install view");
        match inspect_logical_install_input(request) {
            Ok((plan, analysis)) => (Some(plan), Some(analysis), None),
            Err(error) => (None, None, Some(redact_preflight_error(&error, request))),
        }
    } else {
        (None, None, None)
    };
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
    let magic_loader_layout = inventory.as_ref().is_some_and(|value| {
        value.classification == "magicloader-syncmap-iostore"
            && value.magic_loader_config_count > 0
            && value.incomplete_container_count == 0
            && value.link_count == 0
            && !value.scan_truncated
    });
    let candidate_mod_root = inventory
        .as_ref()
        .and_then(|value| value.candidate_mod_root.as_deref());
    let current_game_data = request
        .game_root
        .as_deref()
        .map(normalize_install_root)
        .map(|root| root.join(r"OblivionRemastered\Content\Dev\ObvData\Data"));
    let (plugin_compatibility, additive_contract, worldspace_master_probe) =
        if expected_plugin_count > 0
            && inventory
                .as_ref()
                .is_some_and(|value| !value.scan_truncated)
        {
            progress("Reading plugin headers, masters, FormIDs, and record domains");
            if additive_layout {
                match inspect_additive_contract_input(
                    &request.mod_input,
                    candidate_mod_root,
                    current_game_data.as_deref(),
                ) {
                    Ok((plugin_set, contract)) => {
                        let complex_worldspace = plugin_set.artifacts.iter().any(|artifact| {
                            artifact.masters.len() > 1
                                && artifact
                                    .master_override_type_counts
                                    .keys()
                                    .any(|kind| matches!(kind.as_str(), "CELL" | "REFR" | "WRLD"))
                        });
                        if complex_worldspace
                            && current_game_data.as_ref().is_some_and(|path| path.is_dir())
                        {
                            match inspect_worldspace_master_probe_input(
                                &request.mod_input,
                                candidate_mod_root,
                                current_game_data.as_deref().unwrap(),
                            ) {
                                Ok((plugin_set, probe)) => {
                                    (Some(plugin_set), Some(contract), Some(probe))
                                }
                                Err(_) => (Some(plugin_set), Some(contract), None),
                            }
                        } else {
                            (Some(plugin_set), Some(contract), None)
                        }
                    }
                    Err(_) => (
                        Some(PluginSetReport::unavailable(expected_plugin_count)),
                        None,
                        None,
                    ),
                }
            } else {
                let plugin_set =
                    inspect_plugin_input_at_root(&request.mod_input, candidate_mod_root)
                        .unwrap_or_else(|_| PluginSetReport::unavailable(expected_plugin_count));
                let complex_worldspace = plugin_set.artifacts.iter().any(|artifact| {
                    artifact.masters.len() > 1
                        && artifact
                            .master_override_type_counts
                            .keys()
                            .any(|kind| matches!(kind.as_str(), "CELL" | "REFR" | "WRLD"))
                });
                if (magic_loader_layout || complex_worldspace)
                    && current_game_data.as_ref().is_some_and(|path| path.is_dir())
                {
                    match inspect_worldspace_master_probe_input(
                        &request.mod_input,
                        candidate_mod_root,
                        current_game_data.as_deref().unwrap(),
                    ) {
                        Ok((plugin_set, probe)) => (Some(plugin_set), None, Some(probe)),
                        Err(_) => (Some(plugin_set), None, None),
                    }
                } else {
                    (Some(plugin_set), None, None)
                }
            }
        } else if expected_plugin_count > 0 {
            (
                Some(PluginSetReport::unavailable(expected_plugin_count)),
                None,
                None,
            )
        } else {
            (None, None, None)
        };
    let complex_worldspace_plugin = magic_loader_layout
        || plugin_compatibility.as_ref().is_some_and(|report| {
            report.artifacts.iter().any(|artifact| {
                artifact.masters.len() > 1
                    && artifact
                        .master_override_type_counts
                        .keys()
                        .any(|kind| matches!(kind.as_str(), "CELL" | "REFR" | "WRLD"))
            })
        });
    let additive_shape = additive_layout
        && plugin_compatibility
            .as_ref()
            .is_some_and(|value| value.additive_syncmap_v1.compatible)
        && additive_contract
            .as_ref()
            .is_some_and(|value| value.compatible);
    let replacement_shape = inventory.as_ref().is_some_and(is_replacement_shape);
    let selected_active_game_mods = selects_active_game_mods(request);
    let logical_selected_adapter = logical_install_analysis
        .as_ref()
        .and_then(|analysis| analysis.selected_adapter.as_deref());
    let logical_adapter_matched = logical_install_analysis
        .as_ref()
        .is_some_and(|analysis| analysis.can_update);
    let requires_adapter = additive_layout || replacement_shape || logical_adapter_matched;
    let requires_runtime = additive_shape
        || logical_selected_adapter.is_some_and(|adapter| adapter == "native-additive-syncmap-v1");

    progress("Validating the selected game installation and current metadata");
    let game = request
        .game_root
        .as_deref()
        .map(|path| validate_game_install(path, "preflight"));
    let game_valid = game.as_ref().is_some_and(|value| value.valid);
    let (mixed_iostore_dependency_probe, _mixed_iostore_dependency_probe_error) =
        if magic_loader_layout || additive_layout {
            progress("Tracing mixed IoStore package identities and dependency closure");
            if let Some(game) = game.as_ref().filter(|value| value.valid) {
                match probe_mixed_iostore_dependencies(
                    &request.mod_input,
                    candidate_mod_root,
                    &game.root,
                ) {
                    Ok(report) => (Some(report), None),
                    Err(error) => (None, Some(redact_preflight_error(&error, request))),
                }
            } else {
                (
                    None,
                    Some(
                        "A complete current game is required for mixed IoStore dependency tracing."
                            .to_owned(),
                    ),
                )
            }
        } else {
            (None, None)
        };
    let (mixed_replacement_package_diagnostic, mixed_replacement_diagnostic_error) =
        if replacement_shape {
            progress("Inventorying every replacement package identity and dependency edge");
            if let Some(game) = game.as_ref().filter(|value| value.valid) {
                match diagnose_mixed_replacement_input(
                    &request.mod_input,
                    candidate_mod_root,
                    &game.root,
                ) {
                    Ok(report) => (Some(report), None),
                    Err(_) => (
                        None,
                        Some(
                            "The per-package replacement diagnostic could not inspect the bounded IoStore input."
                                .to_owned(),
                        ),
                    ),
                }
            } else {
                (
                    None,
                    Some(
                        "A complete current game is required for per-package replacement diagnostics."
                            .to_owned(),
                    ),
                )
            }
        } else {
            (None, None)
        };
    let needs_layered_dependency_probe = mixed_replacement_package_diagnostic
        .as_ref()
        .is_some_and(|report| report.dependencies.unresolved_edge_count > 0)
        || mixed_iostore_dependency_probe
            .as_ref()
            .is_some_and(|report| report.dependencies.unresolved_edge_count > 0);
    let (layered_iostore_dependency_probe, layered_iostore_dependency_error) =
        if needs_layered_dependency_probe {
            progress(
                "Resolving dependencies across selected, connected, installed, DLC, and stock layers",
            );
            if let Some(game) = game.as_ref().filter(|value| value.valid) {
                match probe_layered_iostore_dependencies(
                    &request.mod_input,
                    &request.connected_tools,
                    &game.root,
                ) {
                    Ok(report) => (Some(report), None),
                    Err(error) => (None, Some(redact_preflight_error(&error, request))),
                }
            } else {
                (
                    None,
                    Some(
                        "A complete current game is required for layered package resolution."
                            .to_owned(),
                    ),
                )
            }
        } else {
            (None, None)
        };
    let identity_alias_recovery_probe = if magic_loader_layout
        && mixed_iostore_dependency_probe
            .as_ref()
            .is_some_and(|probe| !probe.dependencies.fully_resolved)
    {
        if let Some(game) = game.as_ref().filter(|value| value.valid) {
            progress("Attempting fail-closed identity-alias recovery for stale package imports");
            match probe_identity_alias_recovery(&request.mod_input, &game.root) {
                Ok(summary) => Some(summary),
                Err(error) => Some(IdentityAliasRecoveryProbeSummary {
                    api: IDENTITY_ALIAS_RECOVERY_PROBE_API.to_owned(),
                    status: "unavailable".to_owned(),
                    provider_name: None,
                    alias_count: 0,
                    suppression_count: 0,
                    aliases: Vec::new(),
                    blockers: vec![redact_preflight_error(&error, request)],
                }),
            }
        } else {
            None
        }
    } else {
        None
    };
    let recovered_alias_pairs = identity_alias_recovery_probe
        .iter()
        .flat_map(|probe| {
            probe
                .aliases
                .iter()
                .map(|alias| (alias.consumer_package_id, alias.stale_package_id))
        })
        .collect::<BTreeSet<_>>();
    let mixed_unresolved_recovered = mixed_iostore_dependency_probe
        .as_ref()
        .is_some_and(|probe| {
            !probe.dependencies.fully_resolved
                && !probe.dependencies.unresolved_edges.is_empty()
                && probe.dependencies.unresolved_edges.iter().all(|edge| {
                    recovered_alias_pairs
                        .contains(&(edge.source_package_id, edge.missing_dependency_package_id))
                })
        });
    let magicloader_syncmap_gate = if magic_loader_layout {
        Some(
            inspect_magicloader_syncmap_gate(
                &request.mod_input,
                inventory
                    .as_ref()
                    .and_then(|value| value.candidate_mod_root.as_deref()),
            )
            .unwrap_or_else(|error| MagicLoaderSyncMapGate {
                api: crate::plugin::MAGICLOADER_SYNCMAP_KEY_GATE_API.to_owned(),
                status: "blocked".to_owned(),
                entry_count: 0,
                plugin_owned_key_count: 0,
                blockers: vec![redact_preflight_error(&error, request)],
            }),
        )
    } else {
        None
    };
    let mut magicloader_lane_blockers = Vec::new();
    if magic_loader_layout {
        let semantics_proven = worldspace_master_probe.as_ref().is_some_and(|probe| {
            probe.resolution_complete
                && probe
                    .semantic_gate
                    .as_ref()
                    .is_some_and(|gate| gate.status == "proven")
        });
        if !semantics_proven {
            magicloader_lane_blockers
                .push("current-master-worldspace-semantics-not-proven".to_owned());
        }
        let deletion_policy_proven = worldspace_master_probe.as_ref().is_some_and(|probe| {
            probe.deleted_master_override_count == 0
                || probe
                    .deleted_override_policy
                    .as_ref()
                    .is_some_and(|policy| policy.status == "provable")
        });
        if !deletion_policy_proven {
            magicloader_lane_blockers.push("deleted-master-record-policy-not-proven".to_owned());
        }
        match mixed_iostore_dependency_probe.as_ref() {
            Some(probe) => {
                if probe.collision_count > 0 {
                    magicloader_lane_blockers.push("source-current-package-collisions".to_owned());
                }
                if !probe.dependencies.fully_resolved && !mixed_unresolved_recovered {
                    magicloader_lane_blockers.push("mixed-zen-dependencies-unresolved".to_owned());
                }
            }
            None => magicloader_lane_blockers
                .push("mixed-zen-dependency-probe-unavailable".to_owned()),
        }
        if magicloader_syncmap_gate
            .as_ref()
            .is_none_or(|gate| gate.status != "proven")
        {
            magicloader_lane_blockers.push("syncmap-plugin-key-gate-blocked".to_owned());
        }
        if !game_valid {
            magicloader_lane_blockers.push("current-game-unavailable".to_owned());
        }
    }
    let magicloader_worldspace_gate_ready =
        magic_loader_layout && magicloader_lane_blockers.is_empty();
    let requires_runtime = requires_runtime || magicloader_worldspace_gate_ready;
    // Plugin-only lane: one ESP (plus optional SyncMap/MagicLoader sidecars and
    // documentation), no IoStore containers, no scripts. The lane resolves the
    // physical rooting into the canonical Data plane and proves master
    // resolution plus the current-master semantic gate on that logical view.
    let plugin_only_layout = inventory.as_ref().is_some_and(|value| {
        value.classification == "plugin-only" && value.link_count == 0 && !value.scan_truncated
    });
    let plugin_only_lane = if plugin_only_layout {
        progress("Evaluating the plugin-only Data-plane lane against the current game");
        let mut lane = evaluate_plugin_only_lane(
            &request.mod_input,
            current_game_data.as_deref().filter(|_| game_valid),
        );
        if let Some(count) = inventory
            .as_ref()
            .map(|value| value.functional_or_unknown_loose_file_count)
            .filter(|count| *count > 0)
        {
            lane.blockers.push(format!(
                "functional-or-unknown-loose-files-outside-the-data-plane:count-{count}"
            ));
            lane.blockers.sort();
            lane.blockers.dedup();
            lane.status = "blocked".to_owned();
        }
        Some(lane)
    } else {
        None
    };
    let plugin_only_gate_ready = plugin_only_lane
        .as_ref()
        .is_some_and(|lane| lane.status == "proven");
    let requires_runtime = requires_runtime
        || plugin_only_lane
            .as_ref()
            .is_some_and(|lane| lane.status == "proven" && lane.sync_map_entry_count > 0);
    let (
        armor_probe,
        armor_probe_error,
        mixed_armor_probe,
        mixed_armor_probe_error,
        texture_probe,
        texture_probe_error,
        additive_static_mesh_probe,
        additive_static_mesh_probe_error,
        heterogeneous_replacement_probe,
        heterogeneous_replacement_probe_error,
        composite_package_probe,
        composite_package_probe_error,
    ) = if replacement_shape && !selected_active_game_mods {
        progress("Classifying replacement assets and comparing them with the current game");
        if let Some(game) = game.as_ref().filter(|value| value.valid) {
            match probe_input(&request.mod_input, &game.root) {
                Ok(summary) => (
                    Some(summary),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                Err(armor_error) => match probe_mixed_armor_input(&request.mod_input, &game.root) {
                    Ok(summary) => (
                        None,
                        Some(redact_preflight_error(&armor_error, request)),
                        Some(summary),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                    Err(mixed_error) => match probe_texture_input(&request.mod_input, &game.root) {
                        Ok(summary) => (
                            None,
                            Some(redact_preflight_error(&armor_error, request)),
                            None,
                            Some(redact_preflight_error(&mixed_error, request)),
                            Some(summary),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        ),
                        Err(texture_error) => {
                            match probe_additive_static_mesh_input(&request.mod_input, &game.root) {
                                Ok(summary) => (
                                    None,
                                    Some(redact_preflight_error(&armor_error, request)),
                                    None,
                                    Some(redact_preflight_error(&mixed_error, request)),
                                    None,
                                    Some(redact_preflight_error(&texture_error, request)),
                                    Some(summary),
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                ),
                                Err(static_error) => match probe_heterogeneous_replacement_input(
                                    &request.mod_input,
                                    &game.root,
                                ) {
                                    Ok(summary) => (
                                        None,
                                        Some(redact_preflight_error(&armor_error, request)),
                                        None,
                                        Some(redact_preflight_error(&mixed_error, request)),
                                        None,
                                        Some(redact_preflight_error(&texture_error, request)),
                                        None,
                                        Some(redact_preflight_error(&static_error, request)),
                                        Some(summary),
                                        None,
                                        None,
                                        None,
                                    ),
                                    Err(heterogeneous_error) => {
                                        match probe_composite_package_input(
                                            &request.mod_input,
                                            &game.root,
                                        ) {
                                            Ok(summary) => (
                                                None,
                                                Some(redact_preflight_error(&armor_error, request)),
                                                None,
                                                Some(redact_preflight_error(&mixed_error, request)),
                                                None,
                                                Some(redact_preflight_error(
                                                    &texture_error,
                                                    request,
                                                )),
                                                None,
                                                Some(redact_preflight_error(
                                                    &static_error,
                                                    request,
                                                )),
                                                None,
                                                Some(redact_preflight_error(
                                                    &heterogeneous_error,
                                                    request,
                                                )),
                                                Some(summary),
                                                None,
                                            ),
                                            Err(composite_error) => (
                                                None,
                                                Some(redact_preflight_error(&armor_error, request)),
                                                None,
                                                Some(redact_preflight_error(&mixed_error, request)),
                                                None,
                                                Some(redact_preflight_error(
                                                    &texture_error,
                                                    request,
                                                )),
                                                None,
                                                Some(redact_preflight_error(
                                                    &static_error,
                                                    request,
                                                )),
                                                None,
                                                Some(redact_preflight_error(
                                                    &heterogeneous_error,
                                                    request,
                                                )),
                                                None,
                                                Some(redact_preflight_error(
                                                    &composite_error,
                                                    request,
                                                )),
                                            ),
                                        }
                                    }
                                },
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
                None,
                Some(
                    "A complete target game is required for heterogeneous package classification."
                        .to_owned(),
                ),
                None,
                Some(
                    "A complete target game is required for composite package classification."
                        .to_owned(),
                ),
            )
        }
    } else if replacement_shape {
        let message = "Class-specific update probes were not run against the active game ~mods directory; select one original mod archive or its complete extracted root.".to_owned();
        (
            None,
            Some(message.clone()),
            None,
            Some(message.clone()),
            None,
            Some(message.clone()),
            None,
            Some(message),
            None,
            Some(
                "Heterogeneous package probes are not run against the active game ~mods directory."
                    .to_owned(),
            ),
            None,
            Some(
                "Composite package probes are not run against the active game ~mods directory."
                    .to_owned(),
            ),
        )
    } else {
        (
            None, None, None, None, None, None, None, None, None, None, None, None,
        )
    };
    let (additive_composite_probe, additive_composite_probe_error) = if additive_shape
        && !selected_active_game_mods
    {
        progress("Proving the additive mod's composite Unreal package migration");
        if let Some(game) = game.as_ref().filter(|value| value.valid) {
            match probe_composite_package_input(&request.mod_input, &game.root) {
                Ok(summary) => (Some(summary), None),
                Err(error) => (None, Some(redact_preflight_error(&error, request))),
            }
        } else {
            (
                    None,
                    Some(
                        "A complete target game is required for additive composite package classification."
                            .to_owned(),
                    ),
                )
        }
    } else {
        (None, None)
    };
    let composite_package_probe = composite_package_probe.or(additive_composite_probe);
    let composite_package_probe_error =
        composite_package_probe_error.or(additive_composite_probe_error);
    let replacement_probe = armor_probe
        .as_ref()
        .or(mixed_armor_probe.as_ref())
        .or(texture_probe.as_ref())
        .or(additive_static_mesh_probe.as_ref())
        .or(composite_package_probe.as_ref())
        .cloned();
    let pak_passthrough_shape = inventory.as_ref().is_some_and(is_legacy_pak_only_shape);
    let (legacy_pak_passthrough_probe, legacy_pak_passthrough_probe_error) =
        if pak_passthrough_shape && !selected_active_game_mods {
            progress("Validating legacy pak integrity and current-game audio targets");
            if let Some(game) = game.as_ref().filter(|value| value.valid) {
                match probe_legacy_pak_passthrough_input(&request.mod_input, &game.root) {
                    Ok(summary) => (Some(summary), None),
                    Err(error) => (None, Some(redact_preflight_error(&error, request))),
                }
            } else {
                (
                    None,
                    Some(
                        "A complete current game is required to prove legacy pak audio targets."
                            .to_owned(),
                    ),
                )
            }
        } else {
            (None, None)
        };
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
    let magic_loader_executable = game
        .as_ref()
        .filter(|value| value.valid)
        .map(|value| value.root.join(r"MagicLoader\MagicLoader.exe"));
    let magic_loader_present = magic_loader_executable
        .as_ref()
        .is_some_and(|path| path.is_file());
    let magic_loader_installed = magic_loader_executable
        .as_ref()
        .is_some_and(|path| has_portable_executable_magic(path));
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
    if magic_loader_layout {
        let components = magic_loader_executable
            .as_ref()
            .filter(|path| path.is_file())
            .map(|path| {
                vec![ToolComponent {
                    name: "MagicLoader.exe".to_owned(),
                    bytes: path
                        .metadata()
                        .map(|metadata| metadata.len() as usize)
                        .unwrap_or(0),
                    sha256: sha256_file(path).unwrap_or_else(|_| "unreadable".to_owned()),
                    portable_executable: has_portable_executable_magic(path),
                }]
            })
            .unwrap_or_default();
        tools.push(ToolStatus {
            id: "magic-loader".to_owned(),
            display_name: "MagicLoader runtime".to_owned(),
            source: "game-install".to_owned(),
            status: if magic_loader_installed {
                "installed"
            } else if magic_loader_present {
                "invalid-runtime-dependency"
            } else {
                "missing-runtime-dependency"
            }
            .to_owned(),
            required_for_selected_adapter: false,
            candidate_count: 0,
            components,
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
            "source-is-not-active-game-mods",
            !selected_active_game_mods,
            true,
            "The selected mod input is separate from the active game ~mods directory.",
            "The selected input is the active game ~mods directory, which can mix unrelated installed mods and omit an archive's ESP, SyncMap, sidecars, or wrapper root.",
            Some(
                "Select the original mod archive or its complete extracted root. Use the installed-mod scan for the active ~mods directory.",
            ),
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
    if needs_install_plan {
        checks.push(CheckResult {
            id: "logical-install-layout".to_owned(),
            status: if install_plan.is_some() { "pass" } else { "warning" }.to_owned(),
            blocking: false,
            message: install_plan
                .as_ref()
                .map(|plan| {
                    format!(
                        "Resolved {} physical payload mapping(s) into a source-agnostic logical install view using {:?} evidence; {} option group(s) remain explicit.",
                        plan.mappings.len(),
                        plan.evidence,
                        plan.choice_groups.len(),
                    )
                })
                .unwrap_or_else(|| {
                    install_plan_error.clone().unwrap_or_else(|| {
                        "No bounded logical install layout could be inferred.".to_owned()
                    })
                }),
            remediation: install_plan.is_none().then(|| {
                "Use a canonical game-relative layout, a bounded FOMOD with explicit file mappings, or matching Place-in-Data/Place-in-Paks folders with complete container triples."
                    .to_owned()
            }),
        });
    }
    if magic_loader_layout {
        checks.push(CheckResult {
            id: "magic-loader-sidecar".to_owned(),
            status: "pass".to_owned(),
            blocking: false,
            message: format!(
                "Recognized {} path-bound MagicLoader configuration file(s) as functional runtime sidecars.",
                inventory
                    .as_ref()
                    .map(|value| value.magic_loader_config_count)
                    .unwrap_or(0)
            ),
            remediation: None,
        });
        checks.push(CheckResult {
            id: "magic-loader-runtime".to_owned(),
            status: if magic_loader_installed {
                "pass"
            } else {
                "warning"
            }
            .to_owned(),
            blocking: false,
            message: if magic_loader_installed {
                "MagicLoader.exe has a readable Windows executable signature in the expected game-root MagicLoader folder. Its version and runtime behavior are not claimed."
                    .to_owned()
            } else if magic_loader_present {
                "A file named MagicLoader.exe exists in the expected game-root folder, but it does not have a readable Windows executable signature."
                    .to_owned()
            } else {
                "This mod includes a MagicLoader configuration, but MagicLoader.exe was not found in the expected game-root MagicLoader folder."
                    .to_owned()
            },
            remediation: (!magic_loader_installed).then(|| {
                "Install MagicLoader 2 beside OblivionRemastered.exe before running this mod; the updater does not install an unverified MagicLoader payload."
                    .to_owned()
            }),
        });
    }
    if let Some(plugin_report) = plugin_compatibility.as_ref() {
        let metadata_staging_failed = plugin_report.scan_mode == "unavailable";
        checks.push(check(
            "plugin-content-analysis",
            plugin_report.status == "complete"
                && plugin_report.parsed_plugin_count == plugin_report.plugin_count,
            additive_layout,
            format!(
                "Parsed and fingerprinted {} plugin file(s) without rewriting them.",
                plugin_report.plugin_count
            ),
            if metadata_staging_failed {
                "Plugin metadata could not be staged or analyzed safely; this does not prove the ESP/ESM/ESL itself is malformed."
            } else {
                "One or more ESP/ESM/ESL files could not be parsed safely."
            },
            Some(if metadata_staging_failed {
                "Repack the archive or send the report so its archive staging failure can be reproduced."
            } else {
                "Repair or replace malformed plugins before attempting an update."
            }),
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
                "The plugin matches the one-full-ESP inventory-addition policy with Oblivion.esm first in its full-master chain.",
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
                "The SyncMap is non-empty, every mapped FormID is plugin-owned, and every supported CONT, CREA, or NPC_ inventory override is compatible with the installed master chain.",
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
                Some("Use a non-empty SyncMap whose local IDs exist in the ESP. Inventory overrides may add entries, but conflicting changes to installed master rows remain report-only."),
            ));
        }
        if complex_worldspace_plugin {
            let declared_master_count = plugin_report
                .artifacts
                .iter()
                .map(|artifact| artifact.masters.len())
                .sum::<usize>();
            let master_override_count = plugin_report
                .artifacts
                .iter()
                .map(|artifact| artifact.master_override_record_count)
                .sum::<usize>();
            let deleted_record_count = plugin_report
                .artifacts
                .iter()
                .map(|artifact| artifact.deleted_record_count)
                .sum::<usize>();
            let mut override_types = BTreeMap::<String, usize>::new();
            for artifact in &plugin_report.artifacts {
                for (kind, count) in &artifact.master_override_type_counts {
                    *override_types.entry(kind.clone()).or_default() += count;
                }
            }
            let override_summary = override_types
                .iter()
                .map(|(kind, count)| format!("{kind}={count}"))
                .collect::<Vec<_>>()
                .join(", ");
            let worldspace_gates_proven = worldspace_master_probe.as_ref().is_some_and(|probe| {
                probe.resolution_complete
                    && probe
                        .semantic_gate
                        .as_ref()
                        .is_some_and(|gate| gate.status == "proven")
                    && (probe.deleted_master_override_count == 0
                        || probe
                            .deleted_override_policy
                            .as_ref()
                            .is_some_and(|policy| policy.status == "provable"))
            });
            checks.push(CheckResult {
                id: "mixed-worldspace-plugin-semantics".to_owned(),
                status: if worldspace_gates_proven { "pass" } else { "warning" }.to_owned(),
                blocking: false,
                message: if worldspace_gates_proven {
                    format!(
                        "The ESP declares {declared_master_count} master(s) and {master_override_count} master override(s) ({override_summary}), with {deleted_record_count} deleted record(s). Every live override passed the per-subrecord current-master semantic gate and every deletion stub satisfies the fail-closed undelete-and-disable witness contract; disclosed revert-risk fields still require the shipping-game runtime test."
                    )
                } else {
                    format!(
                        "The ESP declares {declared_master_count} master(s) and {master_override_count} master override(s) ({override_summary}), with {deleted_record_count} deleted record(s). Byte preservation proves identity, not compatibility for current CELL/REFR/WRLD or deleted-record semantics."
                    )
                },
                remediation: (!worldspace_gates_proven).then(|| {
                    "Keep this archive report-only until a bridge-aware multi-master adapter resolves current master records and has an explicit deleted-REFR policy."
                        .to_owned()
                }),
            });
        }
        if magic_loader_layout {
            if let Some(probe) = mixed_iostore_dependency_probe.as_ref() {
                checks.push(CheckResult {
                id: "mixed-iostore-package-identity".to_owned(),
                status: if probe.collision_count == 0 {
                    "pass"
                } else {
                    "warning"
                }
                .to_owned(),
                blocking: false,
                message: format!(
                    "Inventoried {} package(s) in {} UTOC container(s): {} are additive and {} source/current collision(s) were found.",
                    probe.source_package_count,
                    probe.container_count,
                    probe.additive_package_count,
                    probe.collision_count,
                ),
                remediation: (probe.collision_count > 0).then(|| {
                    "Keep this mod report-only until each replacement package has a class-specific current-game rebase contract."
                        .to_owned()
                }),
            });
                let unresolved_summary = probe
                    .dependencies
                    .unresolved_edges
                    .iter()
                    .take(8)
                    .map(|edge| {
                        if edge.authored_package_names.is_empty() {
                            format!(
                                "{} -> {}",
                                edge.source_package_path, edge.missing_dependency_package_id
                            )
                        } else {
                            format!(
                                "{} -> {} (authored import name: {})",
                                edge.source_package_path,
                                edge.missing_dependency_package_id,
                                edge.authored_package_names.join(", ")
                            )
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                checks.push(CheckResult {
                id: "mixed-iostore-dependency-closure".to_owned(),
                status: if probe.dependencies.fully_resolved || mixed_unresolved_recovered {
                    "pass"
                } else {
                    "warning"
                }
                .to_owned(),
                blocking: false,
                message: if probe.dependencies.fully_resolved {
                    format!(
                        "Resolved all {} package dependency edge(s) against bundled mod or current-game packages.",
                        probe.dependencies.dependency_edge_count
                    )
                } else if mixed_unresolved_recovered {
                    format!(
                        "Resolved {}/{} package dependency edge(s) directly; the remaining {} stale import(s) recover to disclosed, role-proven bundled identity aliases: {unresolved_summary}",
                        probe.dependencies.resolved_edge_count,
                        probe.dependencies.dependency_edge_count,
                        probe.dependencies.unresolved_edge_count
                    )
                } else {
                    format!(
                        "Found {} unresolved package dependency edge(s): {unresolved_summary}",
                        probe.dependencies.unresolved_edge_count
                    )
                },
                remediation: (!probe.dependencies.fully_resolved && !mixed_unresolved_recovered).then(|| {
                    "Use a current-version mod package that removes the stale assets, or wait for a class- and shader-aware repair adapter; unresolved package IDs are never dropped automatically."
                        .to_owned()
                }),
            });
            } else {
                checks.push(CheckResult {
                    id: "mixed-iostore-dependency-closure".to_owned(),
                    status: "warning".to_owned(),
                    blocking: false,
                    message: "The report-only mixed IoStore dependency probe could not complete."
                        .to_owned(),
                    remediation: Some(
                        "Connect a complete current game and provide intact UTOC/UCAS package-store data within the bounded probe limit. Absolute setup paths are not serialized into the shareable report."
                            .to_owned(),
                    ),
                });
            }
            checks.push(check(
                "magicloader-worldspace-gate",
                magicloader_worldspace_gate_ready,
                true,
                "The MagicLoader worldspace lane gates passed: current-master override semantics, the undelete-and-disable deletion policy, the package dependency closure, and the SyncMap plugin-key gate are all proven.",
                format!(
                    "The MagicLoader worldspace lane is blocked: {}",
                    magicloader_lane_blockers.join(", ")
                ),
                Some("Each named gate fails closed; the mod stays report-only until every gate is proven against the current game."),
            ));
        }
    }
    if complex_worldspace_plugin {
        if let Some(probe) = worldspace_master_probe.as_ref() {
            let identity_resolved = probe.found_master_count == probe.declared_master_count
                && probe.parsed_master_count == probe.declared_master_count
                && probe.resolved_master_override_count == probe.master_override_count
                && probe.unresolved_master_override_count == 0
                && probe.type_mismatch_override_count == 0;
            checks.push(CheckResult {
                id: "worldspace-master-resolution".to_owned(),
                status: if identity_resolved { "pass" } else { "warning" }.to_owned(),
                blocking: false,
                message: format!(
                    "Resolved {}/{} master override target(s) through {}/{} installed master(s), with {} unresolved target(s), {} type mismatch(es), and {} deleted override(s). This proves record identity only, not field semantics.",
                    probe.resolved_master_override_count,
                    probe.master_override_count,
                    probe.parsed_master_count,
                    probe.declared_master_count,
                    probe.unresolved_master_override_count,
                    probe.type_mismatch_override_count,
                    probe.deleted_master_override_count,
                ),
                remediation: (!identity_resolved).then(|| {
                    "Install the exact declared masters and keep this mod report-only until every override target resolves to the same current record type."
                        .to_owned()
                }),
            });
            let risk_tier = if probe.deleted_master_override_count > 0 {
                "high-deletion-semantics"
            } else {
                "elevated-broad-override-semantics"
            };
            checks.push(CheckResult {
                id: "complex-worldspace-plugin-risk".to_owned(),
                status: "warning".to_owned(),
                blocking: false,
                message: format!(
                    "Classified the immutable TES plugin plane as {risk_tier}. Master identity/type resolution is {}, but CELL/REFR/WRLD field behavior and save/runtime semantics are not automatically rewritten or claimed.",
                    if identity_resolved { "complete" } else { "incomplete" }
                ),
                remediation: Some(
                    "Keep automatic installation disabled and test the byte-preserved plugin with its exact declared masters in the shipping game."
                        .to_owned(),
                ),
            });
        } else {
            checks.push(CheckResult {
                id: "worldspace-master-resolution".to_owned(),
                status: "warning".to_owned(),
                blocking: false,
                message: "The read-only multi-master override probe could not run without a valid current game Data directory."
                    .to_owned(),
                remediation: Some(
                    "Connect a complete current game installation to resolve the ESP's declared masters and override targets."
                        .to_owned(),
                ),
            });
        }
    }
    if additive_layout {
        let publishable_container_layout =
            mixed_iostore_dependency_probe
                .as_ref()
                .is_some_and(|probe| {
                    probe
                        .containers
                        .iter()
                        .all(|container| is_direct_mod_container_path(&container.relative_path))
                });
        checks.push(check(
            "additive-container-layout",
            publishable_container_layout,
            true,
            "Every additive container is in one direct child folder of Content/Paks, and the native publisher preserves that folder.",
            "One or more additive containers are nested more deeply below Content/Paks or split across physical folders.",
            Some(
                "Place every complete container triple together in one direct child folder of Content/Paks.",
            ),
        ));
        let dependency_closure = mixed_iostore_dependency_probe
            .as_ref()
            .is_some_and(|probe| probe.collision_count == 0 && probe.dependencies.fully_resolved)
            || composite_package_probe.is_some();
        let failure = mixed_iostore_dependency_probe
            .as_ref()
            .map(|probe| {
                format!(
                    "The additive package set has {} source/current collision(s) and {} unresolved dependency edge(s), and those edges did not pass the guarded composite identity-recovery contract.",
                    probe.collision_count, probe.dependencies.unresolved_edge_count
                )
            })
            .unwrap_or_else(|| {
                "The additive package dependency closure could not be inspected against the current game."
                    .to_owned()
            });
        checks.push(check(
            "additive-iostore-dependency-closure",
            dependency_closure,
            true,
            "Every additive package dependency resolves from the selected mod or current game, with no source/current package collisions.",
            failure,
            Some(
                "Bundle every required package with the selected mod or update the mod against the current game. Dependencies supplied only by unrelated installed mods are reported diagnostically but are not used to authorize an update.",
            ),
        ));
    }
    if replacement_shape {
        if let Some(diagnostic) = mixed_replacement_package_diagnostic.as_ref() {
            checks.push(CheckResult {
                id: "replacement-package-identity".to_owned(),
                status: if diagnostic.conflict_package_count == 0
                    && diagnostic.root_alias_replacement_count == 0
                {
                    "pass"
                } else {
                    "warning"
                }
                .to_owned(),
                blocking: false,
                message: format!(
                    "Inventoried {} package(s) in {} container(s): {} exact replacement(s), {} root-alias replacement(s) resolved only by their unique package IDs, {} additive package(s), and {} path/package-ID conflict(s).",
                    diagnostic.source_package_count,
                    diagnostic.container_count,
                    diagnostic.exact_replacement_count,
                    diagnostic.root_alias_replacement_count,
                    diagnostic.additive_package_count,
                    diagnostic.conflict_package_count,
                ),
                remediation: if diagnostic.conflict_package_count > 0 {
                    Some(
                        "Keep conflicting packages report-only until their current identity and intended target are unambiguous."
                            .to_owned(),
                    )
                } else if diagnostic.root_alias_replacement_count > 0 {
                    Some(
                        "Root-alias packages are stored at their container mount root; the diagnostic warnings list each unique package-ID resolution."
                            .to_owned(),
                    )
                } else {
                    None
                },
            });
            let unresolved_summary = diagnostic
                .dependencies
                .unresolved_edges
                .iter()
                .take(8)
                .map(|edge| {
                    format!(
                        "{} -> {}",
                        edge.source_package_path, edge.missing_dependency_package_id
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            checks.push(CheckResult {
                id: "replacement-dependency-closure".to_owned(),
                status: if diagnostic.dependencies.fully_resolved {
                    "pass"
                } else {
                    "warning"
                }
                .to_owned(),
                blocking: false,
                message: if diagnostic.dependencies.fully_resolved {
                    format!(
                        "Resolved all {} replacement dependency edge(s) against bundled or stock-main-game packages.",
                        diagnostic.dependencies.dependency_edge_count
                    )
                } else {
                    format!(
                        "Found {} unresolved replacement dependency edge(s): {unresolved_summary}",
                        diagnostic.dependencies.unresolved_edge_count
                    )
                },
                remediation: (!diagnostic.dependencies.fully_resolved).then(|| {
                    "Unresolved package IDs are never removed automatically; keep this input report-only until a class-aware repair is proven."
                        .to_owned()
                }),
            });
        } else {
            checks.push(CheckResult {
                id: "replacement-package-diagnostic".to_owned(),
                status: "warning".to_owned(),
                blocking: false,
                message: mixed_replacement_diagnostic_error.clone().unwrap_or_else(|| {
                    "The per-package replacement diagnostic was unavailable.".to_owned()
                }),
                remediation: Some(
                    "Connect a complete current game and provide the intact original archive or complete extracted mod root."
                        .to_owned(),
                ),
            });
        }
    }
    if needs_layered_dependency_probe {
        checks.push(CheckResult {
            id: "layered-iostore-dependency-closure".to_owned(),
            status: layered_iostore_dependency_probe
                .as_ref()
                .map(|report| if report.resolution_complete { "pass" } else { "warning" })
                .unwrap_or("warning")
                .to_owned(),
            blocking: false,
            message: layered_iostore_dependency_probe
                .as_ref()
                .map(|report| {
                    let excluded = if report.excluded_incomplete_container_count > 0 {
                        format!(
                            " {} incomplete PAK/UCAS/UTOC container group(s) were excluded from resolution: {}.",
                            report.excluded_incomplete_container_count,
                            report.excluded_incomplete_containers.join("; "),
                        )
                    } else {
                        String::new()
                    };
                    format!(
                        "Resolved {}/{} reachable dependency edge(s) across {} provider(s) with explicit precedence; {} edge(s) remain unresolved and {} cross-layer collision(s) were recorded.{excluded}",
                        report.resolved_edge_count,
                        report.dependency_edge_count,
                        report.provider_count,
                        report.unresolved_edge_count,
                        report.cross_layer_collision_count,
                    )
                })
                .unwrap_or_else(|| {
                    layered_iostore_dependency_error.clone().unwrap_or_else(|| {
                        "The layered IoStore dependency probe was unavailable.".to_owned()
                    })
                }),
            remediation: if layered_iostore_dependency_probe
                .as_ref()
                .is_some_and(|report| report.resolution_complete)
            {
                None
            } else {
                Some("Connect the missing dependency mod, remove ambiguous same-layer providers, or use a source version whose imports resolve under the reported precedence.".to_owned())
            },
        });
    }
    if replacement_shape {
        let passed = replacement_probe.is_some()
            || heterogeneous_replacement_probe.is_some()
            || composite_package_probe.is_some();
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
            })
            .or_else(|| {
                heterogeneous_replacement_probe.as_ref().map(|summary| {
                    let warning_count = summary
                        .packages
                        .iter()
                        .map(|package| package.warnings.len())
                        .sum::<usize>();
                    format!(
                        "The input contains {} independently proven package(s) in {} complete container(s): {} StaticMesh and {} Texture2D package(s), with current package-ID/path-or-content-alias evidence, complete dependency closure, and {} disclosed diagnostic warning(s).",
                        summary.package_count,
                        summary.container_count,
                        summary.static_mesh_count,
                        summary.texture_count,
                        warning_count,
                    )
                })
            })
            .or_else(|| {
                composite_package_probe.as_ref().map(|summary| {
                    format!(
                        "The input contains {} package(s) in {} complete container(s) accepted by the system-wide composite rebase contract: {}. Every decoded package class, identity, stale import repair, and authored export payload passed its guarded probe.",
                        summary.package_count, summary.container_count, summary.asset_kind
                    )
                })
            });
        let failure = format!(
            "No proven content adapter accepted every package. Armor: {} Mixed armor: {} Texture2D: {} StaticMesh: {} Heterogeneous StaticMesh/Texture2D: {} Composite package rebase: {}",
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
                .unwrap_or("not evaluated as a StaticMesh container."),
            heterogeneous_replacement_probe_error
                .as_deref()
                .unwrap_or("not evaluated as a heterogeneous replacement container."),
            composite_package_probe_error
                .as_deref()
                .unwrap_or("not evaluated by the composite package contract.")
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
    if pak_passthrough_shape {
        let success = legacy_pak_passthrough_probe
            .as_ref()
            .map(|summary| {
                format!(
                    "The input is a legacy .pak-only payload on the {} content plane: {} pak(s), {} hash-verified entr(ies), all present in the current game's shipped pak index.",
                    WWISE_AUDIO_MEDIA_PLANE, summary.pak_count, summary.entry_count
                )
            })
            .unwrap_or_default();
        let failure = legacy_pak_passthrough_probe_error
            .clone()
            .unwrap_or_else(|| "The legacy pak passthrough contract was not evaluated.".to_owned());
        checks.push(check(
            "legacy-pak-passthrough-contract",
            legacy_pak_passthrough_probe.is_some(),
            true,
            success,
            failure,
            Some(
                "Encrypted, structurally inconsistent, or non-audio legacy paks and entries absent from the current game remain report-only until their planes are proven.",
            ),
        ));
    }
    let adapter_blockers = checks
        .iter()
        .filter(|value| value.blocking)
        .map(|value| value.id.clone())
        .collect::<Vec<_>>();
    let additive_dependency_closure = mixed_iostore_dependency_probe
        .as_ref()
        .is_some_and(|probe| probe.collision_count == 0 && probe.dependencies.fully_resolved)
        || (additive_shape && composite_package_probe.is_some());
    let additive_can_update =
        additive_shape && additive_dependency_closure && adapter_blockers.is_empty();
    let magicloader_can_update =
        magicloader_worldspace_gate_ready && adapter_blockers.is_empty();
    let armor_can_update =
        replacement_shape && armor_probe.is_some() && adapter_blockers.is_empty();
    let mixed_armor_can_update =
        replacement_shape && mixed_armor_probe.is_some() && adapter_blockers.is_empty();
    let texture_can_update =
        replacement_shape && texture_probe.is_some() && adapter_blockers.is_empty();
    let additive_static_mesh_can_update =
        replacement_shape && additive_static_mesh_probe.is_some() && adapter_blockers.is_empty();
    let heterogeneous_replacement_can_update = replacement_shape
        && heterogeneous_replacement_probe.is_some()
        && adapter_blockers.is_empty();
    let composite_package_can_update =
        replacement_shape && composite_package_probe.is_some() && adapter_blockers.is_empty();
    let pak_passthrough_can_update = pak_passthrough_shape
        && legacy_pak_passthrough_probe.is_some()
        && adapter_blockers.is_empty();
    let plugin_only_can_update = plugin_only_gate_ready && adapter_blockers.is_empty();
    let direct_can_update = additive_can_update
        || magicloader_can_update
        || armor_can_update
        || mixed_armor_can_update
        || texture_can_update
        || additive_static_mesh_can_update
        || heterogeneous_replacement_can_update
        || composite_package_can_update
        || pak_passthrough_can_update
        || plugin_only_can_update;
    let logical_publication_adapter = install_plan
        .as_ref()
        .filter(|plan| supports_logical_install_publication(plan))
        .and(logical_install_analysis.as_ref())
        .filter(|analysis| analysis.can_update)
        .and_then(|analysis| analysis.selected_adapter.as_deref())
        .and_then(|adapter| logical_install_adapter_id(adapter).ok());
    let logical_install_can_update =
        logical_publication_adapter.is_some() && adapter_blockers.is_empty();
    let can_update = direct_can_update || logical_install_can_update;
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
        id: crate::install_plan::INSTALL_PLAN_API.to_owned(),
        available: install_plan.is_some(),
        evidence_level: "bounded-physical-to-logical-install-mapping".to_owned(),
        description: "Separates archive paths from logical game destinations, understands canonical roots, bounded explicit FOMOD file mappings, and conservative Place-in-Data/Place-in-Paks structures, preserves option groups, and rejects traversal, links, incomplete triples, and destination collisions.".to_owned(),
        blockers: if install_plan.is_some() {
            Vec::new()
        } else if needs_install_plan {
            vec!["logical-install-layout-unresolved".to_owned()]
        } else {
            vec!["physical-layout-already-canonical-or-not-applicable".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: LOGICAL_INSTALL_PUBLICATION_API.to_owned(),
        available: logical_install_can_update,
        evidence_level: "immutable-plan-nested-adapter-physical-reconstruction".to_owned(),
        description: "Publishes a proven nested adapter through a choice-free canonical or manual-structural install plan. The complete physical source is hash-snapshotted, only adapter-owned mapped IoStore payloads may change, original wrapper and pass-through paths are reconstructed, fresh preflight must reproduce the plan, and the portable archive is reopened and verified.".to_owned(),
        blockers: if logical_install_can_update {
            Vec::new()
        } else if install_plan.is_some() {
            vec!["logical-install-publication-not-implemented".to_owned()]
        } else {
            vec!["logical-install-plan-not-applicable".to_owned()]
        },
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
        id: MAGIC_LOADER_SIDECAR_API.to_owned(),
        available: magic_loader_layout,
        evidence_level: "path-bound-functional-sidecar-inventory".to_owned(),
        description: "Recognizes JSON configuration files directly under the selected mod root's Content/Dev/ObvData/Data/MagicLoader folder, keeps them distinct from documentation and unknown loose payloads, and reports the separate MagicLoader runtime requirement. Recognition alone never enables an update adapter.".to_owned(),
        blockers: if magic_loader_layout {
            Vec::new()
        } else {
            vec!["no-path-bound-magicloader-config-sidecar".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: WORLDSPACE_MASTER_PROBE_API.to_owned(),
        available: worldspace_master_probe.is_some(),
        evidence_level: "esp-declared-master-order-record-identity".to_owned(),
        description: "Resolves a multi-master worldspace ESP's override targets in the ESP-declared master order against the matching installed files, using defining-plugin plus local FormID identity, and requires current record-type agreement. This read-only probe never claims field semantics or enables mutation.".to_owned(),
        blockers: worldspace_master_probe
            .as_ref()
            .map(|probe| probe.blockers.clone())
            .unwrap_or_else(|| vec!["worldspace-master-probe-not-run".to_owned()]),
    });
    capabilities.push(Capability {
        id: "tes4-complex-worldspace-risk-classification-v1".to_owned(),
        available: complex_worldspace_plugin,
        evidence_level: "immutable-plugin-master-resolution-and-record-domain-risk".to_owned(),
        description: "Classifies multi-master CELL/REFR/WRLD plugin planes separately from Unreal conversion, preserves plugin bytes, resolves current master identities and record types when possible, and keeps automatic installation disabled because field, deletion, save, and runtime semantics are not rewritten or claimed.".to_owned(),
        blockers: if complex_worldspace_plugin {
            vec!["shipping-game-runtime-validation-required".to_owned()]
        } else {
            vec!["no-complex-worldspace-plugin-plane".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: MIXED_IOSTORE_DEPENDENCY_PROBE_API.to_owned(),
        available: mixed_iostore_dependency_probe.is_some(),
        evidence_level: "selected-bounded-iostore-package-store-graph".to_owned(),
        description: "Stages only bounded source UTOC/UCAS package-store data, compares package paths and IDs with the current game, and reports every resolved or unresolved dependency edge without enabling conversion.".to_owned(),
        blockers: mixed_iostore_dependency_probe
            .as_ref()
            .map(|probe| probe.blockers.clone())
            .unwrap_or_else(|| vec!["mixed-iostore-dependency-probe-not-run".to_owned()]),
    });
    capabilities.push(Capability {
        id: MIXED_REPLACEMENT_PACKAGE_DIAGNOSTIC_API.to_owned(),
        available: mixed_replacement_package_diagnostic.is_some(),
        evidence_level: "current-stock-main-package-store-identity-and-dependency-graph".to_owned(),
        description: "Inventories every package in heterogeneous Unreal-container-only inputs, preserves its container/path/ID/import evidence, distinguishes exact stock-main replacements from additions and identity conflicts, and reports the complete dependency closure against bundled and stock-main packages. Installed-mod precedence, other game containers, export classes, and mutation are not claimed.".to_owned(),
        blockers: mixed_replacement_package_diagnostic
            .as_ref()
            .map(|diagnostic| diagnostic.blockers.clone())
            .unwrap_or_else(|| vec!["mixed-replacement-package-diagnostic-not-run".to_owned()]),
    });
    capabilities.push(Capability {
        id: LAYERED_IOSTORE_DEPENDENCY_API.to_owned(),
        available: layered_iostore_dependency_probe
            .as_ref()
            .is_some_and(|report| report.resolution_complete),
        evidence_level: "deterministic-multi-provider-package-store-precedence".to_owned(),
        description: "Resolves transitive imports in explicit order across the selected mod, connected dependency mods, installed active mods, game/DLC containers, and stock main data. Same-layer ambiguity fails closed; cross-layer shadowing and every selected provider remain visible in the report.".to_owned(),
        blockers: layered_iostore_dependency_probe
            .as_ref()
            .map(|report| report.blockers.clone())
            .unwrap_or_else(|| {
                if needs_layered_dependency_probe {
                    vec!["layered-iostore-dependency-probe-unavailable".to_owned()]
                } else {
                    vec!["stock-or-bundled-dependency-closure-was-already-complete".to_owned()]
                }
            }),
    });
    capabilities.push(Capability {
        id: "native-magicloader-worldspace-syncmap-v1".to_owned(),
        available: magicloader_can_update,
        evidence_level: if magicloader_can_update {
            "guarded-structural-adapter".to_owned()
        } else {
            "report-only-cross-plane-inventory".to_owned()
        },
        description: "Fail-closed lane for a MagicLoader sidecar, a multi-master worldspace ESP, stock-plus-mod SyncMap closure, and additive Unreal packages. Live master overrides must pass the per-subrecord three-way current-master semantic gate, witness-shaped REFR deletion stubs are rewritten as undeleted, initially disabled, player-opposite enable-parented overrides, and stale bundled imports may resolve only through disclosed, role-proven identity aliases. The output is a runtime-test candidate; the MagicLoader runtime itself is disclosed but never installed by the updater.".to_owned(),
        blockers: if magic_loader_layout {
            let mut blockers = magicloader_lane_blockers.clone();
            blockers.extend(adapter_blockers.iter().cloned());
            blockers.sort();
            blockers.dedup();
            blockers
        } else {
            vec!["mod-layout-does-not-match-magicloader-worldspace-lane".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: ADDITIVE_CONTRACT_API.to_owned(),
        available: additive_contract
            .as_ref()
            .is_some_and(|value| value.compatible),
        evidence_level: "current-master-field-aware-validation".to_owned(),
        description: "Binds the unique candidate root, ESP, SyncMap, and ordered installed full-master chain; rejects empty or duplicate mappings, unmapped plugin-local IDs, and CONT, CREA, or NPC_ overrides that conflict with installed inventory or non-inventory semantics. Newly installed master rows are merged into the candidate without dropping the mod's additions. Master overrides outside the inventory contract are accepted byte-preserved only when the per-subrecord three-way current-master semantic gate resolves every override identity and type, with authored, revert-risk, and merge-needed fields disclosed and witness-shaped deletion stubs proven by the undelete-and-disable policy.".to_owned(),
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
        id: PLUGIN_ONLY_ADAPTER.to_owned(),
        available: plugin_only_can_update,
        evidence_level: "current-master-semantic-gate-on-canonical-data-plane-layout".to_owned(),
        description: "Fail-closed lane for plugin-only mods: one full ESP plus optional SyncMap INI, MagicLoader JSON sidecars, and documentation, resolved from a canonical wrapper, Place-in-Data, or bare rooting into Content/Dev/ObvData/Data. Declared masters must resolve installed, and every master override must pass the per-subrecord three-way current-master semantic gate with authored, revert-risk, and merge-needed fields disclosed; witness-shaped REFR deletion stubs are rewritten as undeleted, initially disabled, player-opposite enable-parented overrides, and every other byte is preserved. The output is a runtime-test candidate; SyncMap package targets and the MagicLoader runtime remain disclosed runtime requirements.".to_owned(),
        blockers: plugin_only_lane
            .as_ref()
            .map(|lane| {
                if lane.blockers.is_empty() {
                    adapter_blockers.clone()
                } else {
                    lane.blockers.clone()
                }
            })
            .unwrap_or_else(|| vec!["mod-layout-does-not-match-plugin-only-lane".to_owned()]),
    });
    capabilities.push(Capability {
        id: ARMOR_REPLACEMENT_ADAPTER.to_owned(),
        available: armor_can_update,
        evidence_level: "guarded-payload-preserving-rebase".to_owned(),
        description: "Pure existing SK_ skeletal-mesh replacements under /Content/Art, including armor and clothing, resolve serialized FSkeletalMaterial slots by name, migrate the skeleton separately, and null a retired PhysicsAsset only when current-donor and serialized-property evidence prove that role. Unknown auxiliary imports stop instead of becoming materials. The approved payload migration is roundtripped through current Zen metadata, and output remains a runtime-test candidate.".to_owned(),
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
        id: HETEROGENEOUS_REPLACEMENT_ADAPTER.to_owned(),
        available: heterogeneous_replacement_can_update,
        evidence_level: "guarded-per-package-static-mesh-texture-rebase".to_owned(),
        description: "Classifies every package independently and accepts only containers composed entirely of structurally proven StaticMesh and Texture2D assets. Each package must have one current-game package ID plus either an exact path or a project-root-only content alias, complete source dependency closure, exact source-case extraction, and verified inventory, imports, class, and payload preservation after one container rebuild. Authored source import changes are preserved and disclosed.".to_owned(),
        blockers: if heterogeneous_replacement_probe.is_some() {
            adapter_blockers.clone()
        } else {
            vec!["packages-did-not-pass-the-heterogeneous-static-mesh-texture-contract".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: COMPOSITE_PACKAGE_REBASE_ADAPTER.to_owned(),
        available: composite_package_can_update,
        evidence_level: "guarded-system-wide-current-template-and-serialized-role-rebase"
            .to_owned(),
        description: "Classifies packages by decoded export structure across content domains. Existing packages may reuse the current import table only when package identity, cooked flags, and export topology match and every authored export/sidecar byte is preserved. Skeletal references require serialized skeleton/physics role proof; additive single-parent repairs require one exact current dependency. StaticMesh, Texture2D, material-instance, and current-template packages share the same fail-closed container rebuild and roundtrip checks.".to_owned(),
        blockers: if composite_package_probe.is_some() {
            adapter_blockers.clone()
        } else {
            vec!["packages-did-not-pass-the-system-wide-composite-rebase-contract".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: LEGACY_PAK_PASSTHROUGH_ADAPTER.to_owned(),
        available: pak_passthrough_can_update,
        evidence_level: "hash-verified-byte-preserving-passthrough".to_owned(),
        description: "Legacy .pak-only payloads whose unencrypted index, per-entry stored-payload SHA-1 hashes, and zlib roundtrips all verify, whose every entry mounts on the proven Wwise audio media plane, and whose media IDs all exist in the current game's hash-verified shipped pak index are published byte-preserved with a ~mods install plan. The payload is version-passthrough, not structurally rebuilt; output remains a runtime-test candidate.".to_owned(),
        blockers: if pak_passthrough_can_update {
            Vec::new()
        } else if pak_passthrough_shape {
            adapter_blockers.clone()
        } else {
            vec!["mod-layout-is-not-a-legacy-pak-only-payload".to_owned()]
        },
    });
    capabilities.push(Capability {
        id: "pinned-offhand-staff-a-v1".to_owned(),
        available: false,
        evidence_level: "separate-audited-donor-cli".to_owned(),
        description: "The Staff A donor repair remains available only through its separately pinned console lane and cannot be inferred from a generic mod input.".to_owned(),
        blockers: vec!["audited-donor-selection-required".to_owned()],
    });
    if !additive_shape
        && !magicloader_worldspace_gate_ready
        && !plugin_only_gate_ready
        && replacement_probe.is_none()
        && heterogeneous_replacement_probe.is_none()
        && composite_package_probe.is_none()
        && legacy_pak_passthrough_probe.is_none()
        && !logical_adapter_matched
        && inventory.is_some()
    {
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
    let selected_adapter = if additive_can_update {
        Some("native-additive-syncmap-v1".to_owned())
    } else if magicloader_can_update {
        Some("native-magicloader-worldspace-syncmap-v1".to_owned())
    } else if armor_can_update {
        Some(ARMOR_REPLACEMENT_ADAPTER.to_owned())
    } else if mixed_armor_can_update {
        Some(MIXED_ARMOR_REPLACEMENT_ADAPTER.to_owned())
    } else if texture_can_update {
        Some(TEXTURE_REPLACEMENT_ADAPTER.to_owned())
    } else if additive_static_mesh_can_update {
        Some(ADDITIVE_STATIC_MESH_ADAPTER.to_owned())
    } else if heterogeneous_replacement_can_update {
        Some(HETEROGENEOUS_REPLACEMENT_ADAPTER.to_owned())
    } else if composite_package_can_update {
        Some(COMPOSITE_PACKAGE_REBASE_ADAPTER.to_owned())
    } else if pak_passthrough_can_update {
        Some(LEGACY_PAK_PASSTHROUGH_ADAPTER.to_owned())
    } else if plugin_only_can_update {
        Some(PLUGIN_ONLY_ADAPTER.to_owned())
    } else if logical_install_can_update {
        logical_publication_adapter.clone()
    } else {
        None
    };
    let mut disposition_blockers = adapter_blockers.clone();
    if let Some(lane) = plugin_only_lane.as_ref().filter(|lane| lane.status != "proven") {
        disposition_blockers.extend(lane.blockers.iter().cloned());
    }
    if let Some(plugin) = plugin_compatibility.as_ref() {
        disposition_blockers.extend(plugin.blockers.iter().cloned());
    }
    if let Some(layered) = layered_iostore_dependency_probe.as_ref() {
        if mixed_unresolved_recovered {
            // Every unresolved layered edge is covered by the disclosed, role-proven
            // identity-alias recovery reported in identityAliasRecoveryProbe; only the
            // uncovered blockers remain dispositive.
            disposition_blockers.extend(
                layered
                    .blockers
                    .iter()
                    .filter(|blocker| {
                        !blocker.starts_with("unresolved-layered-package-dependencies:")
                    })
                    .cloned(),
            );
        } else {
            disposition_blockers.extend(layered.blockers.iter().cloned());
        }
    }
    if let Some(logical) = logical_install_analysis.as_ref() {
        disposition_blockers.extend(logical.disposition.blocker_ids.iter().cloned());
    }
    if install_plan.is_some() && !logical_install_can_update {
        disposition_blockers.push("logical-install-publication-not-implemented".to_owned());
    }
    disposition_blockers.sort();
    disposition_blockers.dedup();
    let (disposition_code, disposition_reason) = if can_update {
        (
            "guarded-update-candidate",
            "Every selected adapter gate passed. The output must still be tested in the shipping game.".to_owned(),
        )
    } else if inventory.is_none() {
        (
            "input-error",
            "The selected source could not be inventoried safely.".to_owned(),
        )
    } else if layered_iostore_dependency_probe
        .as_ref()
        .is_some_and(|report| !report.resolution_complete)
        && !mixed_unresolved_recovered
    {
        (
            "dependency-closure-unresolved",
            "At least one reachable IoStore import remains unresolved under explicit provider precedence.".to_owned(),
        )
    } else if plugin_compatibility
        .as_ref()
        .is_some_and(|report| !report.blockers.is_empty())
    {
        (
            "plugin-structural-or-semantic-review-required",
            "Plugin structure or record semantics exceed the currently proven mutation policies.".to_owned(),
        )
    } else if plugin_only_lane
        .as_ref()
        .is_some_and(|lane| lane.status != "proven")
    {
        (
            "plugin-only-lane-blocked",
            "The plugin-only Data-plane lane could not prove every gate; the disclosed blockers name each unproven step.",
        )
    } else if install_plan.is_some() {
        (
            "install-layout-resolved-report-only",
            "Physical-to-logical install mappings were resolved, but no end-to-end mutation adapter passed for that logical component.".to_owned(),
        )
    } else if pak_passthrough_shape {
        (
            "legacy-pak-passthrough-validation-blocked",
            format!(
                "The input is a legacy .pak-only payload, but the fail-closed passthrough validation did not pass: {}",
                legacy_pak_passthrough_probe_error
                    .as_deref()
                    .unwrap_or("a blocking preflight check failed before the passthrough contract")
            ),
        )
    } else if inventory
        .as_ref()
        .is_some_and(is_ue4ss_script_payload_shape)
    {
        let inventory = inventory.as_ref().expect("inventory checked above");
        (
            "ue4ss-script-payload",
            format!(
                "The payload is UE4SS Lua runtime scripting ({} Lua file(s), {} loader DLL(s)). This updater never auto-installs or rewrites executable code, so there is no update lane; install the scripts under the UE4SS Mods folder and validate behavior in the shipping game.",
                inventory_extension_count(inventory, "lua"),
                inventory_extension_count(inventory, "dll"),
            ),
        )
    } else if inventory.as_ref().is_some_and(is_standalone_tool_shape) {
        let inventory = inventory.as_ref().expect("inventory checked above");
        (
            "standalone-tool-executable",
            format!(
                "The payload is a standalone tool ({} executable(s), {} DLL(s)); it is not game mod content that installs into the game folder, so there is nothing for this updater to update. Run the tool separately.",
                inventory_extension_count(inventory, "exe"),
                inventory_extension_count(inventory, "dll"),
            ),
        )
    } else if inventory.as_ref().is_some_and(is_authoring_resource_shape) {
        let inventory = inventory.as_ref().expect("inventory checked above");
        let source_extensions = inventory
            .extension_counts
            .keys()
            .filter(|extension| AUTHORING_SOURCE_EXTENSIONS.contains(&extension.as_str()))
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        (
            "authoring-resource-source-assets",
            format!(
                "The payload is a source authoring resource ({source_extensions} plus sidecars/previews): DCC or editor inputs, not packaged game content. There is nothing to install into the game and therefore nothing to update.",
            ),
        )
    } else {
        (
            "unsupported-structural-content",
            "The input is reportable, but one or more selected files lack a proven update capability.".to_owned(),
        )
    };
    let disposition = UpdateDisposition {
        code: disposition_code.to_owned(),
        automatic_update: can_update,
        runtime_validation_required: can_update,
        reason: disposition_reason,
        blocker_ids: disposition_blockers,
    };
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
        worldspace_master_probe,
        mixed_iostore_dependency_probe,
        mixed_replacement_package_diagnostic,
        layered_iostore_dependency_probe,
        identity_alias_recovery_probe,
        magicloader_syncmap_gate,
        install_plan,
        logical_install_analysis,
        legacy_pak_passthrough_probe,
        unreal_replacement_probe: replacement_probe,
        heterogeneous_replacement_probe,
        selected_adapter,
        can_update,
        status: status.to_owned(),
        disposition,
        performance: PerformanceReport {
            elapsed_ms: started.elapsed().as_millis(),
            scan_entry_limit: MAX_SCAN_ENTRIES,
            metadata_only_archive_scan: !replacement_shape && !magic_loader_layout,
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
        "installPlan": report.install_plan.as_ref().map(|value| (
            &value.evidence,
            &value.mappings,
            &value.choice_groups,
            &value.unmapped_sources,
        )),
        "logicalInstallAnalysis": report.logical_install_analysis.as_ref().map(|value| (
            value.inventory.as_ref().map(|inventory| (
                &inventory.classification,
                &inventory.metadata_manifest_sha256,
            )),
            value.plugin_compatibility.as_ref().map(|plugin| (
                &plugin.status,
                &plugin.manifest_sha256,
                plugin.logical_plugin_count,
                &plugin.blockers,
            )),
            &value.selected_adapter,
            value.can_update,
            &value.status,
            &value.disposition.code,
            &value.disposition.blocker_ids,
        )),
        "legacyPakPassthroughProbe": report
            .legacy_pak_passthrough_probe
            .as_ref()
            .map(|value| (
                value.pak_count,
                value.entry_count,
                value.matched_current_media_count,
                value.paks.iter().map(|pak| &pak.pak_sha256).collect::<Vec<_>>(),
            )),
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
        "worldspaceMasterProbe": report
            .worldspace_master_probe
            .as_ref()
            .map(|value| (
                &value.status,
                value.resolution_complete,
                value.resolved_master_override_count,
                value.unresolved_master_override_count,
                value.type_mismatch_override_count,
                value.deleted_master_override_count,
                &value.blockers,
            )),
        "mixedIoStoreDependencyProbe": report
            .mixed_iostore_dependency_probe
            .as_ref()
            .map(|value| (
                &value.status,
                value.container_count,
                value.source_package_count,
                value.collision_count,
                value.dependencies.resolved_edge_count,
                value.dependencies.unresolved_edges.iter().map(|edge| (
                    edge.source_package_id,
                    edge.missing_dependency_package_id,
                )).collect::<Vec<_>>(),
            )),
        "mixedReplacementPackageDiagnostic": report
            .mixed_replacement_package_diagnostic
            .as_ref()
            .map(|value| (
                &value.status,
                value.container_count,
                value.source_package_count,
                value.exact_replacement_count,
                value.additive_package_count,
                value.conflict_package_count,
                &value.containers,
                &value.packages,
                &value.dependencies.resolved_edges,
                &value.dependencies.unresolved_edges,
                &value.blockers,
            )),
        "layeredIoStoreDependencyProbe": report
            .layered_iostore_dependency_probe
            .as_ref()
            .map(|value| (
                &value.status,
                value.resolution_complete,
                &value.logical_sha256,
                value.provider_count,
                value.reachable_package_count,
                value.resolved_edge_count,
                value.unresolved_edge_count,
                value.cross_layer_collision_count,
                &value.blockers,
            )),
        "heterogeneousReplacementProbe": report
            .heterogeneous_replacement_probe
            .as_ref()
            .map(|value| (
                &value.adapter,
                value.container_count,
                value.package_count,
                value.static_mesh_count,
                value.texture_count,
                &value.packages,
            )),
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
        "disposition": (
            &report.disposition.code,
            report.disposition.automatic_update,
            report.disposition.runtime_validation_required,
            &report.disposition.blocker_ids,
        ),
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

    #[test]
    fn native_additive_publication_accepts_direct_author_container_folders() {
        assert!(is_direct_mod_container_path(
            "Content/Paks/~mods/Fixture_P.utoc"
        ));
        assert!(is_direct_mod_container_path(
            "content\\paks\\~MODS\\Fixture_P.UTOC"
        ));
        assert!(is_direct_mod_container_path(
            "Content/Paks/Author Name/Fixture_P.utoc"
        ));
        assert!(!is_direct_mod_container_path(
            "Content/Paks/~mods/Nested/Fixture_P.utoc"
        ));
        assert!(!is_direct_mod_container_path("Content/Paks/Fixture_P.utoc"));
    }

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

    fn worldspace_plugin_bytes() -> Vec<u8> {
        let mut hedr = 0.8_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&2_u32.to_le_bytes());
        hedr.extend_from_slice(&0x801_u32.to_le_bytes());
        let mut header_data = tes4_subrecord("HEDR", &hedr);
        header_data.extend(tes4_subrecord("MAST", b"Oblivion.esm\0"));
        header_data.extend(tes4_subrecord("DATA", &[0; 8]));
        let mut bytes = tes4_record_bytes("TES4", 0, &header_data);
        bytes.extend(tes4_record_bytes(
            "CELL",
            0x0000_1234,
            &tes4_subrecord("EDID", b"CurrentCell\0"),
        ));
        bytes.extend(tes4_record_bytes(
            "REFR",
            0x0100_0800,
            &tes4_subrecord("EDID", b"OwnedReference\0"),
        ));
        bytes
    }

    fn current_worldspace_master_bytes() -> Vec<u8> {
        let mut hedr = 0.8_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&1_u32.to_le_bytes());
        hedr.extend_from_slice(&0x1235_u32.to_le_bytes());
        let header_data = tes4_subrecord("HEDR", &hedr);
        let mut bytes = tes4_record_bytes("TES4", 0, &header_data);
        bytes.extend(tes4_record_bytes(
            "CELL",
            0x0000_1234,
            &tes4_subrecord("EDID", b"CurrentCell\0"),
        ));
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

    fn magic_loader_sidecar_fixture(root: &Path) {
        let config = root.join(r"Fixture\Content\Dev\ObvData\Data\MagicLoader\Fixture.json");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        // MagicLoader configuration files in the wild may accept JSON-like
        // trailing commas. Inventory is intentionally path/byte based here.
        fs::write(config, br#"{"FullNames_Edit":{"LOC_FN_Test":"Test",}}"#).unwrap();
    }

    fn game_fixture(root: &Path) {
        for (label, relative) in crate::game::REQUIRED_GAME_FILES {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let payload = if *label == "Oblivion.esm" {
                current_master_with_container_bytes()
            } else {
                b"fixture".to_vec()
            };
            fs::write(path, payload).unwrap();
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

    #[test]
    fn binds_plugin_only_candidate_root_from_the_data_plane() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp
            .path()
            .join(r"OblivionRemastered\Content\Dev\ObvData\Data");
        fs::create_dir_all(data.join("SyncMap")).unwrap();
        fs::create_dir_all(data.join("MagicLoader")).unwrap();
        fs::write(data.join("Fixture.esp"), valid_plugin_bytes()).unwrap();
        fs::write(
            data.join(r"SyncMap\Fixture.ini"),
            b"[Meshes]\n000800=../../../OblivionRemastered/Content/Fixture/SM_Fixture.SM_Fixture\n",
        )
        .unwrap();
        fs::write(data.join(r"MagicLoader\Fixture.json"), b"{}").unwrap();

        let inventory = scan_directory(temp.path()).unwrap();
        assert_eq!(inventory.classification, "plugin-only");
        assert_eq!(inventory.candidate_mod_root_count, 1);
        assert_eq!(
            inventory.candidate_mod_root.as_deref(),
            Some("OblivionRemastered")
        );
        assert_eq!(inventory.magic_loader_config_count, 1);
    }

    #[test]
    fn classifies_additive_layout_in_named_paks_directories() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp
            .path()
            .join(r"Wrapped\OblivionRemastered\Content\Dev\ObvData\Data");
        let paks = temp
            .path()
            .join(r"Wrapped\OblivionRemastered\Content\Paks\Author Name");
        fs::create_dir_all(data.join("SyncMap")).unwrap();
        fs::create_dir_all(&paks).unwrap();
        fs::write(data.join("Fixture.esp"), valid_plugin_bytes()).unwrap();
        fs::write(
            data.join(r"SyncMap\Fixture.ini"),
            b"[Meshes]\n000800=../../../OblivionRemastered/Content/Fixture/SM_Fixture.SM_Fixture\n",
        )
        .unwrap();
        for stem in ["Fixture_Forms_P", "Fixture_Assets_P"] {
            for extension in ["pak", "ucas", "utoc"] {
                fs::write(paks.join(format!("{stem}.{extension}")), extension).unwrap();
            }
        }

        let inventory = scan_directory(temp.path()).unwrap();
        assert_eq!(inventory.classification, "additive-syncmap-iostore");
        assert_eq!(inventory.complete_container_triple_count, 2);
        assert_eq!(inventory.candidate_mod_root_count, 1);
        assert_eq!(
            inventory.candidate_mod_root.as_deref(),
            Some("Wrapped/OblivionRemastered")
        );
    }

    #[test]
    fn replacement_shape_allows_docs_but_blocks_unknown_loose_payloads() {
        let temp = tempfile::tempdir().unwrap();
        for extension in ["pak", "ucas", "utoc"] {
            fs::write(
                temp.path().join(format!("Fixture_P.{extension}")),
                extension,
            )
            .unwrap();
        }
        fs::write(temp.path().join("README.txt"), b"installation notes").unwrap();
        let inventory = scan_directory(temp.path()).unwrap();
        assert_eq!(inventory.loose_file_count, 1);
        assert_eq!(inventory.functional_or_unknown_loose_file_count, 0);
        assert!(is_replacement_shape(&inventory));

        fs::write(temp.path().join("settings.ini"), b"[Runtime]").unwrap();
        let inventory = scan_directory(temp.path()).unwrap();
        assert_eq!(inventory.functional_or_unknown_loose_file_count, 1);
        assert!(!is_replacement_shape(&inventory));
    }

    #[test]
    fn additive_layout_does_not_run_mixed_replacement_diagnostic() {
        let temp = tempfile::tempdir().unwrap();
        additive_fixture(temp.path());
        let report = analyze(&PreflightRequest {
            mod_input: temp.path().to_path_buf(),
            game_root: None,
            output_parent: None,
            connected_tools: Vec::new(),
        });
        assert!(report.mixed_replacement_package_diagnostic.is_none());
        assert!(report.capabilities.iter().any(|capability| {
            capability.id == MIXED_REPLACEMENT_PACKAGE_DIAGNOSTIC_API && !capability.available
        }));
    }

    #[test]
    fn recognizes_the_active_game_mods_directory_as_partial_installed_input() {
        let temp = tempfile::tempdir().unwrap();
        let game = temp.path().join("game");
        let active_mods = game.join(r"OblivionRemastered\Content\Paks\~mods");
        fs::create_dir_all(&active_mods).unwrap();
        let request = PreflightRequest {
            mod_input: active_mods,
            game_root: Some(game),
            output_parent: None,
            connected_tools: Vec::new(),
        };
        assert!(selects_active_game_mods(&request));
    }

    #[test]
    fn recognizes_path_bound_magic_loader_sidecar_without_enabling_additive_adapter() {
        let temp = tempfile::tempdir().unwrap();
        additive_fixture(temp.path());
        magic_loader_sidecar_fixture(temp.path());

        let inventory = scan_directory(temp.path()).unwrap();
        assert_eq!(inventory.classification, "magicloader-syncmap-iostore");
        assert_eq!(inventory.magic_loader_config_count, 1);
        assert_eq!(inventory.loose_file_count, 1);
        assert_eq!(inventory.functional_or_unknown_loose_file_count, 0);

        let report = analyze(&PreflightRequest {
            mod_input: temp.path().to_path_buf(),
            game_root: None,
            output_parent: None,
            connected_tools: Vec::new(),
        });
        assert!(!report.can_update);
        assert_eq!(report.selected_adapter, None);
        assert!(report.capabilities.iter().any(|capability| {
            capability.id == MAGIC_LOADER_SIDECAR_API && capability.available
        }));
        assert!(report.checks.iter().any(|check| {
            check.id == "magic-loader-runtime" && check.status == "warning" && !check.blocking
        }));
    }

    #[test]
    fn magic_loader_runtime_requires_a_readable_executable_signature() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("MagicLoader.exe");
        fs::write(&executable, b"not-an-executable").unwrap();
        assert!(!has_portable_executable_magic(&executable));
        fs::write(&executable, b"MZfixture").unwrap();
        assert!(has_portable_executable_magic(&executable));
    }

    #[test]
    fn magic_loader_worldspace_layout_runs_read_only_current_master_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let mod_input = temp.path().join("mod");
        let game = temp.path().join("game");
        additive_fixture(&mod_input);
        magic_loader_sidecar_fixture(&mod_input);
        fs::write(
            mod_input.join(r"Fixture\Content\Dev\ObvData\Data\Fixture.esp"),
            worldspace_plugin_bytes(),
        )
        .unwrap();
        game_fixture(&game);
        fs::write(
            game.join(r"OblivionRemastered\Content\Dev\ObvData\Data\Oblivion.esm"),
            current_worldspace_master_bytes(),
        )
        .unwrap();

        let report = analyze(&PreflightRequest {
            mod_input,
            game_root: Some(game),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        let probe = report.worldspace_master_probe.as_ref().unwrap();
        assert_eq!(probe.declared_master_count, 1);
        assert_eq!(probe.parsed_master_count, 1);
        assert_eq!(probe.master_override_count, 1);
        assert_eq!(probe.resolved_master_override_count, 1);
        assert_eq!(probe.unresolved_master_override_count, 0);
        assert_eq!(probe.type_mismatch_override_count, 0);
        assert!(
            report.checks.iter().any(|check| {
                check.id == "worldspace-master-resolution" && check.status == "pass"
            })
        );
        assert!(!report.can_update);
        assert_eq!(report.selected_adapter, None);
    }

    #[test]
    fn magic_loader_sidecar_outside_selected_root_remains_unknown_functional_content() {
        let temp = tempfile::tempdir().unwrap();
        additive_fixture(temp.path());
        let misplaced = temp
            .path()
            .join(r"Other\Content\Dev\ObvData\Data\MagicLoader\Misplaced.json");
        fs::create_dir_all(misplaced.parent().unwrap()).unwrap();
        fs::write(misplaced, b"{}").unwrap();

        let inventory = scan_directory(temp.path()).unwrap();
        assert_eq!(inventory.classification, "mixed-mod");
        assert_eq!(inventory.magic_loader_config_count, 0);
        assert_eq!(inventory.functional_or_unknown_loose_file_count, 1);
    }

    #[test]
    fn nested_magic_loader_payload_remains_unknown_functional_content() {
        let temp = tempfile::tempdir().unwrap();
        additive_fixture(temp.path());
        let nested = temp
            .path()
            .join(r"Fixture\Content\Dev\ObvData\Data\MagicLoader\Nested\Config.json");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(nested, b"{}").unwrap();

        let inventory = scan_directory(temp.path()).unwrap();
        assert_eq!(inventory.classification, "mixed-mod");
        assert_eq!(inventory.magic_loader_config_count, 0);
        assert_eq!(inventory.functional_or_unknown_loose_file_count, 1);
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
    fn logical_install_analysis_stops_after_one_derived_view() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        let data = input.join(r"Wrapper\Place in Data");
        let containers = input.join(r"Wrapper\Place in Paks");
        fs::create_dir_all(data.join("SyncMap")).unwrap();
        fs::create_dir_all(&containers).unwrap();
        fs::write(data.join("Fixture.esp"), b"plugin").unwrap();
        fs::write(data.join(r"SyncMap\Fixture.ini"), b"map").unwrap();
        for extension in ["pak", "ucas", "utoc"] {
            fs::write(
                containers.join(format!("Fixture_P.{extension}")),
                extension.as_bytes(),
            )
            .unwrap();
        }

        let report = analyze(&PreflightRequest {
            mod_input: input,
            game_root: None,
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });

        assert!(report.install_plan.is_some());
        let logical = report.logical_install_analysis.as_ref().unwrap();
        assert_eq!(
            logical.inventory.as_ref().unwrap().classification,
            "additive-syncmap-iostore"
        );
        assert!(!logical.can_update);
        assert!(!report.can_update);
        assert!(
            report
                .disposition
                .blocker_ids
                .iter()
                .any(|blocker| blocker == "logical-install-publication-not-implemented")
        );
    }

    fn mixed_replacement_signature_fixture(path: &str) -> MixedReplacementPackageDiagnosticReport {
        MixedReplacementPackageDiagnosticReport {
            api: MIXED_REPLACEMENT_PACKAGE_DIAGNOSTIC_API.to_owned(),
            status: "complete-report-only".to_owned(),
            mutation_policy: "report-only".to_owned(),
            automatic_update_enabled: false,
            container_count: 1,
            source_package_count: 1,
            current_game_package_count: 1,
            exact_replacement_count: 1,
            root_alias_replacement_count: 0,
            additive_package_count: 0,
            conflict_package_count: 0,
            path_conflict_count: 0,
            package_id_conflict_count: 0,
            containers: vec![crate::replacement::MixedReplacementContainerDiagnostic {
                name: "Fixture_P".to_owned(),
                relative_utoc: "Fixture_P.utoc".to_owned(),
                package_count: 1,
            }],
            packages: vec![crate::replacement::MixedReplacementPackageDiagnostic {
                container: "Fixture_P.utoc".to_owned(),
                container_name: "Fixture_P".to_owned(),
                name: "T_fixture.uasset".to_owned(),
                path: path.to_owned(),
                package_id: 7,
                imported_package_ids: Vec::new(),
                identity_status:
                    crate::replacement::MixedReplacementIdentityStatus::ExactReplacement,
                current_path_match_package_id: Some(7),
                current_id_match_path: Some(path.to_owned()),
            }],
            dependencies: crate::fixes::DependencyDiagnosticReport {
                api: crate::fixes::DEPENDENCY_DIAGNOSTIC_API.to_owned(),
                bundled_package_count: 1,
                current_game_package_count: 1,
                dependency_edge_count: 0,
                resolved_edge_count: 0,
                unresolved_edge_count: 0,
                bundled_edge_count: 0,
                current_game_edge_count: 0,
                fully_resolved: true,
                resolved_edges: Vec::new(),
                unresolved_edges: Vec::new(),
            },
            blockers: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn mixed_replacement_identity_changes_the_stable_signature() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("readme.txt"), b"fixture").unwrap();
        let request = PreflightRequest {
            mod_input: temp.path().to_path_buf(),
            game_root: None,
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        };
        let mut first = analyze(&request);
        let mut second = analyze(&request);
        first.mixed_replacement_package_diagnostic = Some(mixed_replacement_signature_fixture(
            "../../../OblivionRemastered/Content/A/T_fixture.uasset",
        ));
        second.mixed_replacement_package_diagnostic = Some(mixed_replacement_signature_fixture(
            "../../../OblivionRemastered/Content/B/T_fixture.uasset",
        ));
        assert_ne!(stable_signature(&first), stable_signature(&second));
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
    fn malformed_replacement_probe_errors_omit_absolute_paths() {
        let temp = tempfile::tempdir().unwrap();
        let mod_input = temp.path().join("replacement");
        let game = temp.path().join("game");
        let output = temp.path().join("output");
        fs::create_dir_all(&mod_input).unwrap();
        fs::create_dir_all(&output).unwrap();
        game_fixture(&game);
        for extension in ["pak", "ucas", "utoc"] {
            fs::write(
                mod_input.join(format!("Malformed_P.{extension}")),
                b"not-an-iostore-container",
            )
            .unwrap();
        }
        let report = analyze(&PreflightRequest {
            mod_input,
            game_root: Some(game),
            output_parent: Some(output),
            connected_tools: Vec::new(),
        });
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(&temp.path().to_string_lossy().to_string()));
        assert!(!report.can_update);
        assert_eq!(report.status, "report-only");
    }

    #[test]
    fn tool_connections_do_not_bypass_additive_package_validation() {
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
        assert!(!connected.can_update);
        assert!(connected.selected_adapter.is_none());
        assert!(
            connected
                .tools
                .iter()
                .filter(|tool| matches!(tool.id.as_str(), "ue4ss" | "tes-sync-map-injector"))
                .all(|tool| tool.status != "missing")
        );
        assert!(
            connected
                .checks
                .iter()
                .any(|check| check.id == "additive-iostore-dependency-closure" && check.blocking)
        );
    }

    #[test]
    fn additive_zip_reads_only_selected_metadata_before_package_validation() {
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
        assert!(!report.can_update);
        assert!(report.performance.metadata_only_archive_scan);
        assert_eq!(
            report.plugin_compatibility.as_ref().unwrap().scan_mode,
            "validated-selected-entry-extraction"
        );
        assert!(
            !report
                .checks
                .iter()
                .any(|check| check.id.starts_with("mixed-iostore-")),
            "mixed-IoStore diagnostics are reserved for the MagicLoader mixed layout"
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id == "additive-iostore-dependency-closure" && check.blocking)
        );
    }

    #[test]
    fn additive_preflight_accepts_inner_game_folder_but_rejects_invalid_iostore() {
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

        assert!(!report.can_update);
        assert!(report.game_valid);
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

    fn pak_passthrough_sound_entries() -> Vec<crate::pak::test_support::SyntheticEntry> {
        vec![
            crate::pak::test_support::SyntheticEntry {
                name: "1020757059.wem".to_owned(),
                payload: b"plain wwise payload".to_vec(),
                zlib: false,
            },
            crate::pak::test_support::SyntheticEntry {
                name: "240112521.wem".to_owned(),
                payload: b"zlib wwise payload zlib wwise payload".to_vec(),
                zlib: true,
            },
        ]
    }

    fn game_fixture_with_main_pak(root: &Path, listed_media: &[&str]) {
        game_fixture(root);
        let listing = crate::pak::test_support::write_modern_listing_pak(listed_media);
        let pak_path = root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.pak");
        fs::create_dir_all(pak_path.parent().unwrap()).unwrap();
        fs::write(pak_path, listing).unwrap();
    }

    #[test]
    fn pak_only_wwise_payload_becomes_a_guarded_passthrough_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        fs::create_dir_all(&mod_root).unwrap();
        let pak = crate::pak::test_support::write_legacy_pak_v3(
            "../../../OblivionRemastered/Content/WwiseAudio/Media/",
            &pak_passthrough_sound_entries(),
        );
        fs::write(mod_root.join("Fixture_P.pak"), pak).unwrap();
        let game_root = temp.path().join("game");
        game_fixture_with_main_pak(
            &game_root,
            &[
                "OblivionRemastered/Content/WwiseAudio/Media/1020757059.wem",
                "OblivionRemastered/Content/WwiseAudio/Media/240112521.wem",
            ],
        );
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        assert_eq!(
            report.inventory.as_ref().unwrap().classification,
            "unreal-container-only"
        );
        assert!(report.game_valid);
        assert!(report.can_update, "blockers: {:?}", report.disposition);
        assert_eq!(report.disposition.code, "guarded-update-candidate");
        assert!(report.disposition.runtime_validation_required);
        assert_eq!(
            report.selected_adapter.as_deref(),
            Some(crate::pak::LEGACY_PAK_PASSTHROUGH_ADAPTER)
        );
        let probe = report.legacy_pak_passthrough_probe.as_ref().unwrap();
        assert_eq!(probe.pak_count, 1);
        assert_eq!(probe.entry_count, 2);
        assert_eq!(probe.matched_current_media_count, 2);
        assert!(
            report
                .capabilities
                .iter()
                .any(|capability| capability.id == crate::pak::LEGACY_PAK_PASSTHROUGH_ADAPTER
                    && capability.available)
        );
    }

    #[test]
    fn pak_only_payload_missing_current_media_fails_closed_with_a_precise_code() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        fs::create_dir_all(&mod_root).unwrap();
        let pak = crate::pak::test_support::write_legacy_pak_v3(
            "../../../OblivionRemastered/Content/WwiseAudio/Media/",
            &pak_passthrough_sound_entries(),
        );
        fs::write(mod_root.join("Fixture_P.pak"), pak).unwrap();
        let game_root = temp.path().join("game");
        game_fixture_with_main_pak(
            &game_root,
            &["OblivionRemastered/Content/WwiseAudio/Media/1020757059.wem"],
        );
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        assert!(!report.can_update);
        assert_eq!(
            report.disposition.code,
            "legacy-pak-passthrough-validation-blocked"
        );
        assert!(report.disposition.reason.contains("not present"));
        assert!(report.selected_adapter.is_none());
    }

    #[test]
    fn pak_only_cooked_asset_payload_fails_closed_with_a_precise_code() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        fs::create_dir_all(&mod_root).unwrap();
        let pak = crate::pak::test_support::write_legacy_pak_v3(
            "../../../OblivionRemastered/Content/Art/",
            &[crate::pak::test_support::SyntheticEntry {
                name: "SK_Armor.uasset".to_owned(),
                payload: b"cooked".to_vec(),
                zlib: false,
            }],
        );
        fs::write(mod_root.join("Fixture_P.pak"), pak).unwrap();
        let game_root = temp.path().join("game");
        game_fixture_with_main_pak(
            &game_root,
            &["OblivionRemastered/Content/WwiseAudio/Media/1020757059.wem"],
        );
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: Some(game_root),
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        assert!(!report.can_update);
        assert_eq!(
            report.disposition.code,
            "legacy-pak-passthrough-validation-blocked"
        );
        assert!(report.disposition.reason.contains("cooked-asset"));
    }

    #[test]
    fn ue4ss_lua_payload_gets_a_precise_terminal_disposition() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        fs::create_dir_all(mod_root.join(r"MyMod\Scripts")).unwrap();
        fs::write(mod_root.join(r"MyMod\Scripts\main.lua"), b"-- script").unwrap();
        fs::write(mod_root.join(r"MyMod\enabled.txt"), b"").unwrap();
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: None,
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        assert_eq!(
            report.inventory.as_ref().unwrap().classification,
            "script-or-loader"
        );
        assert!(!report.can_update);
        assert_eq!(report.disposition.code, "ue4ss-script-payload");
        assert!(!report.disposition.automatic_update);
        assert!(report.disposition.reason.contains("UE4SS"));
    }

    #[test]
    fn standalone_tool_executable_gets_a_precise_terminal_disposition() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        fs::create_dir_all(&mod_root).unwrap();
        fs::write(mod_root.join("Tool.exe"), b"MZ tool").unwrap();
        fs::write(mod_root.join("Helper.dll"), b"MZ helper").unwrap();
        fs::write(mod_root.join("README.md"), b"docs").unwrap();
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: None,
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        assert_eq!(
            report.inventory.as_ref().unwrap().classification,
            "script-or-loader"
        );
        assert!(!report.can_update);
        assert_eq!(report.disposition.code, "standalone-tool-executable");
        assert!(report.disposition.reason.contains("tool"));
    }

    #[test]
    fn authoring_source_assets_get_a_precise_terminal_disposition() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        fs::create_dir_all(&mod_root).unwrap();
        fs::write(mod_root.join("Sword.fbx"), b"fbx").unwrap();
        fs::write(mod_root.join("Sword.pskx"), b"pskx").unwrap();
        fs::write(mod_root.join("Sword.json"), b"{}").unwrap();
        fs::write(mod_root.join("Preview.png"), b"png").unwrap();
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: None,
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        assert_eq!(
            report.inventory.as_ref().unwrap().classification,
            "loose-files-or-unknown"
        );
        assert!(!report.can_update);
        assert_eq!(report.disposition.code, "authoring-resource-source-assets");
        assert!(report.disposition.reason.contains("authoring"));
    }

    #[test]
    fn mixed_script_and_executable_payload_keeps_the_generic_terminal_code() {
        let temp = tempfile::tempdir().unwrap();
        let mod_root = temp.path().join("mod");
        fs::create_dir_all(&mod_root).unwrap();
        fs::write(mod_root.join("Tool.exe"), b"MZ tool").unwrap();
        fs::write(mod_root.join("script.lua"), b"-- script").unwrap();
        let report = analyze(&PreflightRequest {
            mod_input: mod_root,
            game_root: None,
            output_parent: Some(temp.path().to_path_buf()),
            connected_tools: Vec::new(),
        });
        assert!(!report.can_update);
        assert_eq!(report.disposition.code, "unsupported-structural-content");
    }
}
