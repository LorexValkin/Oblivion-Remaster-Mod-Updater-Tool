use crate::archive::{MAX_ARCHIVE_ENTRIES, extract_archive_files_with_extensions, sha256_bytes};
use crate::tes4::{
    COMPRESSED_RECORD, DELETED_RECORD, LIGHT_PLUGIN, MASTER_FILE, Plugin, Record,
    merge_inventory_addition, package_to_game_path, read_plugin_bytes, read_sync_map_bytes,
    supports_additive_inventory_record,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const PLUGIN_MANIFEST_API: &str = "tes4-plugin-manifest-v1";
pub const PLUGIN_PRESERVATION_API: &str = "tes4-plugin-byte-preservation-v1";
pub const PLUGIN_SEMANTIC_REWRITE_API: &str = "tes4-inventory-semantic-rewrite-v1";
pub const ADDITIVE_PLUGIN_POLICY: &str = "tes4-additive-syncmap-policy-v2";
const MIN_FULL_PLUGIN_LOCAL_ID: u32 = 0x800;
const MAX_PLUGIN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SELECTED_METADATA_BYTES: u64 = 512 * 1024 * 1024;
const PLUGIN_METADATA_EXTENSIONS: &[&str] = &["esp", "esm", "esl", "ini"];
pub const ADDITIVE_CONTRACT_API: &str = "tes4-syncmap-additive-contract-v2";
pub const WORLDSPACE_MASTER_PROBE_API: &str = "tes4-worldspace-master-resolution-probe-v1";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterDependency {
    pub plugin: String,
    pub master: String,
    pub master_index: usize,
    pub source: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginArtifact {
    pub relative_path: String,
    pub file_name: String,
    pub kind: String,
    pub bytes: u64,
    pub sha256: String,
    pub parse_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_flags: Option<String>,
    pub master_flag: bool,
    pub light_plugin_flag: bool,
    pub masters: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_record_count: Option<u32>,
    pub parsed_group_count: usize,
    pub parsed_record_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_object_id: Option<String>,
    pub record_type_counts: BTreeMap<String, usize>,
    pub master_override_type_counts: BTreeMap<String, usize>,
    pub plugin_owned_record_count: usize,
    pub master_override_record_count: usize,
    pub out_of_range_record_count: usize,
    pub reserved_local_form_id_count: usize,
    pub duplicate_form_id_count: usize,
    pub compressed_record_count: usize,
    pub deleted_record_count: usize,
    pub change_domains: Vec<String>,
    pub structural_blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginMirrorEvidence {
    pub file_name: String,
    pub canonical_relative_path: String,
    pub mirror_relative_path: String,
    pub sync_map_relative_path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginPolicyEvaluation {
    pub id: String,
    pub compatible: bool,
    pub mutation_policy: String,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSetReport {
    pub api: String,
    pub scan_mode: String,
    pub status: String,
    pub manifest_sha256: String,
    /// Number of physical ESP/ESM/ESL files retained in `artifacts`.
    pub plugin_count: usize,
    /// Number of plugins used for dependency and mutation-policy analysis after
    /// collapsing only recognized byte-identical SyncMap mirrors.
    pub logical_plugin_count: usize,
    pub parsed_plugin_count: usize,
    pub artifacts: Vec<PluginArtifact>,
    pub plugin_mirrors: Vec<PluginMirrorEvidence>,
    pub dependency_edges: Vec<MasterDependency>,
    pub unresolved_external_masters: Vec<String>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub additive_syncmap_v1: PluginPolicyEvaluation,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditiveContractReport {
    pub api: String,
    pub status: String,
    pub compatible: bool,
    pub current_master_checked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_map_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_map_sha256: Option<String>,
    pub sync_map_entry_count: usize,
    pub validated_master_override_count: usize,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledMasterProbe {
    pub declared_name: String,
    pub master_index: usize,
    pub found: bool,
    pub parsed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_file_name: Option<String>,
    pub own_master_count: usize,
    pub indexed_record_count: usize,
    pub matching_override_record_count: usize,
    pub unmappable_record_count: usize,
    pub unmappable_target_collision_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorldspaceMasterProbeReport {
    pub api: String,
    pub status: String,
    pub resolution_complete: bool,
    pub semantic_compatibility_claimed: bool,
    pub mutation_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_path: Option<String>,
    pub declared_master_count: usize,
    pub found_master_count: usize,
    pub parsed_master_count: usize,
    pub master_override_count: usize,
    pub resolved_master_override_count: usize,
    pub unresolved_master_override_count: usize,
    pub type_mismatch_override_count: usize,
    pub deleted_master_override_count: usize,
    pub masters: Vec<InstalledMasterProbe>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

impl PluginSetReport {
    pub fn unavailable(expected_plugins: usize) -> Self {
        Self {
            api: PLUGIN_MANIFEST_API.to_owned(),
            scan_mode: "unavailable".to_owned(),
            status: "failed".to_owned(),
            manifest_sha256: String::new(),
            plugin_count: expected_plugins,
            logical_plugin_count: expected_plugins,
            parsed_plugin_count: 0,
            artifacts: Vec::new(),
            plugin_mirrors: Vec::new(),
            dependency_edges: Vec::new(),
            unresolved_external_masters: Vec::new(),
            blockers: vec!["plugin-input-could-not-be-staged-safely".to_owned()],
            warnings: Vec::new(),
            additive_syncmap_v1: PluginPolicyEvaluation {
                id: ADDITIVE_PLUGIN_POLICY.to_owned(),
                compatible: false,
                mutation_policy: "report-only".to_owned(),
                blockers: vec!["plugin-analysis-unavailable".to_owned()],
            },
        }
    }
}

fn plugin_kind(path: &Path) -> Option<String> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    matches!(extension.as_str(), "esp" | "esm" | "esl").then_some(extension)
}

fn normalize_relative(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn direct_game_data_plugin(path: &str) -> bool {
    let normalized = path.trim_start_matches('/').to_ascii_lowercase();
    let marker = "content/dev/obvdata/data/";
    let Some(tail) = normalized.strip_prefix(marker) else {
        return false;
    };
    !tail.is_empty() && !tail.contains('/')
}

fn direct_sync_map_ini(path: &str) -> bool {
    let normalized = path.trim_start_matches('/').to_ascii_lowercase();
    let marker = "content/dev/obvdata/data/syncmap/";
    let Some(tail) = normalized.strip_prefix(marker) else {
        return false;
    };
    !tail.is_empty() && !tail.contains('/')
}

fn direct_sync_map_plugin(path: &str) -> bool {
    let normalized = path.trim_start_matches('/').to_ascii_lowercase();
    let marker = "content/dev/obvdata/data/syncmap/";
    let Some(tail) = normalized.strip_prefix(marker) else {
        return false;
    };
    !tail.is_empty() && !tail.contains('/')
}

fn record_domain(kind: &str) -> &'static str {
    match kind {
        "WRLD" | "CELL" | "REFR" | "ACHR" | "ACRE" | "LAND" | "NAVM" | "PGRD" => {
            "worldspace-and-placement"
        }
        "CONT" | "LVLI" | "LVLC" | "LVSP" => "distribution-and-leveled-content",
        "ARMO" | "WEAP" | "AMMO" | "ALCH" | "INGR" | "BOOK" => "items-and-equipment",
        "NPC_" | "CREA" | "RACE" | "CLAS" => "actors-and-races",
        "QUST" | "DIAL" | "INFO" | "SCEN" => "quests-and-dialogue",
        "SPEL" | "ENCH" | "MGEF" => "magic",
        "STAT" | "DOOR" | "ACTI" | "FURN" | "TREE" | "FLOR" => "world-objects",
        _ => "other-tes-data",
    }
}

fn analyze_parsed_plugin(
    relative_path: String,
    file_name: String,
    kind: String,
    bytes: u64,
    sha256: String,
    plugin: Plugin,
) -> PluginArtifact {
    let mut record_type_counts = BTreeMap::new();
    let mut master_override_type_counts = BTreeMap::new();
    let mut domains = BTreeSet::new();
    let mut seen_form_ids = HashSet::new();
    let mut duplicate_form_id_count = 0;
    let mut plugin_owned_record_count = 0;
    let mut master_override_record_count = 0;
    let mut out_of_range_record_count = 0;
    let mut reserved_local_form_id_count = 0;
    let mut compressed_record_count = 0;
    let mut deleted_record_count = 0;
    let mut max_owned_local_id = None::<u32>;
    let plugin_index = plugin.masters.len();
    let light_semantics = kind == "esl" || plugin.header_flags & LIGHT_PLUGIN != 0;
    let ordinary_form_ids = !light_semantics && plugin_index <= u8::MAX as usize;

    for record in &plugin.records {
        *record_type_counts.entry(record.kind.clone()).or_default() += 1;
        domains.insert(record_domain(&record.kind).to_owned());
        if !seen_form_ids.insert(record.form_id) {
            duplicate_form_id_count += 1;
        }
        if record.flags & COMPRESSED_RECORD != 0 {
            compressed_record_count += 1;
        }
        if record.flags & DELETED_RECORD != 0 {
            deleted_record_count += 1;
        }
        if !ordinary_form_ids {
            continue;
        }
        let source_index = (record.form_id >> 24) as usize;
        if source_index < plugin_index {
            master_override_record_count += 1;
            *master_override_type_counts
                .entry(record.kind.clone())
                .or_default() += 1;
        } else if source_index == plugin_index {
            plugin_owned_record_count += 1;
            let local_id = record.form_id & 0x00ff_ffff;
            max_owned_local_id =
                Some(max_owned_local_id.map_or(local_id, |value| value.max(local_id)));
            if local_id < MIN_FULL_PLUGIN_LOCAL_ID {
                reserved_local_form_id_count += 1;
            }
        } else {
            out_of_range_record_count += 1;
        }
    }

    let mut structural_blockers = Vec::new();
    let mut warnings = Vec::new();
    if duplicate_form_id_count > 0 {
        structural_blockers.push("duplicate-form-ids".to_owned());
    }
    if light_semantics {
        warnings.push(
            "ESL/light-plugin FormID semantics are not runtime-proven and remain report-only"
                .to_owned(),
        );
    } else if plugin_index > u8::MAX as usize {
        structural_blockers.push("master-count-exceeds-full-plugin-index-space".to_owned());
    } else {
        if out_of_range_record_count > 0 {
            structural_blockers.push("record-form-ids-exceed-master-plugin-index-range".to_owned());
        }
        if reserved_local_form_id_count > 0 {
            structural_blockers.push("plugin-owned-local-form-ids-below-0x800".to_owned());
        }
    }
    if plugin.declared_record_count as usize != plugin.records.len() + plugin.group_count {
        structural_blockers
            .push("declared-record-count-does-not-match-records-and-groups".to_owned());
    }
    if !light_semantics {
        if plugin.next_object_id < MIN_FULL_PLUGIN_LOCAL_ID {
            structural_blockers.push("next-object-id-below-0x800".to_owned());
        } else if max_owned_local_id.is_some_and(|value| plugin.next_object_id <= value) {
            warnings.push(
                "TES4 HEDR nextObjectId does not follow the highest owned FormID; this byte-preserving adapter never allocates FormIDs"
                    .to_owned(),
            );
        }
    }
    let mut master_names = HashSet::new();
    if plugin
        .masters
        .iter()
        .any(|master| !master_names.insert(master.to_ascii_lowercase()))
    {
        structural_blockers.push("duplicate-master-names".to_owned());
    }
    if deleted_record_count > 0 {
        warnings.push(
            "Plugin contains deleted records; semantic update requires a dedicated record adapter"
                .to_owned(),
        );
    }
    structural_blockers.sort();
    structural_blockers.dedup();

    PluginArtifact {
        relative_path,
        file_name,
        kind,
        bytes,
        sha256,
        parse_status: "parsed".to_owned(),
        parse_error: None,
        header_flags: Some(format!("0x{:08X}", plugin.header_flags)),
        master_flag: plugin.header_flags & MASTER_FILE != 0,
        light_plugin_flag: plugin.header_flags & LIGHT_PLUGIN != 0,
        masters: plugin.masters,
        declared_record_count: Some(plugin.declared_record_count),
        parsed_group_count: plugin.group_count,
        parsed_record_count: plugin.records.len(),
        next_object_id: Some(format!("0x{:06X}", plugin.next_object_id)),
        record_type_counts,
        master_override_type_counts,
        plugin_owned_record_count,
        master_override_record_count,
        out_of_range_record_count,
        reserved_local_form_id_count,
        duplicate_form_id_count,
        compressed_record_count,
        deleted_record_count,
        change_domains: domains.into_iter().collect(),
        structural_blockers,
        warnings,
    }
}

fn failed_artifact(
    relative_path: String,
    file_name: String,
    kind: String,
    bytes: u64,
    sha256: String,
    error: &anyhow::Error,
) -> PluginArtifact {
    PluginArtifact {
        relative_path,
        file_name,
        kind,
        bytes,
        sha256,
        parse_status: "failed".to_owned(),
        parse_error: Some(format!("{error:#}")),
        header_flags: None,
        master_flag: false,
        light_plugin_flag: false,
        masters: Vec::new(),
        declared_record_count: None,
        parsed_group_count: 0,
        parsed_record_count: 0,
        next_object_id: None,
        record_type_counts: BTreeMap::new(),
        master_override_type_counts: BTreeMap::new(),
        plugin_owned_record_count: 0,
        master_override_record_count: 0,
        out_of_range_record_count: 0,
        reserved_local_form_id_count: 0,
        duplicate_form_id_count: 0,
        compressed_record_count: 0,
        deleted_record_count: 0,
        change_domains: Vec::new(),
        structural_blockers: vec!["plugin-parse-failed".to_owned()],
        warnings: Vec::new(),
    }
}

fn graph_has_cycle(adjacency: &BTreeMap<String, BTreeSet<String>>) -> bool {
    fn visit(
        node: &str,
        adjacency: &BTreeMap<String, BTreeSet<String>>,
        states: &mut HashMap<String, u8>,
    ) -> bool {
        match states.get(node).copied().unwrap_or(0) {
            1 => return true,
            2 => return false,
            _ => {}
        }
        states.insert(node.to_owned(), 1);
        if adjacency
            .get(node)
            .is_some_and(|neighbors| neighbors.iter().any(|next| visit(next, adjacency, states)))
        {
            return true;
        }
        states.insert(node.to_owned(), 2);
        false
    }

    let mut states = HashMap::new();
    adjacency
        .keys()
        .any(|node| visit(node, adjacency, &mut states))
}

fn evaluate_additive_policy(
    artifacts: &[PluginArtifact],
    global_blockers: &[String],
) -> PluginPolicyEvaluation {
    let mut blockers = global_blockers.to_vec();
    if artifacts.len() != 1 {
        blockers.push("requires-exactly-one-plugin".to_owned());
    }
    if let Some(plugin) = artifacts.first().filter(|_| artifacts.len() == 1) {
        if plugin.kind != "esp" {
            blockers.push("requires-one-full-esp-not-esm-or-esl".to_owned());
        }
        if plugin.master_flag {
            blockers.push("esp-header-declares-master-file".to_owned());
        }
        if plugin.light_plugin_flag {
            blockers.push("esp-header-declares-light-plugin".to_owned());
        }
        if !direct_game_data_plugin(&plugin.relative_path) {
            blockers.push("esp-is-not-directly-under-content-dev-obvdata-data".to_owned());
        }
        if plugin.parse_status != "parsed" {
            blockers.push("esp-could-not-be-parsed".to_owned());
        }
        if plugin.masters.is_empty() || !plugin.masters[0].eq_ignore_ascii_case("Oblivion.esm") {
            blockers.push("requires-oblivion-esm-as-first-master".to_owned());
        }
        if plugin
            .master_override_type_counts
            .keys()
            .any(|kind| !supports_additive_inventory_record(kind))
        {
            blockers.push(
                "master-overrides-outside-supported-inventory-records-are-unsupported".to_owned(),
            );
        }
        blockers.extend(plugin.structural_blockers.iter().cloned());
    }
    blockers.sort();
    blockers.dedup();
    PluginPolicyEvaluation {
        id: ADDITIVE_PLUGIN_POLICY.to_owned(),
        compatible: blockers.is_empty(),
        mutation_policy: if blockers.is_empty() {
            "merge-current-master-inventory-and-preserve-plugin-additions".to_owned()
        } else {
            "report-only".to_owned()
        },
        blockers,
    }
}

fn bounded_file_payload(path: &Path, label: &str, limit: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path).with_context(|| format!("opening bounded payload {label}"))?;
    let declared_bytes = file.metadata()?.len();
    if declared_bytes > limit {
        bail!("payload exceeds the {limit} byte content-analysis limit: {label}");
    }
    let mut payload = Vec::with_capacity(declared_bytes as usize);
    file.take(limit + 1)
        .read_to_end(&mut payload)
        .with_context(|| format!("reading bounded payload {label}"))?;
    if payload.len() as u64 > limit {
        bail!("payload exceeds the {limit} byte content-analysis limit: {label}");
    }
    if payload.len() as u64 != declared_bytes {
        bail!("payload size changed while it was being read: {label}");
    }
    Ok(payload)
}

fn bounded_plugin_payload(path: &Path, relative_path: &str) -> Result<Vec<u8>> {
    bounded_file_payload(path, relative_path, MAX_PLUGIN_BYTES)
}

fn bounded_tree_paths(root: &Path, predicate: impl Fn(&Path) -> bool) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for (index, entry) in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        if index >= MAX_ARCHIVE_ENTRIES {
            bail!(
                "plugin metadata tree exceeds the {} entry safety limit",
                MAX_ARCHIVE_ENTRIES
            );
        }
        let entry =
            entry.with_context(|| format!("walking staged plugin tree {}", root.display()))?;
        if entry.path() == root {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!("plugin tree contains a filesystem link");
        }
        if entry.file_type().is_file() && predicate(entry.path()) {
            paths.push(entry.path().to_path_buf());
        }
    }
    paths.sort_by_key(|path| {
        normalize_relative(path.strip_prefix(root).unwrap_or(path)).to_ascii_lowercase()
    });
    Ok(paths)
}

fn files_are_byte_identical(left: &Path, right: &Path, expected_bytes: u64) -> Result<bool> {
    if expected_bytes > MAX_PLUGIN_BYTES {
        bail!("plugin mirror exceeds the bounded content-analysis limit");
    }
    let mut left = fs::File::open(left).context("opening canonical plugin mirror candidate")?;
    let mut right = fs::File::open(right).context("opening SyncMap plugin mirror candidate")?;
    if left.metadata()?.len() != expected_bytes || right.metadata()?.len() != expected_bytes {
        return Ok(false);
    }

    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    let mut remaining = expected_bytes;
    while remaining > 0 {
        let chunk = remaining.min(left_buffer.len() as u64) as usize;
        left.read_exact(&mut left_buffer[..chunk])?;
        right.read_exact(&mut right_buffer[..chunk])?;
        if left_buffer[..chunk] != right_buffer[..chunk] {
            return Ok(false);
        }
        remaining -= chunk as u64;
    }
    let mut trailing = [0_u8; 1];
    Ok(left.read(&mut trailing)? == 0 && right.read(&mut trailing)? == 0)
}

fn recognize_plugin_mirror(
    artifacts: &[PluginArtifact],
    artifact_paths: &[PathBuf],
    indexes: &[usize],
    direct_sync_map_inis: &[(String, String)],
) -> Result<Option<(usize, PluginMirrorEvidence)>> {
    if indexes.len() != 2 {
        return Ok(None);
    }
    let canonical = indexes
        .iter()
        .copied()
        .filter(|index| {
            artifacts[*index].kind == "esp"
                && direct_game_data_plugin(&artifacts[*index].relative_path)
        })
        .collect::<Vec<_>>();
    let mirror = indexes
        .iter()
        .copied()
        .filter(|index| {
            artifacts[*index].kind == "esp"
                && direct_sync_map_plugin(&artifacts[*index].relative_path)
        })
        .collect::<Vec<_>>();
    let ([canonical], [mirror]) = (canonical.as_slice(), mirror.as_slice()) else {
        return Ok(None);
    };
    let canonical = *canonical;
    let mirror = *mirror;
    let canonical_artifact = &artifacts[canonical];
    let mirror_artifact = &artifacts[mirror];
    if !canonical_artifact
        .file_name
        .eq_ignore_ascii_case(&mirror_artifact.file_name)
        || canonical_artifact.bytes != mirror_artifact.bytes
        || canonical_artifact.sha256 != mirror_artifact.sha256
    {
        return Ok(None);
    }

    let plugin_stem = Path::new(&canonical_artifact.file_name)
        .file_stem()
        .and_then(|value| value.to_str())
        .context("plugin mirror filename has no Unicode stem")?;
    let matching_inis = direct_sync_map_inis
        .iter()
        .filter(|(stem, _)| stem.eq_ignore_ascii_case(plugin_stem))
        .collect::<Vec<_>>();
    let [(_, sync_map_relative_path)] = matching_inis.as_slice() else {
        return Ok(None);
    };
    if !files_are_byte_identical(
        &artifact_paths[canonical],
        &artifact_paths[mirror],
        canonical_artifact.bytes,
    )? {
        return Ok(None);
    }

    Ok(Some((
        canonical,
        PluginMirrorEvidence {
            file_name: canonical_artifact.file_name.clone(),
            canonical_relative_path: canonical_artifact.relative_path.clone(),
            mirror_relative_path: mirror_artifact.relative_path.clone(),
            sync_map_relative_path: sync_map_relative_path.clone(),
            bytes: canonical_artifact.bytes,
            sha256: canonical_artifact.sha256.clone(),
        },
    )))
}

pub fn inspect_plugin_set(root: &Path) -> Result<PluginSetReport> {
    let paths = bounded_tree_paths(root, |path| plugin_kind(path).is_some())?;

    let mut artifacts = Vec::new();
    for path in &paths {
        let relative_path = normalize_relative(path.strip_prefix(root)?);
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .context("plugin path has no Unicode filename")?
            .to_owned();
        let kind = plugin_kind(path).context("plugin extension disappeared")?;
        let payload = bounded_plugin_payload(path, &relative_path)?;
        let bytes = payload.len() as u64;
        let sha256 = sha256_bytes(&payload);
        let artifact = match read_plugin_bytes(&payload, &relative_path) {
            Ok(plugin) => {
                analyze_parsed_plugin(relative_path, file_name, kind, bytes, sha256, plugin)
            }
            Err(error) => failed_artifact(relative_path, file_name, kind, bytes, sha256, &error),
        };
        artifacts.push(artifact);
    }

    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut physical_file_names = BTreeMap::<String, Vec<usize>>::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        physical_file_names
            .entry(artifact.file_name.to_ascii_lowercase())
            .or_default()
            .push(index);
    }

    let direct_sync_map_inis = bounded_tree_paths(root, |path| {
        path.extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("ini"))
            && direct_sync_map_ini(&normalize_relative(path.strip_prefix(root).unwrap_or(path)))
    })?
    .into_iter()
    .map(|path| {
        let relative_path = normalize_relative(path.strip_prefix(root).unwrap_or(&path));
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .context("SyncMap INI path has no Unicode stem")?
            .to_owned();
        Ok((stem, relative_path))
    })
    .collect::<Result<Vec<_>>>()?;

    let mut logical_indexes = Vec::new();
    let mut plugin_mirrors = Vec::new();
    for indexes in physical_file_names.values() {
        if indexes.len() == 1 {
            logical_indexes.push(indexes[0]);
        } else if let Some((canonical, mirror)) =
            recognize_plugin_mirror(&artifacts, &paths, indexes, &direct_sync_map_inis)?
        {
            logical_indexes.push(canonical);
            plugin_mirrors.push(mirror);
        } else {
            blockers.push("case-insensitive-plugin-filename-collision".to_owned());
            logical_indexes.extend(indexes.iter().copied());
        }
    }
    logical_indexes.sort_unstable();
    plugin_mirrors.sort_by(|left, right| {
        left.canonical_relative_path
            .to_ascii_lowercase()
            .cmp(&right.canonical_relative_path.to_ascii_lowercase())
    });

    let mut file_names = BTreeMap::<String, Vec<usize>>::new();
    for index in &logical_indexes {
        let artifact = &artifacts[*index];
        file_names
            .entry(artifact.file_name.to_ascii_lowercase())
            .or_default()
            .push(*index);
        blockers.extend(
            artifact
                .structural_blockers
                .iter()
                .map(|blocker| format!("{}:{blocker}", artifact.file_name)),
        );
        warnings.extend(
            artifact
                .warnings
                .iter()
                .map(|warning| format!("{}: {warning}", artifact.file_name)),
        );
    }

    let mut dependency_edges = Vec::new();
    let mut unresolved_external_masters = BTreeSet::new();
    let mut adjacency = BTreeMap::<String, BTreeSet<String>>::new();
    for index in &logical_indexes {
        let artifact = &artifacts[*index];
        let plugin_key = artifact.file_name.to_ascii_lowercase();
        adjacency.entry(plugin_key.clone()).or_default();
        for (master_index, master) in artifact.masters.iter().enumerate() {
            let master_key = master.to_ascii_lowercase();
            let source = if master.eq_ignore_ascii_case("Oblivion.esm") {
                "game-base-master"
            } else if file_names
                .get(&master_key)
                .is_some_and(|rows| rows.len() == 1)
            {
                adjacency
                    .entry(plugin_key.clone())
                    .or_default()
                    .insert(master_key.clone());
                "bundled-plugin"
            } else if file_names.contains_key(&master_key) {
                blockers.push(format!(
                    "{}:ambiguous-bundled-master:{master}",
                    artifact.file_name
                ));
                "ambiguous-bundled-plugin"
            } else {
                unresolved_external_masters.insert(master.clone());
                "external-master"
            };
            if master_key == plugin_key {
                blockers.push(format!(
                    "{}:plugin-lists-itself-as-master",
                    artifact.file_name
                ));
            }
            dependency_edges.push(MasterDependency {
                plugin: artifact.file_name.clone(),
                master: master.clone(),
                master_index,
                source: source.to_owned(),
            });
        }
    }
    if graph_has_cycle(&adjacency) {
        blockers.push("bundled-plugin-master-cycle".to_owned());
    }

    let mut manifest_rows = artifacts
        .iter()
        .map(|artifact| {
            format!(
                "{}\t{}\t{}\t{}",
                artifact.relative_path, artifact.kind, artifact.bytes, artifact.sha256
            )
        })
        .collect::<Vec<_>>();
    manifest_rows.sort();
    blockers.sort();
    blockers.dedup();
    warnings.sort();
    warnings.dedup();
    dependency_edges.sort_by(|left, right| {
        (&left.plugin, left.master_index, &left.master).cmp(&(
            &right.plugin,
            right.master_index,
            &right.master,
        ))
    });
    let parsed_plugin_count = artifacts
        .iter()
        .filter(|artifact| artifact.parse_status == "parsed")
        .count();
    let status = if parsed_plugin_count == artifacts.len() {
        "complete"
    } else if parsed_plugin_count == 0 {
        "failed"
    } else {
        "partial"
    };
    let logical_artifacts = logical_indexes
        .iter()
        .map(|index| artifacts[*index].clone())
        .collect::<Vec<_>>();
    let additive_syncmap_v1 = evaluate_additive_policy(&logical_artifacts, &blockers);

    Ok(PluginSetReport {
        api: PLUGIN_MANIFEST_API.to_owned(),
        scan_mode: "staged-tree".to_owned(),
        status: status.to_owned(),
        manifest_sha256: sha256_bytes(manifest_rows.join("\n").as_bytes()),
        plugin_count: artifacts.len(),
        logical_plugin_count: logical_artifacts.len(),
        parsed_plugin_count,
        artifacts,
        plugin_mirrors,
        dependency_edges,
        unresolved_external_masters: unresolved_external_masters.into_iter().collect(),
        blockers,
        warnings,
        additive_syncmap_v1,
    })
}

fn safe_candidate_root(root: &str) -> Result<PathBuf> {
    let path = Path::new(root);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || !path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        bail!("candidate mod root is not a safe relative path");
    }
    Ok(path.to_path_buf())
}

fn copy_bounded_metadata_file(
    source_path: &Path,
    target: &Path,
    relative: &Path,
    selected_bytes: &mut u64,
    per_file_limit: u64,
    total_limit: u64,
) -> Result<()> {
    let mut source = fs::File::open(source_path)
        .with_context(|| format!("opening selected metadata {}", source_path.display()))?;
    let declared_bytes = source.metadata()?.len();
    if declared_bytes > per_file_limit {
        bail!(
            "selected plugin metadata entry exceeds the {} byte safety limit: {}",
            per_file_limit,
            normalize_relative(relative)
        );
    }
    let next_total = selected_bytes
        .checked_add(declared_bytes)
        .context("selected plugin metadata size overflow")?;
    if next_total > total_limit {
        bail!(
            "selected plugin metadata exceeds the {} byte safety limit",
            total_limit
        );
    }

    fs::create_dir_all(target.parent().context("metadata file has no parent")?)?;
    let mut output = BufWriter::new(fs::File::create(target)?);
    let copied = io::copy(
        &mut Read::by_ref(&mut source).take(declared_bytes),
        &mut output,
    )?;
    let mut extra = [0_u8; 1];
    let has_extra_byte = source.read(&mut extra)? != 0;
    output.flush()?;
    if copied != declared_bytes || has_extra_byte {
        drop(output);
        let _ = fs::remove_file(target);
        bail!(
            "selected plugin metadata size changed while it was being copied: {}",
            normalize_relative(relative)
        );
    }
    *selected_bytes = next_total;
    Ok(())
}

fn stage_selected_metadata(input: &Path, destination: &Path) -> Result<&'static str> {
    if input.is_file() {
        extract_archive_files_with_extensions(
            input,
            destination,
            PLUGIN_METADATA_EXTENSIONS,
            MAX_SELECTED_METADATA_BYTES,
        )?;
        return Ok("validated-selected-entry-extraction");
    }
    let mut selected_bytes = 0_u64;
    for path in bounded_tree_paths(input, |path| {
        path.extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| {
                PLUGIN_METADATA_EXTENSIONS
                    .iter()
                    .any(|extension| value.eq_ignore_ascii_case(extension))
            })
    })? {
        let relative = path.strip_prefix(input)?;
        let target = destination.join(relative);
        copy_bounded_metadata_file(
            &path,
            &target,
            relative,
            &mut selected_bytes,
            MAX_PLUGIN_BYTES,
            MAX_SELECTED_METADATA_BYTES,
        )?;
    }
    Ok("bounded-selected-file-snapshot")
}

fn staged_candidate_root(staged: &Path, candidate_root: Option<&str>) -> Result<PathBuf> {
    let Some(candidate_root) = candidate_root.filter(|value| *value != ".") else {
        return Ok(staged.to_path_buf());
    };
    let relative = safe_candidate_root(candidate_root)?;
    let root = staged.join(relative);
    if !root.is_dir() {
        bail!("candidate mod root was not present in the selected metadata snapshot");
    }
    Ok(root)
}

fn inspect_staged_plugin_input(
    input: &Path,
    candidate_root: Option<&str>,
) -> Result<(tempfile::TempDir, PathBuf, &'static str)> {
    let staged = tempfile::Builder::new()
        .prefix("obr-plugin-manifest-")
        .tempdir()?;
    let scan_mode = stage_selected_metadata(input, staged.path())?;
    let root = staged_candidate_root(staged.path(), candidate_root)?;
    Ok((staged, root, scan_mode))
}

pub fn inspect_plugin_input_at_root(
    input: &Path,
    candidate_root: Option<&str>,
) -> Result<PluginSetReport> {
    let (_staged, root, scan_mode) = inspect_staged_plugin_input(input, candidate_root)?;
    let mut report = inspect_plugin_set(&root)?;
    report.scan_mode = scan_mode.to_owned();
    Ok(report)
}

pub fn inspect_plugin_input(input: &Path) -> Result<PluginSetReport> {
    inspect_plugin_input_at_root(input, None)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CanonicalFormId {
    origin: String,
    local_id: u32,
}

#[derive(Clone, Debug)]
struct IndexedMasterRecord {
    kind: String,
    provider: String,
    record: Record,
}

#[derive(Clone, Debug)]
struct InstalledMasterIndex {
    masters: Vec<String>,
    record_count: usize,
    matching_records: BTreeMap<CanonicalFormId, IndexedMasterRecord>,
    unmappable_record_count: usize,
    unmappable_target_collisions: Vec<u32>,
}

#[derive(Clone, Debug)]
struct DataEntryCandidate {
    file_name: String,
    path: PathBuf,
    regular_file: bool,
    symlink: bool,
}

#[derive(Clone, Debug)]
pub struct ResolvedInstalledRecord {
    pub record: Record,
    pub provider: String,
}

fn canonical_form_id(owner: &str, masters: &[String], form_id: u32) -> Result<CanonicalFormId> {
    if masters.len() > u8::MAX as usize {
        bail!("master count exceeds the full-plugin FormID index space");
    }
    let source_index = (form_id >> 24) as usize;
    let origin = if source_index < masters.len() {
        &masters[source_index]
    } else if source_index == masters.len() {
        owner
    } else {
        bail!(
            "record 0x{form_id:08X} uses source index {source_index} beyond full-plugin index {}",
            masters.len()
        );
    };
    Ok(CanonicalFormId {
        origin: origin.to_ascii_lowercase(),
        local_id: form_id & 0x00ff_ffff,
    })
}

fn header_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .with_context(|| format!("truncated {label}"))?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn index_installed_master(
    path: &Path,
    declared_name: &str,
    wanted: &BTreeSet<CanonicalFormId>,
) -> Result<InstalledMasterIndex> {
    let mut source = fs::File::open(path)
        .with_context(|| format!("opening installed master {declared_name}"))?;
    let original_length = source
        .metadata()
        .with_context(|| format!("reading installed master metadata for {declared_name}"))?
        .len();
    if original_length < 20 {
        bail!("installed master is shorter than a TES4 record header");
    }

    let mut header = [0_u8; 20];
    source
        .read_exact(&mut header)
        .with_context(|| format!("reading TES4 header from installed master {declared_name}"))?;
    if &header[..4] != b"TES4" {
        bail!("installed master does not begin with a TES4 header");
    }
    let header_size = header_u32(&header, 4, "TES4 header size")? as u64;
    let header_end = 20_u64
        .checked_add(header_size)
        .context("TES4 header size overflow")?;
    if header_end > original_length {
        bail!("installed master has a truncated TES4 header");
    }
    if header_end > MAX_PLUGIN_BYTES {
        bail!("installed master TES4 header exceeds the bounded metadata limit");
    }
    let mut header_bytes = Vec::with_capacity(header_end as usize);
    header_bytes.extend_from_slice(&header);
    let mut header_payload = vec![0_u8; header_size as usize];
    source
        .read_exact(&mut header_payload)
        .with_context(|| format!("reading TES4 metadata from installed master {declared_name}"))?;
    header_bytes.extend_from_slice(&header_payload);
    let parsed_header = read_plugin_bytes(&header_bytes, declared_name)
        .with_context(|| format!("parsing TES4 metadata from installed master {declared_name}"))?;
    if parsed_header.header_flags & LIGHT_PLUGIN != 0 {
        bail!("light-plugin FormID semantics are not supported by this probe");
    }
    if parsed_header.masters.len() > u8::MAX as usize {
        bail!("master count exceeds the full-plugin FormID index space");
    }
    let mut master_names = HashSet::new();
    if parsed_header
        .masters
        .iter()
        .any(|master| !master_names.insert(master.to_ascii_lowercase()))
    {
        bail!("installed master declares duplicate case-insensitive master names");
    }

    let mut group_count = 0_usize;
    let mut record_count = 0_usize;
    let mut matching_records = BTreeMap::new();
    let wanted_local_ids = wanted
        .iter()
        .map(|identity| identity.local_id)
        .collect::<BTreeSet<_>>();
    let mut unmappable_record_count = 0_usize;
    let mut unmappable_target_collisions = Vec::new();
    let mut group_ends = Vec::<u64>::new();
    loop {
        let start = source.stream_position()?;
        while group_ends.last().is_some_and(|end| *end == start) {
            group_ends.pop();
        }
        if group_ends.last().is_some_and(|end| start > *end) {
            bail!("installed master record stream crossed a GRUP boundary");
        }
        if start == original_length {
            break;
        }
        let enclosing_end = group_ends.last().copied().unwrap_or(original_length);
        if start.checked_add(20).is_none_or(|end| end > enclosing_end) {
            bail!("installed master has trailing bytes inside a GRUP");
        }
        let mut record_header = [0_u8; 20];
        source.read_exact(&mut record_header).with_context(|| {
            format!("reading record header from installed master {declared_name}")
        })?;
        let kind = String::from_utf8_lossy(&record_header[..4]).into_owned();
        if kind == "GRUP" {
            let group_size = header_u32(&record_header, 4, "GRUP size")? as u64;
            let group_end = start
                .checked_add(group_size)
                .context("GRUP size overflow")?;
            if group_size < 20 || group_end > enclosing_end {
                bail!("installed master contains an invalid GRUP at 0x{start:X}");
            }
            group_count += 1;
            group_ends.push(group_end);
            continue;
        }

        let data_size = header_u32(&record_header, 4, "record data size")? as u64;
        let form_id = header_u32(&record_header, 12, "record FormID")?;
        let record_end = source
            .stream_position()?
            .checked_add(data_size)
            .context("record data size overflow")?;
        if record_end > enclosing_end {
            bail!("installed master contains a truncated {kind} record 0x{form_id:08X}");
        }
        record_count += 1;
        if (form_id >> 24) as usize > parsed_header.masters.len() {
            unmappable_record_count += 1;
            if wanted_local_ids.contains(&(form_id & 0x00ff_ffff)) {
                unmappable_target_collisions.push(form_id);
            }
        } else {
            let identity = canonical_form_id(declared_name, &parsed_header.masters, form_id)?;
            if wanted.contains(&identity) {
                if data_size > MAX_PLUGIN_BYTES {
                    bail!(
                        "target {kind} record 0x{form_id:08X} exceeds the bounded record-parse limit"
                    );
                }
                let mut raw = vec![0_u8; data_size as usize];
                source.read_exact(&mut raw).with_context(|| {
                    format!(
                        "reading target {kind} record 0x{form_id:08X} from installed master {declared_name}"
                    )
                })?;
                let mut fragment = Vec::with_capacity(
                    header_bytes
                        .len()
                        .checked_add(record_header.len())
                        .and_then(|size| size.checked_add(raw.len()))
                        .context("target record parse buffer size overflow")?,
                );
                fragment.extend_from_slice(&header_bytes);
                fragment.extend_from_slice(&record_header);
                fragment.extend_from_slice(&raw);
                let parsed_record = read_plugin_bytes(&fragment, declared_name)
                    .with_context(|| {
                        format!(
                            "parsing target {kind} record 0x{form_id:08X} from installed master {declared_name}"
                        )
                    })?
                    .records
                    .into_iter()
                    .next()
                    .context("target record parser returned no record")?;
                if parsed_record.kind != kind || parsed_record.form_id != form_id {
                    bail!("target record parser returned a different record identity");
                }
                if matching_records
                    .insert(
                        identity,
                        IndexedMasterRecord {
                            kind,
                            provider: declared_name.to_owned(),
                            record: parsed_record,
                        },
                    )
                    .is_some()
                {
                    bail!("installed master contains a duplicate target FormID 0x{form_id:08X}");
                }
            }
        }
        source.seek(SeekFrom::Start(record_end))?;
    }
    if source.stream_position()? != original_length {
        bail!("installed master has trailing bytes after its last complete record");
    }
    if parsed_header.declared_record_count as usize != record_count + group_count {
        bail!(
            "installed master HEDR count {} does not match {} records plus {} groups",
            parsed_header.declared_record_count,
            record_count,
            group_count
        );
    }
    if source.metadata()?.len() != original_length {
        bail!("installed master changed while it was being indexed");
    }
    Ok(InstalledMasterIndex {
        masters: parsed_header.masters,
        record_count,
        matching_records,
        unmappable_record_count,
        unmappable_target_collisions,
    })
}

fn case_insensitive_data_entries(
    game_data_dir: &Path,
) -> Result<BTreeMap<String, Vec<DataEntryCandidate>>> {
    if !game_data_dir.is_dir() {
        bail!("game Data directory is unavailable");
    }
    let mut entries = BTreeMap::<String, Vec<DataEntryCandidate>>::new();
    for (index, entry) in fs::read_dir(game_data_dir)
        .context("reading game Data directory")?
        .enumerate()
    {
        if index >= MAX_ARCHIVE_ENTRIES {
            bail!("game Data directory exceeds the bounded entry limit");
        }
        let entry = entry.context("reading a game Data directory entry")?;
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("game Data directory contains a non-Unicode name"))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading Data entry type for {file_name}"))?;
        entries
            .entry(file_name.to_ascii_lowercase())
            .or_default()
            .push(DataEntryCandidate {
                file_name,
                path: entry.path(),
                regular_file: file_type.is_file(),
                symlink: file_type.is_symlink(),
            });
    }
    Ok(entries)
}

/// Resolves records against the effective installed master chain. Requiring every master's own
/// dependency list to be the exact preceding prefix keeps all embedded full-plugin FormIDs aligned
/// with the staged plugin while still supporting arbitrary-length DLC/mod master chains.
pub fn resolve_installed_master_records(
    plugin: &Plugin,
    game_data_dir: &Path,
    wanted_form_ids: &[u32],
) -> Result<HashMap<u32, ResolvedInstalledRecord>> {
    if plugin.masters.is_empty() || plugin.masters.len() > u8::MAX as usize {
        bail!("plugin must declare a non-empty full-master chain");
    }
    let mut names = HashSet::new();
    if plugin
        .masters
        .iter()
        .any(|name| !names.insert(name.to_ascii_lowercase()))
    {
        bail!("plugin declares duplicate case-insensitive master names");
    }
    let mut wanted = BTreeSet::new();
    let mut staged_identities = Vec::new();
    for form_id in wanted_form_ids.iter().copied() {
        let source_index = (form_id >> 24) as usize;
        if source_index >= plugin.masters.len() {
            bail!("wanted FormID 0x{form_id:08X} is not owned by a declared master");
        }
        let identity = canonical_form_id("<staged-plugin>", &plugin.masters, form_id)?;
        wanted.insert(identity.clone());
        staged_identities.push((form_id, identity));
    }
    let data_entries = case_insensitive_data_entries(game_data_dir)?;
    let mut effective = BTreeMap::<CanonicalFormId, IndexedMasterRecord>::new();
    for (master_index, declared_name) in plugin.masters.iter().enumerate() {
        let candidates = data_entries
            .get(&declared_name.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or_default();
        if candidates.len() != 1 {
            bail!(
                "declared master {declared_name} requires one case-insensitive Data match; found {}",
                candidates.len()
            );
        }
        let candidate = &candidates[0];
        if !candidate.regular_file || candidate.symlink {
            bail!("declared master {declared_name} is not a direct regular Data file");
        }
        let index = index_installed_master(&candidate.path, declared_name, &wanted)
            .with_context(|| format!("indexing declared master {declared_name}"))?;
        if index.masters.len() != master_index
            || index
                .masters
                .iter()
                .zip(&plugin.masters[..master_index])
                .any(|(actual, expected)| !actual.eq_ignore_ascii_case(expected))
        {
            bail!(
                "installed master {declared_name} does not declare the exact preceding master prefix"
            );
        }
        if !index.unmappable_target_collisions.is_empty() {
            bail!("installed master {declared_name} has an unmappable target FormID collision");
        }
        for (identity, record) in index.matching_records {
            effective.insert(identity, record);
        }
    }
    let mut resolved = HashMap::new();
    for (staged_form_id, identity) in staged_identities {
        let indexed = effective.get(&identity).with_context(|| {
            format!("installed master chain has no target for 0x{staged_form_id:08X}")
        })?;
        if indexed.record.form_id != staged_form_id {
            bail!(
                "installed master prefix alignment produced a different raw FormID for 0x{staged_form_id:08X}"
            );
        }
        resolved.insert(
            staged_form_id,
            ResolvedInstalledRecord {
                record: indexed.record.clone(),
                provider: indexed.provider.clone(),
            },
        );
    }
    Ok(resolved)
}

fn finish_worldspace_master_probe(
    mut report: WorldspaceMasterProbeReport,
) -> WorldspaceMasterProbeReport {
    report.blockers.sort();
    report.blockers.dedup();
    report.warnings.sort();
    report.warnings.dedup();
    report.resolution_complete = report.blockers.is_empty()
        && report.resolved_master_override_count == report.master_override_count;
    report.status = if report.resolution_complete {
        "complete-report-only"
    } else {
        "blocked"
    }
    .to_owned();
    report
}

fn worldspace_master_probe_from_staged(
    root: &Path,
    plugin_set: &PluginSetReport,
    game_data_dir: &Path,
) -> WorldspaceMasterProbeReport {
    let mut report = WorldspaceMasterProbeReport {
        api: WORLDSPACE_MASTER_PROBE_API.to_owned(),
        status: "blocked".to_owned(),
        resolution_complete: false,
        semantic_compatibility_claimed: false,
        mutation_policy: "report-only".to_owned(),
        plugin_path: None,
        declared_master_count: 0,
        found_master_count: 0,
        parsed_master_count: 0,
        master_override_count: 0,
        resolved_master_override_count: 0,
        unresolved_master_override_count: 0,
        type_mismatch_override_count: 0,
        deleted_master_override_count: 0,
        masters: Vec::new(),
        blockers: Vec::new(),
        warnings: vec![
            "This probe proves only installed-master identity and record-type resolution; it does not prove record semantics, load-order safety, or runtime compatibility."
                .to_owned(),
        ],
    };

    let paths = match bounded_tree_paths(root, |path| plugin_kind(path).is_some()) {
        Ok(paths) => paths,
        Err(_) => {
            report.blockers.push("plugin-inventory-failed".to_owned());
            return finish_worldspace_master_probe(report);
        }
    };
    if paths.len() != 1 {
        report.blockers.push(format!(
            "requires-exactly-one-staged-plugin:found-{}",
            paths.len()
        ));
        return finish_worldspace_master_probe(report);
    }
    let path = &paths[0];
    let relative = normalize_relative(path.strip_prefix(root).unwrap_or(path));
    report.plugin_path = Some(relative.clone());
    let kind = plugin_kind(path).unwrap_or_default();
    if kind != "esp" {
        report
            .blockers
            .push("requires-one-full-esp-not-esm-or-esl".to_owned());
    }
    if !direct_game_data_plugin(&relative) {
        report
            .blockers
            .push("esp-is-not-directly-under-content-dev-obvdata-data".to_owned());
    }
    report.blockers.extend(
        plugin_set
            .blockers
            .iter()
            .map(|blocker| format!("plugin-manifest:{blocker}")),
    );
    report.warnings.extend(plugin_set.warnings.iter().cloned());

    let payload = match bounded_plugin_payload(path, &relative) {
        Ok(payload) => payload,
        Err(_) => {
            report.blockers.push("staged-plugin-read-failed".to_owned());
            return finish_worldspace_master_probe(report);
        }
    };
    let plugin = match read_plugin_bytes(&payload, &relative) {
        Ok(plugin) => plugin,
        Err(_) => {
            report
                .blockers
                .push("staged-plugin-parse-failed".to_owned());
            return finish_worldspace_master_probe(report);
        }
    };
    if plugin.header_flags & MASTER_FILE != 0 {
        report
            .blockers
            .push("esp-header-declares-master-file".to_owned());
    }
    if plugin.header_flags & LIGHT_PLUGIN != 0 {
        report
            .blockers
            .push("esp-header-declares-light-plugin".to_owned());
    }
    if !plugin
        .records
        .iter()
        .any(|record| record_domain(&record.kind) == "worldspace-and-placement")
    {
        report
            .blockers
            .push("plugin-has-no-worldspace-or-placement-records".to_owned());
    }
    report.declared_master_count = plugin.masters.len();
    if plugin.masters.is_empty() {
        report
            .blockers
            .push("plugin-declares-no-masters".to_owned());
    }
    if plugin.masters.len() > u8::MAX as usize {
        report
            .blockers
            .push("master-count-exceeds-full-plugin-index-space".to_owned());
        return finish_worldspace_master_probe(report);
    }
    let mut declared_names = HashSet::new();
    if plugin
        .masters
        .iter()
        .any(|master| !declared_names.insert(master.to_ascii_lowercase()))
    {
        report
            .blockers
            .push("plugin-declares-duplicate-case-insensitive-master-names".to_owned());
        return finish_worldspace_master_probe(report);
    }

    let mut overrides = Vec::new();
    let mut wanted = BTreeSet::new();
    for record in &plugin.records {
        let source_index = (record.form_id >> 24) as usize;
        if source_index < plugin.masters.len() {
            let identity = match canonical_form_id("staged-plugin", &plugin.masters, record.form_id)
            {
                Ok(identity) => identity,
                Err(_) => {
                    report.blockers.push(format!(
                        "staged-plugin-form-id-remap-failed:0x{:08X}",
                        record.form_id
                    ));
                    continue;
                }
            };
            wanted.insert(identity.clone());
            overrides.push((record.form_id, record.kind.clone(), identity));
            if record.flags & DELETED_RECORD != 0 {
                report.deleted_master_override_count += 1;
            }
        } else if source_index > plugin.masters.len() {
            report.blockers.push(format!(
                "staged-plugin-record-index-out-of-range:0x{:08X}",
                record.form_id
            ));
        }
    }
    report.master_override_count = overrides.len();
    if report.deleted_master_override_count > 0 {
        report.blockers.push(format!(
            "deleted-master-overrides-require-dedicated-semantic-validation:found-{}",
            report.deleted_master_override_count
        ));
    }

    let data_entries = match case_insensitive_data_entries(game_data_dir) {
        Ok(entries) => entries,
        Err(_) => {
            report
                .blockers
                .push("game-data-inventory-failed".to_owned());
            return finish_worldspace_master_probe(report);
        }
    };
    let mut indexes = Vec::<Option<InstalledMasterIndex>>::new();
    for (master_index, declared_name) in plugin.masters.iter().enumerate() {
        let mut master_report = InstalledMasterProbe {
            declared_name: declared_name.clone(),
            master_index,
            found: false,
            parsed: false,
            installed_file_name: None,
            own_master_count: 0,
            indexed_record_count: 0,
            matching_override_record_count: 0,
            unmappable_record_count: 0,
            unmappable_target_collision_count: 0,
        };
        let candidates = data_entries
            .get(&declared_name.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or_default();
        if candidates.is_empty() {
            report
                .blockers
                .push(format!("declared-master-missing:{declared_name}"));
            report.masters.push(master_report);
            indexes.push(None);
            continue;
        }
        if candidates.len() != 1 {
            report.blockers.push(format!(
                "declared-master-case-insensitive-match-is-ambiguous:{declared_name}:found-{}",
                candidates.len()
            ));
            report.masters.push(master_report);
            indexes.push(None);
            continue;
        }
        let candidate = &candidates[0];
        master_report.installed_file_name = Some(candidate.file_name.clone());
        if !candidate.regular_file || candidate.symlink {
            report.blockers.push(format!(
                "declared-master-is-not-a-direct-regular-file:{declared_name}"
            ));
            report.masters.push(master_report);
            indexes.push(None);
            continue;
        }
        master_report.found = true;
        report.found_master_count += 1;
        match index_installed_master(&candidate.path, declared_name, &wanted) {
            Ok(index) => {
                master_report.parsed = true;
                master_report.own_master_count = index.masters.len();
                master_report.indexed_record_count = index.record_count;
                master_report.matching_override_record_count = index.matching_records.len();
                master_report.unmappable_record_count = index.unmappable_record_count;
                master_report.unmappable_target_collision_count =
                    index.unmappable_target_collisions.len();
                if index.unmappable_record_count > 0 {
                    report.warnings.push(format!(
                        "{declared_name}: skipped {} record(s) whose source index cannot be mapped by that master's own master list",
                        index.unmappable_record_count
                    ));
                }
                for form_id in &index.unmappable_target_collisions {
                    report.blockers.push(format!(
                        "installed-master-unmappable-record-collides-with-target-local-id:{declared_name}:0x{form_id:08X}"
                    ));
                }
                for dependency in &index.masters {
                    match plugin
                        .masters
                        .iter()
                        .position(|master| master.eq_ignore_ascii_case(dependency))
                    {
                        Some(dependency_index) if dependency_index < master_index => {}
                        Some(dependency_index) => report.blockers.push(format!(
                            "installed-master-dependency-is-not-earlier-in-esp-declared-order:{declared_name}:{dependency}:index-{dependency_index}"
                        )),
                        None => report.blockers.push(format!(
                            "installed-master-dependency-is-absent-from-esp-declared-master-list:{declared_name}:{dependency}"
                        )),
                    }
                }
                report.parsed_master_count += 1;
                indexes.push(Some(index));
            }
            Err(_) => {
                report
                    .blockers
                    .push(format!("declared-master-parse-failed:{declared_name}"));
                indexes.push(None);
            }
        }
        report.masters.push(master_report);
    }

    let mut effective_records = BTreeMap::<CanonicalFormId, IndexedMasterRecord>::new();
    for index in indexes.iter().flatten() {
        for (identity, record) in &index.matching_records {
            effective_records.insert(identity.clone(), record.clone());
        }
    }
    for (form_id, expected_kind, identity) in overrides {
        match effective_records.get(&identity) {
            Some(record) if record.kind == expected_kind => {
                report.resolved_master_override_count += 1;
            }
            Some(record) => {
                report.type_mismatch_override_count += 1;
                report.blockers.push(format!(
                    "master-override-type-mismatch:0x{form_id:08X}:expected-{expected_kind}:found-{}:provider-{}",
                    record.kind, record.provider
                ));
            }
            None => {
                report.unresolved_master_override_count += 1;
                report.blockers.push(format!(
                    "master-override-target-unresolved:0x{form_id:08X}:{expected_kind}:origin-{}",
                    identity.origin
                ));
            }
        }
    }
    finish_worldspace_master_probe(report)
}

pub fn inspect_worldspace_master_probe_input(
    input: &Path,
    candidate_root: Option<&str>,
    game_data_dir: &Path,
) -> Result<(PluginSetReport, WorldspaceMasterProbeReport)> {
    let (_staged, root, scan_mode) = inspect_staged_plugin_input(input, candidate_root)?;
    let mut plugin_set = inspect_plugin_set(&root)?;
    plugin_set.scan_mode = scan_mode.to_owned();
    let probe = worldspace_master_probe_from_staged(&root, &plugin_set, game_data_dir);
    Ok((plugin_set, probe))
}

fn additive_contract_from_staged(
    root: &Path,
    plugin_set: &PluginSetReport,
    game_data_dir: Option<&Path>,
) -> AdditiveContractReport {
    let mut blockers = plugin_set
        .additive_syncmap_v1
        .blockers
        .iter()
        .map(|value| format!("plugin-policy:{value}"))
        .collect::<Vec<_>>();
    let mut warnings = Vec::new();
    let mut sync_map_path = None;
    let mut sync_map_sha256 = None;
    let mut sync_entries = Vec::new();
    let mut validated_master_override_count = 0_usize;
    let mut current_master_checked = false;

    let sync_paths = bounded_tree_paths(root, |path| {
        path.extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("ini"))
            && direct_sync_map_ini(&normalize_relative(path.strip_prefix(root).unwrap_or(path)))
    });
    match sync_paths {
        Ok(paths) if paths.len() == 1 => {
            let path = &paths[0];
            let relative = normalize_relative(path.strip_prefix(root).unwrap_or(path));
            sync_map_path = Some(relative.clone());
            match bounded_file_payload(path, &relative, MAX_PLUGIN_BYTES) {
                Ok(payload) => {
                    sync_map_sha256 = Some(sha256_bytes(&payload));
                    match read_sync_map_bytes(&payload, &relative) {
                        Ok(entries) if entries.is_empty() => {
                            blockers.push("syncmap-has-no-mesh-entries".to_owned());
                        }
                        Ok(entries) => sync_entries = entries,
                        Err(error) => blockers.push(format!("syncmap-parse-failed:{error}")),
                    }
                }
                Err(error) => blockers.push(format!("syncmap-read-failed:{error}")),
            }
        }
        Ok(paths) => blockers.push(format!(
            "requires-exactly-one-syncmap-ini:found-{}",
            paths.len()
        )),
        Err(error) => blockers.push(format!("syncmap-inventory-failed:{error}")),
    }

    let mut sync_ids = HashSet::new();
    for entry in &sync_entries {
        if !sync_ids.insert(entry.local_form_id.to_ascii_lowercase()) {
            blockers.push(format!(
                "duplicate-syncmap-local-form-id:{}",
                entry.local_form_id
            ));
        }
        if let Err(error) = package_to_game_path(&entry.package_path) {
            blockers.push(format!(
                "invalid-syncmap-package-path:{}:{error}",
                entry.local_form_id
            ));
        }
    }

    let plugin_paths = bounded_tree_paths(root, |path| plugin_kind(path).is_some());
    if plugin_set.additive_syncmap_v1.compatible {
        match plugin_paths {
            Ok(paths) if paths.len() == 1 => {
                let relative = normalize_relative(paths[0].strip_prefix(root).unwrap_or(&paths[0]));
                let semantic_result = (|| -> Result<usize> {
                    let payload = bounded_plugin_payload(&paths[0], &relative)?;
                    let plugin = read_plugin_bytes(&payload, &relative)?;
                    let plugin_index = u8::try_from(plugin.masters.len())?;
                    let owned_ids = plugin
                        .records
                        .iter()
                        .filter(|record| (record.form_id >> 24) as u8 == plugin_index)
                        .map(|record| record.form_id)
                        .collect::<HashSet<_>>();
                    for entry in &sync_entries {
                        let local_id =
                            u32::from_str_radix(entry.local_form_id.trim_start_matches("0x"), 16)?;
                        let full_id = ((plugin_index as u32) << 24) | local_id;
                        if !owned_ids.contains(&full_id) {
                            bail!(
                                "SyncMap local FormID {} has no plugin-owned record",
                                entry.local_form_id
                            );
                        }
                    }

                    let game_data_dir = game_data_dir
                        .filter(|path| path.is_dir())
                        .context("current game Data directory is unavailable")?;
                    current_master_checked = true;
                    let overrides = plugin
                        .records
                        .iter()
                        .filter(|record| ((record.form_id >> 24) as u8) < plugin_index)
                        .collect::<Vec<_>>();
                    let target_ids = overrides
                        .iter()
                        .map(|record| record.form_id)
                        .collect::<Vec<_>>();
                    let current =
                        resolve_installed_master_records(&plugin, game_data_dir, &target_ids)?;
                    let mut referenced_master_ids = Vec::new();
                    for record in &overrides {
                        let current_record = current.get(&record.form_id).with_context(|| {
                            format!(
                                "installed master chain has no override target 0x{:08X}",
                                record.form_id
                            )
                        })?;
                        if current_record.record.kind != record.kind {
                            bail!(
                                "master override 0x{:08X} is {}/{} in staged/installed data",
                                record.form_id,
                                record.kind,
                                current_record.record.kind
                            );
                        }
                        let (_, result) =
                            merge_inventory_addition(record, &current_record.record, plugin_index)?;
                        for addition in result
                            .added_inventory_entries
                            .into_iter()
                            .chain(result.preserved_current_master_entries)
                        {
                            let item_form_id = u32::from_str_radix(
                                addition.item_form_id.trim_start_matches("0x"),
                                16,
                            )?;
                            match addition.reference_scope.as_str() {
                                "plugin-owned" if !owned_ids.contains(&item_form_id) => bail!(
                                    "inventory override {} has unresolved plugin-owned reference {}",
                                    result.form_id,
                                    addition.item_form_id
                                ),
                                "current-master" => referenced_master_ids.push(item_form_id),
                                "plugin-owned" => {}
                                _ => bail!("unknown inventory reference scope"),
                            }
                        }
                    }
                    referenced_master_ids.sort_unstable();
                    referenced_master_ids.dedup();
                    resolve_installed_master_records(
                        &plugin,
                        game_data_dir,
                        &referenced_master_ids,
                    )?;
                    Ok(overrides.len())
                })();
                match semantic_result {
                    Ok(count) => validated_master_override_count = count,
                    Err(error) => {
                        let mut detail = format!("{error:#}");
                        if let Some(path) = game_data_dir {
                            detail = detail
                                .replace(path.to_string_lossy().as_ref(), "<current game Data>");
                        }
                        blockers.push(format!("additive-semantic-validation-failed:{detail}"));
                    }
                }
            }
            Ok(paths) => blockers.push(format!(
                "requires-exactly-one-plugin-for-semantic-validation:found-{}",
                paths.len()
            )),
            Err(error) => blockers.push(format!("plugin-inventory-failed:{error}")),
        }
    }
    warnings.push(
        "SyncMap package-to-IoStore resolution is verified by the native update engine before publication"
            .to_owned(),
    );
    blockers.sort();
    blockers.dedup();
    warnings.sort();
    warnings.dedup();
    let compatible = blockers.is_empty();
    AdditiveContractReport {
        api: ADDITIVE_CONTRACT_API.to_owned(),
        status: if compatible { "complete" } else { "blocked" }.to_owned(),
        compatible,
        current_master_checked,
        sync_map_path,
        sync_map_sha256,
        sync_map_entry_count: sync_entries.len(),
        validated_master_override_count,
        blockers,
        warnings,
    }
}

pub fn inspect_additive_contract_input(
    input: &Path,
    candidate_root: Option<&str>,
    game_data_dir: Option<&Path>,
) -> Result<(PluginSetReport, AdditiveContractReport)> {
    let (_staged, root, scan_mode) = inspect_staged_plugin_input(input, candidate_root)?;
    let mut plugin_set = inspect_plugin_set(&root)?;
    plugin_set.scan_mode = scan_mode.to_owned();
    let contract = additive_contract_from_staged(&root, &plugin_set, game_data_dir);
    Ok((plugin_set, contract))
}

pub fn verify_plugin_set_preserved(source_root: &Path, candidate_root: &Path) -> Result<()> {
    let source = inspect_plugin_set(source_root)?;
    let candidate = inspect_plugin_set(candidate_root)?;
    let source_rows = source
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.relative_path.to_ascii_lowercase(),
                artifact.kind.clone(),
                artifact.bytes,
                artifact.sha256.clone(),
            )
        })
        .collect::<Vec<_>>();
    let candidate_rows = candidate
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.relative_path.to_ascii_lowercase(),
                artifact.kind.clone(),
                artifact.bytes,
                artifact.sha256.clone(),
            )
        })
        .collect::<Vec<_>>();
    if source_rows != candidate_rows {
        bail!("candidate plugin set differs in path, kind, size, or SHA-256");
    }
    Ok(())
}

pub fn verify_plugin_set_with_rewritten_esp(
    source_root: &Path,
    candidate_root: &Path,
    rewritten_relative_path: &str,
) -> Result<()> {
    let source = inspect_plugin_set(source_root)?;
    let candidate = inspect_plugin_set(candidate_root)?;
    let source = source
        .artifacts
        .iter()
        .map(|artifact| (artifact.relative_path.to_ascii_lowercase(), artifact))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .artifacts
        .iter()
        .map(|artifact| (artifact.relative_path.to_ascii_lowercase(), artifact))
        .collect::<BTreeMap<_, _>>();
    if source.keys().collect::<Vec<_>>() != candidate.keys().collect::<Vec<_>>() {
        bail!("candidate plugin set differs in paths");
    }
    let rewritten = rewritten_relative_path
        .to_ascii_lowercase()
        .replace('\\', "/");
    for (path, source) in source {
        let candidate = candidate[&path];
        if path == rewritten {
            if source.kind != "esp"
                || candidate.kind != "esp"
                || candidate.parse_status != "parsed"
                || source.master_flag != candidate.master_flag
                || source.light_plugin_flag != candidate.light_plugin_flag
                || source.masters != candidate.masters
                || source.declared_record_count != candidate.declared_record_count
                || source.next_object_id != candidate.next_object_id
                || source.record_type_counts != candidate.record_type_counts
                || source.plugin_owned_record_count != candidate.plugin_owned_record_count
                || source.master_override_record_count != candidate.master_override_record_count
            {
                bail!("rewritten ESP changed plugin structure or identity");
            }
        } else if source.kind != candidate.kind
            || source.bytes != candidate.bytes
            || source.sha256 != candidate.sha256
        {
            bail!("candidate changed a plugin artifact outside the rewritten ESP: {path}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subrecord(kind: &str, data: &[u8]) -> Vec<u8> {
        let mut bytes = kind.as_bytes().to_vec();
        bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    fn plugin_bytes_with_flags(
        masters: &[&str],
        records: &[(&str, u32)],
        next_object_id: u32,
        header_flags: u32,
    ) -> Vec<u8> {
        let mut header_data = Vec::new();
        let mut hedr = 0.8_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&(records.len() as u32).to_le_bytes());
        hedr.extend_from_slice(&next_object_id.to_le_bytes());
        header_data.extend(subrecord("HEDR", &hedr));
        for master in masters {
            let mut name = master.as_bytes().to_vec();
            name.push(0);
            header_data.extend(subrecord("MAST", &name));
            header_data.extend(subrecord("DATA", &[0; 8]));
        }
        let mut bytes = b"TES4".to_vec();
        bytes.extend_from_slice(&(header_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&header_flags.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&header_data);
        for (kind, form_id) in records {
            let data = subrecord("EDID", b"Fixture\0");
            bytes.extend_from_slice(kind.as_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&form_id.to_le_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&data);
        }
        bytes
    }

    fn plugin_bytes(masters: &[&str], records: &[(&str, u32)], next_object_id: u32) -> Vec<u8> {
        plugin_bytes_with_flags(masters, records, next_object_id, 0)
    }

    fn plugin_bytes_with_record_flags(
        masters: &[&str],
        records: &[(&str, u32, u32)],
        next_object_id: u32,
    ) -> Vec<u8> {
        let mut header_data = Vec::new();
        let mut hedr = 1.0_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&(records.len() as u32).to_le_bytes());
        hedr.extend_from_slice(&next_object_id.to_le_bytes());
        header_data.extend(subrecord("HEDR", &hedr));
        for master in masters {
            let mut name = master.as_bytes().to_vec();
            name.push(0);
            header_data.extend(subrecord("MAST", &name));
            header_data.extend(subrecord("DATA", &[0; 8]));
        }
        let mut bytes = b"TES4".to_vec();
        bytes.extend_from_slice(&(header_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&header_data);
        for (kind, form_id, flags) in records {
            let data = subrecord("EDID", b"Fixture\0");
            bytes.extend_from_slice(kind.as_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&flags.to_le_bytes());
            bytes.extend_from_slice(&form_id.to_le_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&data);
        }
        bytes
    }

    fn grouped_plugin_bytes(
        masters: &[&str],
        groups: &[(&str, &[(&str, u32)])],
        next_object_id: u32,
        declared_entry_count: u32,
    ) -> Vec<u8> {
        let mut header_data = Vec::new();
        let mut hedr = 1.0_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&declared_entry_count.to_le_bytes());
        hedr.extend_from_slice(&next_object_id.to_le_bytes());
        header_data.extend(subrecord("HEDR", &hedr));
        for master in masters {
            let mut name = master.as_bytes().to_vec();
            name.push(0);
            header_data.extend(subrecord("MAST", &name));
            header_data.extend(subrecord("DATA", &[0; 8]));
        }

        let mut bytes = b"TES4".to_vec();
        bytes.extend_from_slice(&(header_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&header_data);
        for (label, records) in groups {
            let mut group_payload = Vec::new();
            for (kind, form_id) in *records {
                let data = subrecord("EDID", b"Fixture\0");
                group_payload.extend_from_slice(kind.as_bytes());
                group_payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
                group_payload.extend_from_slice(&0_u32.to_le_bytes());
                group_payload.extend_from_slice(&form_id.to_le_bytes());
                group_payload.extend_from_slice(&0_u32.to_le_bytes());
                group_payload.extend_from_slice(&data);
            }
            bytes.extend_from_slice(b"GRUP");
            bytes.extend_from_slice(&(20_u32 + group_payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(label.as_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&group_payload);
        }
        bytes
    }

    fn write_plugin(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn assert_unrecognized_duplicate(root: &Path, expected_logical_count: usize) {
        let report = inspect_plugin_set(root).unwrap();
        assert_eq!(report.logical_plugin_count, expected_logical_count);
        assert!(report.plugin_mirrors.is_empty());
        assert!(
            report
                .blockers
                .contains(&"case-insensitive-plugin-filename-collision".to_owned())
        );
        assert!(
            report
                .additive_syncmap_v1
                .blockers
                .contains(&"case-insensitive-plugin-filename-collision".to_owned())
        );
    }

    #[test]
    fn accepts_only_the_proven_single_esp_shape_for_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Fixture");
        write_plugin(
            &root,
            r"Content\Dev\ObvData\Data\Fixture.esp",
            &plugin_bytes(&["Oblivion.esm"], &[("STAT", 0x0100_0800)], 0x801),
        );
        let report = inspect_plugin_set(&root).unwrap();
        assert_eq!(report.status, "complete");
        assert!(report.additive_syncmap_v1.compatible);
        assert_eq!(report.artifacts[0].plugin_owned_record_count, 1);
    }

    #[test]
    fn collapses_exact_path_bound_syncmap_esp_mirror_for_dependency_and_policy_analysis() {
        let temp = tempfile::tempdir().unwrap();
        let payload = plugin_bytes(
            &["Oblivion.esm"],
            &[("CELL", 0x0000_1234), ("WEAP", 0x0100_0800)],
            0x801,
        );
        write_plugin(
            temp.path(),
            r"Content\Dev\ObvData\Data\Muramasa.esp",
            &payload,
        );
        write_plugin(
            temp.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Muramasa.esp",
            &payload,
        );
        write_plugin(
            temp.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Muramasa.ini",
            b"[Meshes]\n000800=/Game/Forms/items/weapons/Muramasa.Muramasa",
        );

        let report = inspect_plugin_set(temp.path()).unwrap();
        assert_eq!(report.status, "complete");
        assert_eq!(report.plugin_count, 2);
        assert_eq!(report.logical_plugin_count, 1);
        assert_eq!(report.parsed_plugin_count, 2);
        assert_eq!(report.artifacts.len(), 2);
        assert_eq!(report.plugin_mirrors.len(), 1);
        assert_eq!(
            report.plugin_mirrors[0].canonical_relative_path,
            "Content/Dev/ObvData/Data/Muramasa.esp"
        );
        assert_eq!(
            report.plugin_mirrors[0].mirror_relative_path,
            "Content/Dev/ObvData/Data/SyncMap/Muramasa.esp"
        );
        assert_eq!(
            report.plugin_mirrors[0].sync_map_relative_path,
            "Content/Dev/ObvData/Data/SyncMap/Muramasa.ini"
        );
        assert_eq!(report.dependency_edges.len(), 1);
        assert!(
            !report
                .blockers
                .contains(&"case-insensitive-plugin-filename-collision".to_owned())
        );
        assert!(report.additive_syncmap_v1.blockers.contains(
            &"master-overrides-outside-supported-inventory-records-are-unsupported".to_owned()
        ));
        assert!(
            !report
                .additive_syncmap_v1
                .blockers
                .contains(&"requires-exactly-one-plugin".to_owned())
        );
        assert!(
            !report
                .additive_syncmap_v1
                .blockers
                .contains(&"case-insensitive-plugin-filename-collision".to_owned())
        );
    }

    #[test]
    fn exact_syncmap_esp_mirror_can_enter_the_single_logical_plugin_policy_lane() {
        let temp = tempfile::tempdir().unwrap();
        let payload = plugin_bytes(&["Oblivion.esm"], &[("STAT", 0x0100_0800)], 0x801);
        write_plugin(
            temp.path(),
            r"Content\Dev\ObvData\Data\Fixture.esp",
            &payload,
        );
        write_plugin(
            temp.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.esp",
            &payload,
        );
        write_plugin(
            temp.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.ini",
            b"[Meshes]\n000800=/Game/Fixture.Fixture",
        );

        let report = inspect_plugin_set(temp.path()).unwrap();
        assert_eq!(report.plugin_count, 2);
        assert_eq!(report.logical_plugin_count, 1);
        assert!(report.additive_syncmap_v1.compatible);
    }

    #[test]
    fn leaves_every_non_exact_plugin_duplicate_as_a_collision() {
        let original = plugin_bytes(&["Oblivion.esm"], &[("STAT", 0x0100_0800)], 0x801);
        let changed = plugin_bytes(&["Oblivion.esm"], &[("WEAP", 0x0100_0800)], 0x801);

        let different_bytes = tempfile::tempdir().unwrap();
        write_plugin(
            different_bytes.path(),
            r"Content\Dev\ObvData\Data\Fixture.esp",
            &original,
        );
        write_plugin(
            different_bytes.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.esp",
            &changed,
        );
        write_plugin(
            different_bytes.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.ini",
            b"[Meshes]\n000800=/Game/Fixture.Fixture",
        );
        assert_unrecognized_duplicate(different_bytes.path(), 2);

        let missing_ini = tempfile::tempdir().unwrap();
        write_plugin(
            missing_ini.path(),
            r"Content\Dev\ObvData\Data\Fixture.esp",
            &original,
        );
        write_plugin(
            missing_ini.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.esp",
            &original,
        );
        assert_unrecognized_duplicate(missing_ini.path(), 2);

        let wrong_path = tempfile::tempdir().unwrap();
        write_plugin(
            wrong_path.path(),
            r"Content\Dev\ObvData\Data\Fixture.esp",
            &original,
        );
        write_plugin(
            wrong_path.path(),
            r"Content\Dev\ObvData\Data\Other\Fixture.esp",
            &original,
        );
        write_plugin(
            wrong_path.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.ini",
            b"[Meshes]\n000800=/Game/Fixture.Fixture",
        );
        assert_unrecognized_duplicate(wrong_path.path(), 2);

        let wrong_root = tempfile::tempdir().unwrap();
        write_plugin(
            wrong_root.path(),
            r"Content\Dev\ObvData\Data\Fixture.esp",
            &original,
        );
        write_plugin(
            wrong_root.path(),
            r"Other\Content\Dev\ObvData\Data\SyncMap\Fixture.esp",
            &original,
        );
        write_plugin(
            wrong_root.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.ini",
            b"[Meshes]\n000800=/Game/Fixture.Fixture",
        );
        assert_unrecognized_duplicate(wrong_root.path(), 2);

        let extra_copy = tempfile::tempdir().unwrap();
        for relative in [
            r"Content\Dev\ObvData\Data\Fixture.esp",
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.esp",
            r"Other\Fixture.esp",
        ] {
            write_plugin(extra_copy.path(), relative, &original);
        }
        write_plugin(
            extra_copy.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.ini",
            b"[Meshes]\n000800=/Game/Fixture.Fixture",
        );
        assert_unrecognized_duplicate(extra_copy.path(), 3);

        let esm_pair = tempfile::tempdir().unwrap();
        write_plugin(
            esm_pair.path(),
            r"Content\Dev\ObvData\Data\Fixture.esm",
            &original,
        );
        write_plugin(
            esm_pair.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.esm",
            &original,
        );
        write_plugin(
            esm_pair.path(),
            r"Content\Dev\ObvData\Data\SyncMap\Fixture.ini",
            b"[Meshes]\n000800=/Game/Fixture.Fixture",
        );
        assert_unrecognized_duplicate(esm_pair.path(), 2);
    }

    #[test]
    fn counts_groups_in_hedr_and_only_warns_for_stale_next_object_id() {
        let temp = tempfile::tempdir().unwrap();
        let armor = [
            ("ARMO", 0x0100_08F1),
            ("ARMO", 0x0100_08F2),
            ("ARMO", 0x0100_08F3),
            ("ARMO", 0x0100_08F4),
        ];
        let container = [("CONT", 0x000C_A143)];
        write_plugin(
            temp.path(),
            r"Content\Dev\ObvData\Data\ParryingDaggers_Standalone.esp",
            &grouped_plugin_bytes(
                &["Oblivion.esm"],
                &[("ARMO", &armor), ("CONT", &container)],
                0x803,
                7,
            ),
        );

        let report = inspect_plugin_set(temp.path()).unwrap();
        let artifact = &report.artifacts[0];
        assert_eq!(artifact.declared_record_count, Some(7));
        assert_eq!(artifact.parsed_group_count, 2);
        assert_eq!(artifact.parsed_record_count, 5);
        assert!(artifact.structural_blockers.is_empty());
        assert!(
            artifact
                .warnings
                .iter()
                .any(|warning| warning.contains("nextObjectId"))
        );
        assert!(report.additive_syncmap_v1.compatible);
    }

    #[test]
    fn still_blocks_true_hedr_count_mismatch_and_sub_800_allocator() {
        let temp = tempfile::tempdir().unwrap();
        let records = [("STAT", 0x0100_0800)];
        write_plugin(
            temp.path(),
            r"Mismatch\Content\Dev\ObvData\Data\Mismatch.esp",
            &grouped_plugin_bytes(&["Oblivion.esm"], &[("STAT", &records)], 0x7FF, 3),
        );

        let report = inspect_plugin_set(temp.path()).unwrap();
        let blockers = &report.artifacts[0].structural_blockers;
        assert!(
            blockers
                .contains(&"declared-record-count-does-not-match-records-and-groups".to_owned())
        );
        assert!(blockers.contains(&"next-object-id-below-0x800".to_owned()));
        assert!(report.artifacts[0].warnings.is_empty());
        assert!(!report.additive_syncmap_v1.compatible);
    }

    #[test]
    fn additive_paths_are_anchored_to_the_selected_mod_root() {
        assert!(direct_game_data_plugin(
            "Content/Dev/ObvData/Data/Fixture.esp"
        ));
        assert!(!direct_game_data_plugin(
            "Other/Content/Dev/ObvData/Data/Fixture.esp"
        ));
        assert!(direct_sync_map_ini(
            "Content/Dev/ObvData/Data/SyncMap/Fixture.ini"
        ));
        assert!(direct_sync_map_plugin(
            "Content/Dev/ObvData/Data/SyncMap/Fixture.esp"
        ));
        assert!(!direct_sync_map_plugin(
            "Other/Content/Dev/ObvData/Data/SyncMap/Fixture.esp"
        ));
        assert!(!direct_sync_map_ini("Other/SyncMap/Fixture.ini"));
        assert!(!direct_sync_map_ini(
            "Content/Dev/ObvData/Data/SyncMap/Nested/Fixture.ini"
        ));
    }

    #[test]
    fn blocks_reserved_local_ids_and_esl_from_mutation() {
        let temp = tempfile::tempdir().unwrap();
        write_plugin(
            temp.path(),
            r"Fixture\Content\Dev\ObvData\Data\Low.esp",
            &plugin_bytes(&["Oblivion.esm"], &[("REFR", 0x0100_0001)], 0x802),
        );
        write_plugin(
            temp.path(),
            r"Fixture\Content\Dev\ObvData\Data\Light.esl",
            &plugin_bytes(&["Oblivion.esm"], &[("STAT", 0x0100_0800)], 0x801),
        );
        let report = inspect_plugin_set(temp.path()).unwrap();
        assert!(!report.additive_syncmap_v1.compatible);
        assert!(report.artifacts.iter().any(|artifact| {
            artifact
                .structural_blockers
                .contains(&"plugin-owned-local-form-ids-below-0x800".to_owned())
        }));
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == "esl")
        );
    }

    #[test]
    fn blocks_master_flagged_esp_from_additive_policy() {
        let temp = tempfile::tempdir().unwrap();
        write_plugin(
            temp.path(),
            r"Fixture\Content\Dev\ObvData\Data\MasterNamedEsp.esp",
            &plugin_bytes_with_flags(
                &["Oblivion.esm"],
                &[("STAT", 0x0100_0800)],
                0x801,
                MASTER_FILE,
            ),
        );
        let report = inspect_plugin_set(temp.path()).unwrap();
        assert!(!report.additive_syncmap_v1.compatible);
        assert!(
            report
                .additive_syncmap_v1
                .blockers
                .contains(&"esp-header-declares-master-file".to_owned())
        );
    }

    #[test]
    fn blocks_light_flagged_esp_from_additive_policy() {
        let temp = tempfile::tempdir().unwrap();
        write_plugin(
            temp.path(),
            r"Fixture\Content\Dev\ObvData\Data\LightNamedEsp.esp",
            &plugin_bytes_with_flags(
                &["Oblivion.esm"],
                &[("STAT", 0x0100_0800)],
                0x801,
                LIGHT_PLUGIN,
            ),
        );
        let report = inspect_plugin_set(temp.path()).unwrap();
        assert!(!report.additive_syncmap_v1.compatible);
        assert!(
            report
                .additive_syncmap_v1
                .blockers
                .contains(&"esp-header-declares-light-plugin".to_owned())
        );
    }

    #[test]
    fn detects_same_length_plugin_tampering() {
        let source = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        let original = plugin_bytes(&["Oblivion.esm"], &[("STAT", 0x0100_0800)], 0x801);
        let mut changed = original.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        write_plugin(source.path(), "Data/Fixture.esp", &original);
        write_plugin(candidate.path(), "Data/Fixture.esp", &changed);
        assert!(verify_plugin_set_preserved(source.path(), candidate.path()).is_err());
    }

    #[test]
    fn directory_metadata_snapshot_enforces_per_file_and_total_limits() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("first.esp"), b"1234").unwrap();
        fs::write(source.join("second.ini"), b"56").unwrap();
        let mut selected_bytes = 0;

        copy_bounded_metadata_file(
            &source.join("first.esp"),
            &destination.join("first.esp"),
            Path::new("first.esp"),
            &mut selected_bytes,
            4,
            5,
        )
        .unwrap();
        assert_eq!(selected_bytes, 4);
        assert_eq!(fs::read(destination.join("first.esp")).unwrap(), b"1234");

        assert!(
            copy_bounded_metadata_file(
                &source.join("second.ini"),
                &destination.join("second.ini"),
                Path::new("second.ini"),
                &mut selected_bytes,
                4,
                5,
            )
            .is_err()
        );
        assert_eq!(selected_bytes, 4);
        assert!(!destination.join("second.ini").exists());
    }

    #[test]
    fn worldspace_probe_resolves_multi_master_form_ids_in_load_order() {
        let staged = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let base_records = [("CELL", 0x0000_1234)];
        write_plugin(
            staged.path(),
            r"Content\Dev\ObvData\Data\WorldFixture.esp",
            &plugin_bytes(
                &["base.esm", "PATCH.ESP"],
                &[
                    ("CELL", 0x0000_1234),
                    ("WRLD", 0x0100_2000),
                    ("REFR", 0x0200_0800),
                ],
                0x801,
            ),
        );
        write_plugin(
            data.path(),
            "BASE.ESM",
            &grouped_plugin_bytes(&[], &[("CELL", &base_records)], 0x1235, 2),
        );
        write_plugin(
            data.path(),
            "patch.esp",
            &plugin_bytes(
                &["Base.esm"],
                &[("CELL", 0x0000_1234), ("WRLD", 0x0100_2000)],
                0x2001,
            ),
        );

        let (_plugins, probe) =
            inspect_worldspace_master_probe_input(staged.path(), None, data.path()).unwrap();
        assert_eq!(probe.api, WORLDSPACE_MASTER_PROBE_API);
        assert_eq!(probe.status, "complete-report-only");
        assert!(probe.resolution_complete);
        assert!(!probe.semantic_compatibility_claimed);
        assert_eq!(probe.mutation_policy, "report-only");
        assert_eq!(probe.declared_master_count, 2);
        assert_eq!(probe.found_master_count, 2);
        assert_eq!(probe.parsed_master_count, 2);
        assert_eq!(probe.master_override_count, 2);
        assert_eq!(probe.resolved_master_override_count, 2);
        assert_eq!(probe.unresolved_master_override_count, 0);
        assert_eq!(probe.type_mismatch_override_count, 0);
        assert_eq!(probe.deleted_master_override_count, 0);
        assert!(probe.blockers.is_empty());
    }

    #[test]
    fn worldspace_probe_uses_latest_master_override_and_blocks_type_mismatch() {
        let staged = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        write_plugin(
            staged.path(),
            r"Content\Dev\ObvData\Data\WorldFixture.esp",
            &plugin_bytes(
                &["Base.esm", "Patch.esp"],
                &[("CELL", 0x0000_1234), ("REFR", 0x0200_0800)],
                0x801,
            ),
        );
        write_plugin(
            data.path(),
            "Base.esm",
            &plugin_bytes(&[], &[("CELL", 0x0000_1234)], 0x1235),
        );
        write_plugin(
            data.path(),
            "Patch.esp",
            &plugin_bytes(&["Base.esm"], &[("WRLD", 0x0000_1234)], 0x800),
        );

        let (_plugins, probe) =
            inspect_worldspace_master_probe_input(staged.path(), None, data.path()).unwrap();
        assert!(!probe.resolution_complete);
        assert_eq!(probe.master_override_count, 1);
        assert_eq!(probe.resolved_master_override_count, 0);
        assert_eq!(probe.type_mismatch_override_count, 1);
        assert!(probe.blockers.iter().any(|blocker| {
            blocker.contains(
                "master-override-type-mismatch:0x00001234:expected-CELL:found-WRLD:provider-Patch.esp",
            )
        }));
    }

    #[test]
    fn worldspace_probe_reports_missing_master_and_deleted_override() {
        let staged = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        write_plugin(
            staged.path(),
            r"Content\Dev\ObvData\Data\WorldFixture.esp",
            &plugin_bytes_with_record_flags(
                &["Missing.esm"],
                &[("CELL", 0x0000_1234, DELETED_RECORD)],
                0x800,
            ),
        );

        let (_plugins, probe) =
            inspect_worldspace_master_probe_input(staged.path(), None, data.path()).unwrap();
        assert!(!probe.resolution_complete);
        assert_eq!(probe.found_master_count, 0);
        assert_eq!(probe.parsed_master_count, 0);
        assert_eq!(probe.master_override_count, 1);
        assert_eq!(probe.deleted_master_override_count, 1);
        assert_eq!(probe.unresolved_master_override_count, 1);
        assert!(
            probe
                .blockers
                .contains(&"declared-master-missing:Missing.esm".to_owned())
        );
        assert!(probe.blockers.iter().any(|blocker| {
            blocker == "deleted-master-overrides-require-dedicated-semantic-validation:found-1"
        }));
    }

    #[test]
    fn worldspace_probe_blocks_unmappable_installed_target_collision() {
        let staged = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        write_plugin(
            staged.path(),
            r"Content\Dev\ObvData\Data\WorldFixture.esp",
            &plugin_bytes(
                &["Base.esm"],
                &[("CELL", 0x0000_1234), ("REFR", 0x0100_0800)],
                0x801,
            ),
        );
        write_plugin(
            data.path(),
            "Base.esm",
            &plugin_bytes(&[], &[("CELL", 0x0000_1234), ("WRLD", 0x0100_1234)], 0x1235),
        );

        let (_plugins, probe) =
            inspect_worldspace_master_probe_input(staged.path(), None, data.path()).unwrap();
        assert!(!probe.resolution_complete);
        assert_eq!(probe.parsed_master_count, 1);
        assert_eq!(probe.resolved_master_override_count, 1);
        assert_eq!(probe.masters[0].unmappable_record_count, 1);
        assert_eq!(probe.masters[0].unmappable_target_collision_count, 1);
        assert!(probe.blockers.iter().any(|blocker| {
            blocker
                == "installed-master-unmappable-record-collides-with-target-local-id:Base.esm:0x01001234"
        }));
    }
}
