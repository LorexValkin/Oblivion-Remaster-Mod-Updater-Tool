use crate::archive::{MAX_ARCHIVE_ENTRIES, extract_archive_files_with_extensions, sha256_bytes};
use crate::tes4::{
    COMPRESSED_RECORD, DELETED_RECORD, LIGHT_PLUGIN, MASTER_FILE, Plugin,
    container_inventory_form_ids, package_to_game_path, read_plugin_bytes, read_sync_map_bytes,
    read_target_records, validate_container_addition,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const PLUGIN_MANIFEST_API: &str = "tes4-plugin-manifest-v1";
pub const PLUGIN_PRESERVATION_API: &str = "tes4-plugin-byte-preservation-v1";
pub const ADDITIVE_PLUGIN_POLICY: &str = "tes4-additive-syncmap-policy-v1";
const MIN_FULL_PLUGIN_LOCAL_ID: u32 = 0x800;
const MAX_PLUGIN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SELECTED_METADATA_BYTES: u64 = 512 * 1024 * 1024;
const PLUGIN_METADATA_EXTENSIONS: &[&str] = &["esp", "esm", "esl", "ini"];
pub const ADDITIVE_CONTRACT_API: &str = "tes4-syncmap-additive-contract-v1";

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
    pub plugin_count: usize,
    pub parsed_plugin_count: usize,
    pub artifacts: Vec<PluginArtifact>,
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

impl PluginSetReport {
    pub fn unavailable(expected_plugins: usize) -> Self {
        Self {
            api: PLUGIN_MANIFEST_API.to_owned(),
            scan_mode: "unavailable".to_owned(),
            status: "failed".to_owned(),
            manifest_sha256: String::new(),
            plugin_count: expected_plugins,
            parsed_plugin_count: 0,
            artifacts: Vec::new(),
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
        if plugin.masters.len() != 1 || !plugin.masters[0].eq_ignore_ascii_case("Oblivion.esm") {
            blockers.push("requires-one-exact-oblivion-esm-master".to_owned());
        }
        if plugin
            .master_override_type_counts
            .keys()
            .any(|kind| kind != "CONT")
        {
            blockers.push("master-overrides-outside-cont-are-unsupported".to_owned());
        }
        blockers.extend(plugin.structural_blockers.iter().cloned());
    }
    blockers.sort();
    blockers.dedup();
    PluginPolicyEvaluation {
        id: ADDITIVE_PLUGIN_POLICY.to_owned(),
        compatible: blockers.is_empty(),
        mutation_policy: if blockers.is_empty() {
            "byte-preserve-plugin-and-validate-cont-additions".to_owned()
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

pub fn inspect_plugin_set(root: &Path) -> Result<PluginSetReport> {
    let mut paths = Vec::<PathBuf>::new();
    paths.extend(bounded_tree_paths(root, |path| {
        plugin_kind(path).is_some()
    })?);

    let mut artifacts = Vec::new();
    for path in paths {
        let relative_path = normalize_relative(path.strip_prefix(root)?);
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .context("plugin path has no Unicode filename")?
            .to_owned();
        let kind = plugin_kind(&path).context("plugin extension disappeared")?;
        let payload = bounded_plugin_payload(&path, &relative_path)?;
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
    let mut file_names = BTreeMap::<String, Vec<usize>>::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        file_names
            .entry(artifact.file_name.to_ascii_lowercase())
            .or_default()
            .push(index);
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
    if file_names.values().any(|indexes| indexes.len() > 1) {
        blockers.push("case-insensitive-plugin-filename-collision".to_owned());
    }

    let mut dependency_edges = Vec::new();
    let mut unresolved_external_masters = BTreeSet::new();
    let mut adjacency = BTreeMap::<String, BTreeSet<String>>::new();
    for artifact in &artifacts {
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
    let additive_syncmap_v1 = evaluate_additive_policy(&artifacts, &blockers);

    Ok(PluginSetReport {
        api: PLUGIN_MANIFEST_API.to_owned(),
        scan_mode: "staged-tree".to_owned(),
        status: status.to_owned(),
        manifest_sha256: sha256_bytes(manifest_rows.join("\n").as_bytes()),
        plugin_count: artifacts.len(),
        parsed_plugin_count,
        artifacts,
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

fn additive_contract_from_staged(
    root: &Path,
    plugin_set: &PluginSetReport,
    current_esm: Option<&Path>,
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

                    let current_esm = current_esm
                        .filter(|path| path.is_file())
                        .context("current Oblivion.esm is unavailable")?;
                    current_master_checked = true;
                    let overrides = plugin
                        .records
                        .iter()
                        .filter(|record| ((record.form_id >> 24) as u8) < plugin_index)
                        .collect::<Vec<_>>();
                    let mut target_ids = overrides
                        .iter()
                        .map(|record| record.form_id)
                        .collect::<Vec<_>>();
                    for record in &overrides {
                        target_ids.extend(
                            container_inventory_form_ids(record)?
                                .into_iter()
                                .filter(|form_id| ((form_id >> 24) as u8) < plugin_index),
                        );
                    }
                    target_ids.sort_unstable();
                    target_ids.dedup();
                    let current = read_target_records(current_esm, &target_ids)?;
                    for record in &overrides {
                        let current_record = current.get(&record.form_id).with_context(|| {
                            format!(
                                "current Oblivion.esm has no override target 0x{:08X}",
                                record.form_id
                            )
                        })?;
                        let result =
                            validate_container_addition(record, current_record, plugin_index)?;
                        for addition in result.added_inventory_entries {
                            let item_form_id = u32::from_str_radix(
                                addition.item_form_id.trim_start_matches("0x"),
                                16,
                            )?;
                            let resolved = match addition.reference_scope.as_str() {
                                "plugin-owned" => owned_ids.contains(&item_form_id),
                                "current-master" => current.contains_key(&item_form_id),
                                _ => false,
                            };
                            if !resolved {
                                bail!(
                                    "CONT override {} has unresolved {} reference {}",
                                    result.form_id,
                                    addition.reference_scope,
                                    addition.item_form_id
                                );
                            }
                        }
                    }
                    Ok(overrides.len())
                })();
                match semantic_result {
                    Ok(count) => validated_master_override_count = count,
                    Err(error) => {
                        let mut detail = format!("{error:#}");
                        if let Some(path) = current_esm {
                            detail = detail
                                .replace(path.to_string_lossy().as_ref(), "<current Oblivion.esm>");
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
    current_esm: Option<&Path>,
) -> Result<(PluginSetReport, AdditiveContractReport)> {
    let (_staged, root, scan_mode) = inspect_staged_plugin_input(input, candidate_root)?;
    let mut plugin_set = inspect_plugin_set(&root)?;
    plugin_set.scan_mode = scan_mode.to_owned();
    let contract = additive_contract_from_staged(&root, &plugin_set, current_esm);
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
}
