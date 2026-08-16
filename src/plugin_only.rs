//! Fail-closed conversion lane for plugin-only mods: inputs that carry exactly
//! one TES4 ESP plus optional SyncMap/MagicLoader sidecars and documentation,
//! with no IoStore containers and no scripts. The lane resolves one of three
//! proven physical rootings (canonical wrapper, Place-in-Data, bare root) into
//! the canonical `Content/Dev/ObvData/Data` logical layout, then reuses the
//! existing plugin manifest, installed-master resolution, and per-subrecord
//! three-way current-master semantic gate on that logical view. Every override
//! must resolve by canonical identity; witness-shaped REFR deletion stubs may
//! be rewritten by the guarded update lane through the disclosed
//! undelete-and-disable transform; everything else is byte-preserved. Any
//! ambiguity fails closed with the candidates disclosed.

use crate::archive::extract_archive_files_with_extensions;
use crate::plugin::{
    PluginSetReport, evaluate_worldspace_lane_semantics, inspect_plugin_set,
    resolve_installed_master_records,
};
use crate::tes4::{
    DELETED_RECORD, Plugin, infer_self_slot, package_to_game_path, read_plugin_bytes,
    read_sync_map_bytes,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const PLUGIN_ONLY_ADAPTER: &str = "native-plugin-only-esp-v1";
pub const PLUGIN_ONLY_LANE_API: &str = "tes4-plugin-only-lane-v1";

/// Extensions the lane recognizes as installable payloads. Everything else is
/// either documentation (preserved but never installed) or an unrecognized
/// functional file that fails the lane closed.
pub const PLUGIN_ONLY_INSTALLABLE_EXTENSIONS: &[&str] = &["esp", "esm", "esl", "ini", "json"];
const MAX_PLUGIN_ONLY_SELECTED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PLUGIN_ONLY_ENTRIES: usize = 4096;
const DATA_MARKER: &str = "content/dev/obvdata/data/";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginOnlyMapping {
    /// Exact normalized path inside the selected source.
    pub physical_source: String,
    /// Path relative to the game's `OblivionRemastered` project root.
    pub logical_destination: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginOnlyLayout {
    /// "canonical-wrapper", "data-rooted", or "bare-root".
    pub scheme: String,
    /// The shared physical prefix stripped by the mapping ("" when none).
    pub wrapper: String,
    pub mappings: Vec<PluginOnlyMapping>,
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_owned()
}

fn data_phrase(component: &str) -> bool {
    let folded = component
        .chars()
        .filter(|value| value.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(folded.as_str(), "data" | "placeindata" | "placeindatafolder")
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Anchor {
    /// `<wrapper>/Content/Dev/ObvData/Data/<tail>`
    Canonical { wrapper: String, tail: String },
    /// `<wrapper>/Data/<tail>` (including "Place in Data" spellings)
    DataRooted { wrapper: String, tail: String },
    /// A root-level plugin file with no directory component.
    Bare { file: String },
}

fn anchor_for(path: &str) -> Result<Anchor> {
    let normalized = normalize(path);
    let lower = normalized.to_ascii_lowercase();
    if let Some(index) = if lower.starts_with(DATA_MARKER) {
        Some(0)
    } else {
        lower
            .find(&format!("/{DATA_MARKER}"))
            .map(|value| value + 1)
    } {
        let wrapper = normalized[..index].trim_matches('/').to_owned();
        let tail = normalized[index + DATA_MARKER.len()..].to_owned();
        if tail.is_empty() {
            bail!("path ends at the Data marker: {normalized}");
        }
        return Ok(Anchor::Canonical { wrapper, tail });
    }
    let components = normalized.split('/').collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        if data_phrase(component) && index + 1 < components.len() {
            return Ok(Anchor::DataRooted {
                wrapper: components[..index].join("/"),
                tail: components[index + 1..].join("/"),
            });
        }
    }
    if !normalized.contains('/')
        && Path::new(&normalized)
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("esp"))
    {
        return Ok(Anchor::Bare { file: normalized });
    }
    bail!("file is outside every proven Data-plane rooting: {normalized}");
}

/// Resolves the fail-closed physical-to-logical mapping for a plugin-only
/// input. Every installable file must resolve through exactly one rooting
/// scheme and one shared wrapper; mixed schemes, mixed wrappers, and files
/// outside the Data plane fail closed with the offending paths disclosed.
pub fn resolve_plugin_only_layout(installable: &[String]) -> Result<PluginOnlyLayout> {
    if installable.is_empty() {
        bail!("plugin-only layout has no installable files");
    }
    let anchors = installable
        .iter()
        .map(|path| anchor_for(path).map(|anchor| (normalize(path), anchor)))
        .collect::<Result<Vec<_>>>()?;
    let mut schemes = anchors
        .iter()
        .map(|(_, anchor)| match anchor {
            Anchor::Canonical { wrapper, .. } => ("canonical-wrapper", wrapper.clone()),
            Anchor::DataRooted { wrapper, .. } => ("data-rooted", wrapper.clone()),
            Anchor::Bare { .. } => ("bare-root", String::new()),
        })
        .collect::<Vec<_>>();
    schemes.sort();
    schemes.dedup();
    let [(scheme, wrapper)] = schemes.as_slice() else {
        let candidates = schemes
            .iter()
            .map(|(scheme, wrapper)| {
                if wrapper.is_empty() {
                    (*scheme).to_owned()
                } else {
                    format!("{scheme}:{wrapper}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        bail!("plugin-only rooting is ambiguous across schemes/wrappers: {candidates}");
    };
    let mut mappings = Vec::new();
    let mut seen = HashSet::new();
    for (physical, anchor) in &anchors {
        let logical = match anchor {
            Anchor::Canonical { tail, .. } | Anchor::DataRooted { tail, .. } => {
                format!("Content/Dev/ObvData/Data/{tail}")
            }
            Anchor::Bare { file } => format!("Content/Dev/ObvData/Data/{file}"),
        };
        if logical.split('/').any(|component| {
            component.is_empty() || component == "." || component == ".."
        }) {
            bail!("logical destination is not a safe relative path: {logical}");
        }
        if !seen.insert(logical.to_ascii_lowercase()) {
            bail!("logical destination collision at {logical}");
        }
        mappings.push(PluginOnlyMapping {
            physical_source: physical.clone(),
            logical_destination: logical,
        });
    }
    mappings.sort_by(|a, b| a.logical_destination.cmp(&b.logical_destination));
    Ok(PluginOnlyLayout {
        scheme: (*scheme).to_owned(),
        wrapper: wrapper.clone(),
        mappings,
    })
}

fn installable_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            PLUGIN_ONLY_INSTALLABLE_EXTENSIONS
                .iter()
                .any(|extension| value.eq_ignore_ascii_case(extension))
        })
}

fn stage_installable_files(input: &Path, destination: &Path) -> Result<()> {
    if input.is_file() {
        extract_archive_files_with_extensions(
            input,
            destination,
            PLUGIN_ONLY_INSTALLABLE_EXTENSIONS,
            MAX_PLUGIN_ONLY_SELECTED_BYTES,
        )?;
        return Ok(());
    }
    let mut total = 0_u64;
    for (index, entry) in WalkDir::new(input).follow_links(false).into_iter().enumerate() {
        if index >= MAX_PLUGIN_ONLY_ENTRIES {
            bail!("plugin-only input exceeds the {MAX_PLUGIN_ONLY_ENTRIES} entry safety limit");
        }
        let entry = entry.context("walking the plugin-only input")?;
        if entry.file_type().is_symlink() {
            bail!("plugin-only input contains a filesystem link");
        }
        if !entry.file_type().is_file() || !installable_extension(entry.path()) {
            continue;
        }
        let bytes = entry.metadata()?.len();
        total = total
            .checked_add(bytes)
            .context("plugin-only staging size overflow")?;
        if total > MAX_PLUGIN_ONLY_SELECTED_BYTES {
            bail!("plugin-only input exceeds the bounded staging size");
        }
        let relative = entry.path().strip_prefix(input)?;
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().context("staged file has no parent")?)?;
        fs::copy(entry.path(), &target)?;
    }
    Ok(())
}

fn staged_relative_paths(root: &Path) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            paths.push(normalize(
                &entry.path().strip_prefix(root)?.to_string_lossy(),
            ));
        }
    }
    paths.sort();
    Ok(paths)
}

/// Materializes the logical view of a plugin-only input: installable files are
/// staged, the rooting scheme is resolved fail-closed, and each file is placed
/// at its canonical logical destination inside a temporary root.
pub fn stage_plugin_only_logical_view(
    input: &Path,
) -> Result<(tempfile::TempDir, PathBuf, PluginOnlyLayout)> {
    let staged = tempfile::Builder::new()
        .prefix("obr-plugin-only-")
        .tempdir()?;
    let physical_root = staged.path().join("physical");
    let logical_root = staged.path().join("logical");
    fs::create_dir_all(&physical_root)?;
    fs::create_dir_all(&logical_root)?;
    stage_installable_files(input, &physical_root)?;
    let layout = resolve_plugin_only_layout(&staged_relative_paths(&physical_root)?)?;
    for mapping in &layout.mappings {
        let source = physical_root.join(&mapping.physical_source);
        let target = logical_root.join(&mapping.logical_destination);
        fs::create_dir_all(target.parent().context("logical file has no parent")?)?;
        fs::copy(&source, &target).with_context(|| {
            format!(
                "materializing logical view for {}",
                mapping.physical_source
            )
        })?;
    }
    Ok((staged, logical_root, layout))
}

/// The lane's fail-closed probe result. `blockers` empty means every gate the
/// lane depends on is proven for this input against the selected game.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginOnlyLaneEvaluation {
    pub api: String,
    pub status: String,
    pub layout: Option<PluginOnlyLayout>,
    pub esp_logical_path: Option<String>,
    pub master_override_count: usize,
    pub deletion_stub_count: usize,
    pub sync_map_entry_count: usize,
    pub magic_loader_sidecar_count: usize,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

fn logical_files_with_extension(
    logical_root: &Path,
    directory: &str,
    extension: &str,
) -> Result<Vec<PathBuf>> {
    let root = logical_root.join(directory);
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
        {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

fn essential_policy_blockers(plugin_set: &PluginSetReport) -> Vec<String> {
    let mut blockers = plugin_set.blockers.clone();
    if plugin_set.artifacts.len() != 1 {
        blockers.push("requires-exactly-one-plugin".to_owned());
    }
    if let Some(plugin) = plugin_set
        .artifacts
        .first()
        .filter(|_| plugin_set.artifacts.len() == 1)
    {
        if plugin.kind != "esp" {
            blockers.push("requires-one-full-esp-not-esm-or-esl".to_owned());
        }
        if plugin.master_flag {
            blockers.push("esp-header-declares-master-file".to_owned());
        }
        if plugin.light_plugin_flag {
            blockers.push("esp-header-declares-light-plugin".to_owned());
        }
        if plugin.parse_status != "parsed" {
            blockers.push("esp-could-not-be-parsed".to_owned());
        }
        if plugin.masters.is_empty() || !plugin.masters[0].eq_ignore_ascii_case("Oblivion.esm") {
            blockers.push("requires-oblivion-esm-as-first-master".to_owned());
        }
        blockers.extend(plugin.structural_blockers.iter().cloned());
    }
    blockers.sort();
    blockers.dedup();
    blockers
}

fn read_logical_plugin(logical_root: &Path, relative: &str) -> Result<(Vec<u8>, Plugin)> {
    let path = logical_root.join(relative);
    let bytes = fs::read(&path).with_context(|| format!("reading staged plugin {relative}"))?;
    let plugin = read_plugin_bytes(&bytes, relative)?;
    Ok((bytes, plugin))
}

/// Runs every lane gate for a plugin-only input against the selected game.
/// This probe never mutates anything; the guarded update lane re-derives and
/// re-proves the same evidence before publishing a candidate.
pub fn evaluate_plugin_only_lane(
    input: &Path,
    game_data_dir: Option<&Path>,
) -> PluginOnlyLaneEvaluation {
    let mut evaluation = PluginOnlyLaneEvaluation {
        api: PLUGIN_ONLY_LANE_API.to_owned(),
        status: "blocked".to_owned(),
        layout: None,
        esp_logical_path: None,
        master_override_count: 0,
        deletion_stub_count: 0,
        sync_map_entry_count: 0,
        magic_loader_sidecar_count: 0,
        blockers: Vec::new(),
        warnings: Vec::new(),
    };
    let (_staged, logical_root, layout) = match stage_plugin_only_logical_view(input) {
        Ok(result) => result,
        Err(error) => {
            evaluation
                .blockers
                .push(format!("plugin-only-layout-unresolved:{error:#}"));
            return evaluation;
        }
    };
    evaluation.layout = Some(layout);

    let plugin_set = match inspect_plugin_set(&logical_root) {
        Ok(report) => report,
        Err(_) => {
            evaluation
                .blockers
                .push("plugin-inventory-failed".to_owned());
            return evaluation;
        }
    };
    evaluation
        .blockers
        .extend(essential_policy_blockers(&plugin_set));
    let esp_relative = plugin_set
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "esp" && artifact.parse_status == "parsed")
        .map(|artifact| artifact.relative_path.clone());
    evaluation.esp_logical_path = esp_relative.clone();
    evaluation
        .warnings
        .extend(plugin_set.warnings.iter().cloned());
    if !evaluation.blockers.is_empty() {
        return evaluation;
    }
    let Some(esp_relative) = esp_relative else {
        evaluation
            .blockers
            .push("requires-exactly-one-plugin".to_owned());
        return evaluation;
    };
    let Some(game_data_dir) = game_data_dir.filter(|path| path.is_dir()) else {
        evaluation
            .blockers
            .push("current-game-unavailable".to_owned());
        return evaluation;
    };
    let (esp_bytes, plugin) = match read_logical_plugin(&logical_root, &esp_relative) {
        Ok(result) => result,
        Err(_) => {
            evaluation
                .blockers
                .push("staged-plugin-read-failed".to_owned());
            return evaluation;
        }
    };
    let plugin_index = plugin.masters.len() as u8;
    let Some(owned_index) = infer_self_slot(plugin_index, &plugin.records).self_index() else {
        evaluation
            .blockers
            .push("self-slot-inference-ambiguous".to_owned());
        return evaluation;
    };
    let overrides = plugin
        .records
        .iter()
        .filter(|record| ((record.form_id >> 24) as u8) < plugin_index)
        .collect::<Vec<_>>();
    evaluation.master_override_count = overrides.len();
    evaluation.deletion_stub_count = overrides
        .iter()
        .filter(|record| record.flags & DELETED_RECORD != 0)
        .count();
    if overrides.is_empty() {
        if let Err(error) = resolve_installed_master_records(&plugin, game_data_dir, &[]) {
            evaluation
                .blockers
                .push(format!("declared-master-presence-unresolved:{error:#}"));
        }
    } else {
        match evaluate_worldspace_lane_semantics(&plugin, &esp_bytes, &esp_relative, game_data_dir)
        {
            Ok(lane) => {
                let gate = &lane.semantic_gate;
                if gate.status != "proven" {
                    evaluation
                        .blockers
                        .push("current-master-semantic-gate-blocked".to_owned());
                    evaluation.blockers.extend(gate.blockers.iter().cloned());
                }
                let deletion = &lane.deleted_override_policy;
                match deletion.status.as_str() {
                    "not-applicable" | "provable" => {}
                    _ => {
                        evaluation
                            .blockers
                            .push("deleted-master-record-policy-not-proven".to_owned());
                        evaluation
                            .blockers
                            .extend(deletion.blockers.iter().cloned());
                    }
                }
                evaluation.warnings.extend(gate.warnings.iter().cloned());
                evaluation
                    .warnings
                    .extend(deletion.warnings.iter().cloned());
                evaluation.warnings.push(format!(
                    "{} master override(s) validated through the current-master semantic gate: {} identical, {} authored field(s), {} revert-risk field(s), {} merge-needed field(s), {} deletion stub(s)",
                    gate.evaluated_override_count,
                    gate.identical_override_count,
                    gate.authored_field_change_count,
                    gate.revert_risk_field_count,
                    gate.merge_needed_field_count,
                    deletion.deletion_stub_count,
                ));
            }
            Err(error) => {
                evaluation
                    .blockers
                    .push(format!("semantic-gate-unavailable:{error:#}"));
            }
        }
    }

    // SyncMap sidecar: bind every key to a plugin-owned record; package
    // resolution stays a disclosed runtime requirement in this lane.
    match logical_files_with_extension(&logical_root, "Content/Dev/ObvData/Data/SyncMap", "ini") {
        Ok(sync_files) => match sync_files.as_slice() {
            [] => {}
            [sync_file] => match fs::read(sync_file)
                .map_err(anyhow::Error::from)
                .and_then(|payload| read_sync_map_bytes(&payload, "SyncMap ini"))
            {
                Ok(entries) if entries.is_empty() => {
                    evaluation
                        .blockers
                        .push("syncmap-has-no-mesh-entries".to_owned());
                }
                Ok(entries) => {
                    evaluation.sync_map_entry_count = entries.len();
                    let owned_ids = plugin
                        .records
                        .iter()
                        .filter(|record| (record.form_id >> 24) as u8 == owned_index)
                        .map(|record| record.form_id & 0x00ff_ffff)
                        .collect::<HashSet<_>>();
                    let mut seen = HashSet::new();
                    for entry in &entries {
                        let Ok(local_id) = u32::from_str_radix(
                            entry.local_form_id.trim_start_matches("0x"),
                            16,
                        ) else {
                            evaluation
                                .blockers
                                .push(format!("syncmap-key-not-hexadecimal:{}", entry.key));
                            continue;
                        };
                        if !seen.insert(local_id) {
                            evaluation.blockers.push(format!(
                                "duplicate-syncmap-local-form-id:0x{local_id:06X}"
                            ));
                        }
                        if !owned_ids.contains(&local_id) {
                            evaluation
                                .blockers
                                .push(format!("syncmap-key-not-plugin-owned:0x{local_id:06X}"));
                        }
                        if let Err(error) = package_to_game_path(&entry.package_path) {
                            evaluation.blockers.push(format!(
                                "invalid-syncmap-package-path:{}:{error}",
                                entry.local_form_id
                            ));
                        }
                    }
                    evaluation.warnings.push(
                        "SyncMap package targets are not resolved against IoStore containers by this lane; TesSyncMapInjector resolves them at runtime and the in-game test must cover every mapped form"
                            .to_owned(),
                    );
                }
                Err(error) => {
                    evaluation
                        .blockers
                        .push(format!("syncmap-parse-failed:{error:#}"));
                }
            },
            files => {
                evaluation.blockers.push(format!(
                    "requires-at-most-one-syncmap-ini:found-{}",
                    files.len()
                ));
            }
        },
        Err(_) => {
            evaluation
                .blockers
                .push("syncmap-inventory-failed".to_owned());
        }
    }

    // Any other installable INI/JSON outside its proven sidecar folder is an
    // unrecognized functional payload and fails the lane closed.
    if let Some(layout) = evaluation.layout.as_ref() {
        for mapping in &layout.mappings {
            let logical = mapping.logical_destination.to_ascii_lowercase();
            if logical.ends_with(".ini")
                && !logical.starts_with("content/dev/obvdata/data/syncmap/")
            {
                evaluation.blockers.push(format!(
                    "unrecognized-installable-ini:{}",
                    mapping.logical_destination
                ));
            }
            if logical.ends_with(".json")
                && !logical.starts_with("content/dev/obvdata/data/magicloader/")
            {
                evaluation.blockers.push(format!(
                    "unrecognized-installable-json:{}",
                    mapping.logical_destination
                ));
            }
        }
    }
    match logical_files_with_extension(&logical_root, "Content/Dev/ObvData/Data/MagicLoader", "json")
    {
        Ok(files) => {
            evaluation.magic_loader_sidecar_count = files.len();
            for file in &files {
                match fs::read(file) {
                    Ok(payload) => {
                        if let Err(error) = crate::engine::validate_magic_loader_sidecar(&payload) {
                            evaluation.blockers.push(format!(
                                "magicloader-sidecar-parse-failed:{}:{error:#}",
                                file.file_name().unwrap_or_default().to_string_lossy()
                            ));
                        }
                    }
                    Err(_) => {
                        evaluation
                            .blockers
                            .push("magicloader-sidecar-read-failed".to_owned());
                    }
                }
            }
            if !files.is_empty() {
                evaluation.warnings.push(
                    "MagicLoader JSON sidecars are byte-preserved; the MagicLoader runtime is required and never installed by the updater"
                        .to_owned(),
                );
            }
        }
        Err(_) => {
            evaluation
                .blockers
                .push("magicloader-sidecar-inventory-failed".to_owned());
        }
    }

    evaluation.blockers.sort();
    evaluation.blockers.dedup();
    evaluation.warnings.sort();
    evaluation.warnings.dedup();
    if evaluation.blockers.is_empty() {
        evaluation.status = "proven".to_owned();
    }
    evaluation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout_of(paths: &[&str]) -> Result<PluginOnlyLayout> {
        resolve_plugin_only_layout(
            &paths
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn maps_canonical_wrapper_paths_to_the_data_plane() {
        let layout = layout_of(&[
            "OblivionRemastered/Content/Dev/ObvData/Data/Fixture.esp",
            "OblivionRemastered/Content/Dev/ObvData/Data/SyncMap/Fixture.ini",
            "OblivionRemastered/Content/Dev/ObvData/Data/MagicLoader/Fixture.json",
        ])
        .unwrap();
        assert_eq!(layout.scheme, "canonical-wrapper");
        assert_eq!(layout.wrapper, "OblivionRemastered");
        assert_eq!(layout.mappings.len(), 3);
        assert!(layout.mappings.iter().any(|mapping| {
            mapping.physical_source == "OblivionRemastered/Content/Dev/ObvData/Data/Fixture.esp"
                && mapping.logical_destination == "Content/Dev/ObvData/Data/Fixture.esp"
        }));
    }

    #[test]
    fn maps_data_rooted_paths_to_the_data_plane() {
        let layout = layout_of(&["Data/Fixture.esp", "Data/SyncMap/Fixture.ini"]).unwrap();
        assert_eq!(layout.scheme, "data-rooted");
        assert_eq!(layout.wrapper, "");
        assert!(layout.mappings.iter().any(|mapping| {
            mapping.physical_source == "Data/SyncMap/Fixture.ini"
                && mapping.logical_destination == "Content/Dev/ObvData/Data/SyncMap/Fixture.ini"
        }));
    }

    #[test]
    fn maps_a_bare_root_esp_to_the_data_plane() {
        let layout = layout_of(&["Unbroken Blade.esp"]).unwrap();
        assert_eq!(layout.scheme, "bare-root");
        assert_eq!(
            layout.mappings[0].logical_destination,
            "Content/Dev/ObvData/Data/Unbroken Blade.esp"
        );
    }

    #[test]
    fn fails_closed_on_mixed_rooting_schemes() {
        let error = layout_of(&[
            "Data/Fixture.esp",
            "OblivionRemastered/Content/Dev/ObvData/Data/Other.esp",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous across schemes"));
        assert!(error.to_string().contains("canonical-wrapper"));
        assert!(error.to_string().contains("data-rooted"));
    }

    #[test]
    fn fails_closed_on_files_outside_the_data_plane() {
        let error = layout_of(&[
            "OblivionRemastered/Content/Dev/ObvData/Data/Fixture.esp",
            "OblivionRemastered/Binaries/Win64/SkipMessages/Fixture.ini",
        ])
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside every proven Data-plane rooting")
        );
        assert!(error.to_string().contains("SkipMessages/Fixture.ini"));
    }

    fn subrecord(kind: &str, data: &[u8]) -> Vec<u8> {
        let mut bytes = kind.as_bytes().to_vec();
        bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    fn plugin_bytes(masters: &[&str], records: &[(&str, u32)], next_object_id: u32) -> Vec<u8> {
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
        bytes.extend_from_slice(&[0; 12]);
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

    fn write_file(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn proves_a_wrapper_rooted_plugin_only_mod_with_syncmap_against_a_synthetic_game() {
        let mod_dir = tempfile::tempdir().unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        write_file(
            mod_dir.path(),
            r"OblivionRemastered\Content\Dev\ObvData\Data\Fixture.esp",
            &plugin_bytes(
                &["Oblivion.esm"],
                &[("CELL", 0x0000_4499), ("WEAP", 0x0100_0800)],
                0x801,
            ),
        );
        write_file(
            mod_dir.path(),
            r"OblivionRemastered\Content\Dev\ObvData\Data\SyncMap\Fixture.ini",
            b"[Meshes]\n000800=/Game/Forms/items/weapons/Fixture.Fixture",
        );
        write_file(
            data_dir.path(),
            "Oblivion.esm",
            &plugin_bytes(&[], &[("CELL", 0x0000_4499)], 0x900),
        );

        let evaluation = evaluate_plugin_only_lane(mod_dir.path(), Some(data_dir.path()));
        assert_eq!(
            evaluation.status, "proven",
            "blockers: {:?}",
            evaluation.blockers
        );
        assert_eq!(evaluation.master_override_count, 1);
        assert_eq!(evaluation.sync_map_entry_count, 1);
        assert_eq!(
            evaluation.esp_logical_path.as_deref(),
            Some("Content/Dev/ObvData/Data/Fixture.esp")
        );
    }

    #[test]
    fn blocks_a_plugin_only_mod_whose_override_cannot_resolve() {
        let mod_dir = tempfile::tempdir().unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        write_file(
            mod_dir.path(),
            "Fixture.esp",
            &plugin_bytes(&["Oblivion.esm"], &[("CELL", 0x0000_4499)], 0x801),
        );
        write_file(
            data_dir.path(),
            "Oblivion.esm",
            &plugin_bytes(&[], &[("CELL", 0x0000_9999)], 0x900),
        );

        let evaluation = evaluate_plugin_only_lane(mod_dir.path(), Some(data_dir.path()));
        assert_eq!(evaluation.status, "blocked");
        assert!(
            evaluation
                .blockers
                .iter()
                .any(|blocker| blocker == "current-master-semantic-gate-blocked"),
            "blockers: {:?}",
            evaluation.blockers
        );
    }

    #[test]
    fn fails_closed_on_logical_destination_collisions() {
        let error = layout_of(&[
            "Wrap/Content/Dev/ObvData/Data/Fixture.esp",
            "Wrap/Content/Dev/ObvData/Data/FIXTURE.ESP",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("collision"));
    }
}
