//! A bounded, non-mutating logical install view for one selected mod source.
//!
//! Physical paths always identify files inside the selected source. Logical
//! destinations are game-root-relative and are used only for analysis/planning.

use crate::archive::{copy_tree, sha256_directory, sha256_file};
use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;

pub const INSTALL_PLAN_API: &str = "source-agnostic-install-plan-v1";
pub const LOGICAL_INSTALL_PUBLICATION_API: &str = "logical-install-publication-v1";
pub const LOGICAL_INSTALL_ADAPTER_PREFIX: &str = "logical-install-publication-v1:";
pub const MAX_SOURCE_FILES: usize = 250_000;
pub const MAX_FOMOD_XML_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FOMOD_EVENTS: usize = 100_000;
pub const MAX_FOMOD_DEPTH: usize = 64;
pub const MAX_FOMOD_MAPPINGS: usize = 20_000;
pub const MAX_FOMOD_GROUPS: usize = 512;
pub const MAX_FOMOD_OPTIONS: usize = 4_096;
pub const MAX_MATERIALIZED_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MAX_XML_VALUE_CHARS: usize = 8_192;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayoutEvidence {
    Canonical,
    Fomod,
    ManualStructural,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupBehavior {
    SelectExactlyOne,
    SelectAtMostOne,
    SelectAtLeastOne,
    SelectAny,
    SelectAll,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOption {
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallChoiceGroup {
    pub name: String,
    pub behavior: GroupBehavior,
    pub options: Vec<InstallOption>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MappingScope {
    Required,
    Option { group: usize, option: usize },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallMapping {
    /// Exact, normalized relative path inside the selected source.
    pub physical_source: PathBuf,
    /// Normalized path relative to the game root. It is never joined to disk here.
    pub logical_destination: PathBuf,
    pub priority: i32,
    pub scope: MappingScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallPlan {
    pub api: &'static str,
    pub evidence: LayoutEvidence,
    pub mappings: Vec<InstallMapping>,
    pub choice_groups: Vec<InstallChoiceGroup>,
    /// Source files not selected as install payloads. Callers preserve these physically.
    pub unmapped_sources: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionSelection {
    pub group: usize,
    pub options: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializedFile {
    pub physical_source: PathBuf,
    pub logical_destination: PathBuf,
    pub bytes: u64,
}

/// An automatically cleaned-up analysis tree. The caller can pass [`Self::root`]
/// to existing directory-based probes while retaining the original physical paths
/// in [`Self::files`].
#[derive(Debug)]
pub struct StagedInstallView {
    temporary_directory: TempDir,
    pub files: Vec<MaterializedFile>,
    pub total_bytes: u64,
}

#[derive(Debug)]
pub struct ResolvedStagedInstallView {
    pub plan: InstallPlan,
    pub view: StagedInstallView,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallFileFingerprint {
    pub relative_path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalUpdateMapping {
    pub physical_source: PathBuf,
    pub logical_destination: PathBuf,
    pub source_sha256: String,
    pub adapter_owned: bool,
}

/// Immutable evidence carried from logical materialization through physical
/// publication. Publication never resolves the install mappings a second time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalUpdateContext {
    pub api: &'static str,
    pub original_source_sha256: String,
    pub physical_inventory_sha256: String,
    pub nested_adapter: String,
    pub install_plan: InstallPlan,
    pub selected_mappings: Vec<LogicalUpdateMapping>,
    pub original_inventory: Vec<InstallFileFingerprint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalPublicationVerification {
    pub original_file_count: usize,
    pub mapped_file_count: usize,
    pub changed_mapped_file_count: usize,
    pub pass_through_file_count: usize,
    pub changed_logical_paths: Vec<PathBuf>,
    pub candidate_inventory_sha256: String,
    pub source_staging_immutable: bool,
    pub path_inventory_preserved: bool,
    pub pass_through_hashes_preserved: bool,
    pub mapped_output_hashes_verified: bool,
}

impl StagedInstallView {
    pub fn root(&self) -> &Path {
        self.temporary_directory.path()
    }
}

pub fn logical_install_adapter_id(nested_adapter: &str) -> Result<String> {
    if nested_adapter.is_empty() || nested_adapter.starts_with(LOGICAL_INSTALL_ADAPTER_PREFIX) {
        bail!("logical publication requires one non-wrapper nested adapter identity");
    }
    Ok(format!("{LOGICAL_INSTALL_ADAPTER_PREFIX}{nested_adapter}"))
}

pub fn nested_logical_install_adapter(adapter: &str) -> Option<&str> {
    adapter
        .strip_prefix(LOGICAL_INSTALL_ADAPTER_PREFIX)
        .filter(|nested| !nested.is_empty() && !nested.starts_with(LOGICAL_INSTALL_ADAPTER_PREFIX))
}

/// The first publication slice is deliberately narrower than deterministic
/// materialization. Choice-bearing FOMOD plans remain report-only even when a
/// group currently has only one possible selection.
pub fn supports_logical_install_publication(plan: &InstallPlan) -> bool {
    plan.api == INSTALL_PLAN_API
        && plan.choice_groups.is_empty()
        && !plan.mappings.is_empty()
        && matches!(
            plan.evidence,
            LayoutEvidence::Canonical | LayoutEvidence::ManualStructural
        )
}

fn snapshot_tree(
    root: &Path,
    excluded_paths: &BTreeSet<String>,
) -> Result<Vec<InstallFileFingerprint>> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("reading install tree root {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("install tree root must be a real directory, not a link");
    }
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalizing install tree root {}", root.display()))?;
    let mut files = Vec::new();
    let mut seen = BTreeMap::<String, PathBuf>::new();
    let mut total_bytes = 0_u64;
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.context("walking install publication tree")?;
        let relative = entry.path().strip_prefix(&root)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!(
                "install publication tree contains a filesystem link: {}",
                relative.display()
            );
        }
        if entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            bail!(
                "install publication tree contains a special file: {}",
                relative.display()
            );
        }
        if files.len() >= MAX_SOURCE_FILES {
            bail!("install publication tree exceeds the bounded file count");
        }
        let relative = safe_path(relative.to_string_lossy().as_ref())?;
        let key = path_key(&relative);
        if let Some(previous) = seen.insert(key.clone(), relative.clone()) {
            bail!(
                "install publication paths collide case-insensitively: {} and {}",
                previous.display(),
                relative.display()
            );
        }
        if excluded_paths.contains(&key) {
            continue;
        }
        let bytes = entry.metadata()?.len();
        total_bytes = total_bytes
            .checked_add(bytes)
            .context("install publication byte count overflow")?;
        if total_bytes > MAX_MATERIALIZED_BYTES {
            bail!("install publication tree exceeds {MAX_MATERIALIZED_BYTES} bytes");
        }
        files.push(InstallFileFingerprint {
            relative_path: relative,
            bytes,
            sha256: sha256_file(entry.path())?,
        });
    }
    files.sort_by_key(|file| path_key(&file.relative_path));
    Ok(files)
}

fn fingerprints_by_key(
    files: &[InstallFileFingerprint],
) -> BTreeMap<String, &InstallFileFingerprint> {
    files
        .iter()
        .map(|file| (path_key(&file.relative_path), file))
        .collect()
}

pub fn build_logical_update_context(
    physical_root: &Path,
    resolved: &ResolvedStagedInstallView,
    original_source_sha256: String,
    nested_adapter: &str,
    adapter_owned_logical_destinations: &BTreeSet<PathBuf>,
) -> Result<LogicalUpdateContext> {
    if !supports_logical_install_publication(&resolved.plan) {
        bail!("logical publication supports only choice-free canonical or manual-structural plans");
    }
    logical_install_adapter_id(nested_adapter)?;

    let original_inventory = snapshot_tree(physical_root, &BTreeSet::new())?;
    let original_by_key = fingerprints_by_key(&original_inventory);
    let logical_inventory = snapshot_tree(resolved.view.root(), &BTreeSet::new())?;
    let logical_by_key = fingerprints_by_key(&logical_inventory);
    if logical_inventory.len() != resolved.view.files.len()
        || resolved.view.files.len() != resolved.plan.mappings.len()
    {
        bail!("logical materialization does not match the immutable install plan");
    }

    let owned_keys = adapter_owned_logical_destinations
        .iter()
        .map(|path| safe_path(path.to_string_lossy().as_ref()).map(|path| path_key(&path)))
        .collect::<Result<BTreeSet<_>>>()?;
    if owned_keys.is_empty() {
        bail!("nested adapter owns no selected logical payload");
    }

    let mut selected_mappings = Vec::with_capacity(resolved.plan.mappings.len());
    let mut physical_keys = BTreeSet::new();
    let mut logical_keys = BTreeSet::new();
    for mapping in &resolved.plan.mappings {
        if mapping.scope != MappingScope::Required {
            bail!("logical publication cannot carry option-scoped mappings");
        }
        let physical_key = path_key(&mapping.physical_source);
        let logical_key = path_key(&mapping.logical_destination);
        if !physical_keys.insert(physical_key.clone()) {
            bail!(
                "logical publication requires one destination per physical source: {}",
                mapping.physical_source.display()
            );
        }
        if !logical_keys.insert(logical_key.clone()) {
            bail!(
                "logical publication requires unique logical destinations: {}",
                mapping.logical_destination.display()
            );
        }
        let physical = original_by_key.get(&physical_key).with_context(|| {
            format!(
                "selected physical mapping disappeared: {}",
                mapping.physical_source.display()
            )
        })?;
        let logical = logical_by_key.get(&logical_key).with_context(|| {
            format!(
                "selected logical mapping disappeared: {}",
                mapping.logical_destination.display()
            )
        })?;
        if physical.relative_path != mapping.physical_source
            || logical.relative_path != mapping.logical_destination
            || physical.bytes != logical.bytes
            || physical.sha256 != logical.sha256
        {
            bail!(
                "materialized logical bytes do not match physical source {}",
                mapping.physical_source.display()
            );
        }
        selected_mappings.push(LogicalUpdateMapping {
            physical_source: mapping.physical_source.clone(),
            logical_destination: mapping.logical_destination.clone(),
            source_sha256: physical.sha256.clone(),
            adapter_owned: owned_keys.contains(&logical_key),
        });
    }
    if owned_keys.iter().any(|key| !logical_keys.contains(key)) {
        bail!("nested adapter ownership references a non-selected logical path");
    }

    let expected_unmapped = resolved
        .plan
        .unmapped_sources
        .iter()
        .map(|path| path_key(path))
        .collect::<BTreeSet<_>>();
    let actual_unmapped = original_inventory
        .iter()
        .map(|file| path_key(&file.relative_path))
        .filter(|key| !physical_keys.contains(key))
        .collect::<BTreeSet<_>>();
    if expected_unmapped != actual_unmapped {
        bail!("install plan does not account for the complete physical source inventory");
    }

    Ok(LogicalUpdateContext {
        api: LOGICAL_INSTALL_PUBLICATION_API,
        original_source_sha256,
        physical_inventory_sha256: sha256_directory(physical_root)?,
        nested_adapter: nested_adapter.to_owned(),
        install_plan: resolved.plan.clone(),
        selected_mappings,
        original_inventory,
    })
}

pub fn reconstruct_logical_update_candidate(
    context: &LogicalUpdateContext,
    physical_root: &Path,
    logical_candidate_root: &Path,
    excluded_logical_paths: &[PathBuf],
    output_root: &Path,
) -> Result<LogicalPublicationVerification> {
    if context.api != LOGICAL_INSTALL_PUBLICATION_API
        || !supports_logical_install_publication(&context.install_plan)
    {
        bail!("unsupported or ineligible logical publication context");
    }
    if output_root.exists() {
        bail!(
            "refusing to replace an existing physical candidate: {}",
            output_root.display()
        );
    }
    let current_source = snapshot_tree(physical_root, &BTreeSet::new())?;
    if current_source != context.original_inventory
        || sha256_directory(physical_root)? != context.physical_inventory_sha256
    {
        bail!("physical source staging changed after logical context creation");
    }

    let mut excluded_keys = BTreeSet::new();
    for path in excluded_logical_paths {
        let path = safe_path(path.to_string_lossy().as_ref())?;
        let key = path_key(&path);
        if !excluded_keys.insert(key) {
            bail!(
                "logical candidate exclusion is repeated: {}",
                path.display()
            );
        }
        let excluded = logical_candidate_root.join(&path);
        let metadata = fs::symlink_metadata(&excluded).with_context(|| {
            format!("logical candidate exclusion is absent: {}", path.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "logical candidate exclusion is not a regular file: {}",
                path.display()
            );
        }
    }
    let candidate_inventory = snapshot_tree(logical_candidate_root, &excluded_keys)?;
    let candidate_by_key = fingerprints_by_key(&candidate_inventory);
    if candidate_inventory.len() != context.selected_mappings.len() {
        bail!("nested adapter added or removed logical artifacts");
    }
    let expected_keys = context
        .selected_mappings
        .iter()
        .map(|mapping| path_key(&mapping.logical_destination))
        .collect::<BTreeSet<_>>();
    let candidate_keys = candidate_by_key.keys().cloned().collect::<BTreeSet<_>>();
    if candidate_keys != expected_keys {
        bail!("nested adapter changed the logical path inventory");
    }

    let candidate_root = logical_candidate_root.canonicalize()?;
    let mut changed_logical_paths = Vec::new();
    for mapping in &context.selected_mappings {
        let key = path_key(&mapping.logical_destination);
        let candidate = candidate_by_key
            .get(&key)
            .context("logical candidate mapping disappeared")?;
        if candidate.relative_path != mapping.logical_destination {
            bail!(
                "nested adapter changed logical path spelling: {}",
                mapping.logical_destination.display()
            );
        }
        if candidate.sha256 != mapping.source_sha256 {
            if !mapping.adapter_owned {
                bail!(
                    "nested adapter changed an unowned logical artifact: {}",
                    mapping.logical_destination.display()
                );
            }
            changed_logical_paths.push(mapping.logical_destination.clone());
        }
    }

    copy_tree(physical_root, output_root)?;
    for mapping in &context.selected_mappings {
        let source_relative = safe_path(mapping.logical_destination.to_string_lossy().as_ref())?;
        let source = checked_regular_source(&candidate_root, &source_relative)?;
        let destination_relative = safe_path(mapping.physical_source.to_string_lossy().as_ref())?;
        let destination = output_root.join(&destination_relative);
        let copied = fs::copy(&source, &destination).with_context(|| {
            format!(
                "mapping logical output {} back to physical path {}",
                mapping.logical_destination.display(),
                mapping.physical_source.display()
            )
        })?;
        if copied != fs::metadata(&source)?.len() {
            bail!(
                "short copy while publishing physical path {}",
                mapping.physical_source.display()
            );
        }
    }

    let published_inventory = snapshot_tree(output_root, &BTreeSet::new())?;
    let published_by_key = fingerprints_by_key(&published_inventory);
    let original_by_key = fingerprints_by_key(&context.original_inventory);
    if published_inventory.len() != context.original_inventory.len()
        || published_by_key.keys().ne(original_by_key.keys())
    {
        bail!("physical candidate path inventory changed during reconstruction");
    }
    let mappings_by_physical = context
        .selected_mappings
        .iter()
        .map(|mapping| (path_key(&mapping.physical_source), mapping))
        .collect::<BTreeMap<_, _>>();
    for original in &context.original_inventory {
        let key = path_key(&original.relative_path);
        let published = published_by_key
            .get(&key)
            .context("published physical path disappeared")?;
        if published.relative_path != original.relative_path {
            bail!(
                "physical candidate changed path spelling: {}",
                original.relative_path.display()
            );
        }
        let expected_sha256 = if let Some(mapping) = mappings_by_physical.get(&key) {
            &candidate_by_key
                .get(&path_key(&mapping.logical_destination))
                .context("candidate mapping disappeared during verification")?
                .sha256
        } else {
            &original.sha256
        };
        if &published.sha256 != expected_sha256 {
            bail!(
                "physical candidate hash does not match its approved source for {}",
                original.relative_path.display()
            );
        }
    }
    if snapshot_tree(physical_root, &BTreeSet::new())? != context.original_inventory {
        bail!("physical source staging changed during candidate reconstruction");
    }

    changed_logical_paths.sort_by_key(|path| path_key(path));
    Ok(LogicalPublicationVerification {
        original_file_count: context.original_inventory.len(),
        mapped_file_count: context.selected_mappings.len(),
        changed_mapped_file_count: changed_logical_paths.len(),
        pass_through_file_count: context
            .original_inventory
            .len()
            .saturating_sub(context.selected_mappings.len()),
        changed_logical_paths,
        candidate_inventory_sha256: sha256_directory(output_root)?,
        source_staging_immutable: true,
        path_inventory_preserved: true,
        pass_through_hashes_preserved: true,
        mapped_output_hashes_verified: true,
    })
}

pub fn verify_install_trees_match(expected: &Path, actual: &Path) -> Result<String> {
    let expected_inventory = snapshot_tree(expected, &BTreeSet::new())?;
    let actual_inventory = snapshot_tree(actual, &BTreeSet::new())?;
    if expected_inventory != actual_inventory {
        bail!("published archive does not match the verified physical candidate");
    }
    sha256_directory(actual)
}

#[derive(Clone)]
struct SourceIndex {
    ordered: Vec<PathBuf>,
    by_key: BTreeMap<String, PathBuf>,
}

/// Resolve a logical install layout without reading, extracting, or mutating payloads.
///
/// `source_files` is the complete relative file inventory of the selected directory or
/// archive. `module_config_xml`, when supplied by the caller's bounded metadata reader,
/// is authoritative; it is never discovered outside this source boundary.
pub fn resolve_install_plan(
    source_files: &[PathBuf],
    module_config_xml: Option<&[u8]>,
) -> Result<InstallPlan> {
    let sources = SourceIndex::new(source_files)?;
    if let Some(xml) = module_config_xml {
        return parse_fomod(&sources, xml);
    }
    if let Some(plan) = canonical_plan(&sources)? {
        return Ok(plan);
    }
    manual_plan(&sources)
}

/// Convenience entry point for archive inventories, whose paths are normally
/// supplied by a metadata reader as normalized strings.
pub fn resolve_install_plan_strings(
    source_files: &[String],
    module_config_xml: Option<&[u8]>,
) -> Result<InstallPlan> {
    let paths: Vec<PathBuf> = source_files.iter().map(PathBuf::from).collect();
    resolve_install_plan(&paths, module_config_xml)
}

/// Copy only the selected mappings into a fresh temporary logical install tree.
///
/// The source must already be a bounded, extracted/staged representation of the
/// selected input. Links and special files are rejected. Choice selections are
/// validated against their group behavior before any file is copied. Unmapped
/// documentation and FOMOD metadata are intentionally absent from this view.
pub fn stage_install_view(
    physical_root: &Path,
    plan: &InstallPlan,
    selections: &[OptionSelection],
) -> Result<StagedInstallView> {
    if plan.api != INSTALL_PLAN_API {
        bail!("unsupported install-plan API: {}", plan.api);
    }
    let source_metadata = fs::symlink_metadata(physical_root)
        .with_context(|| format!("reading staged source root {}", physical_root.display()))?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        bail!("staged source root must be a real directory, not a link");
    }
    let physical_root = physical_root.canonicalize().with_context(|| {
        format!(
            "canonicalizing staged source root {}",
            physical_root.display()
        )
    })?;
    for mapping in &plan.mappings {
        safe_path(mapping.physical_source.to_string_lossy().as_ref())?;
        safe_path(mapping.logical_destination.to_string_lossy().as_ref())?;
        if let MappingScope::Option { group, option } = mapping.scope {
            let declared_group = plan
                .choice_groups
                .get(group)
                .with_context(|| format!("mapping references unknown choice group {group}"))?;
            if option >= declared_group.options.len() {
                bail!("mapping references unknown option {option} in choice group {group}");
            }
        }
    }
    let selected_options = validate_selections(&plan.choice_groups, selections)?;
    let selected_mappings: Vec<&InstallMapping> = plan
        .mappings
        .iter()
        .filter(|mapping| match mapping.scope {
            MappingScope::Required => true,
            MappingScope::Option { group, option } => selected_options
                .get(&group)
                .is_some_and(|options| options.contains(&option)),
        })
        .collect();
    if selected_mappings.len() > MAX_FOMOD_MAPPINGS {
        bail!("selected install view exceeds the bounded mapping count");
    }
    let owned_mappings: Vec<InstallMapping> = selected_mappings
        .iter()
        .map(|mapping| (*mapping).clone())
        .collect();
    validate_destination_collisions(&owned_mappings, &plan.choice_groups)?;

    let temporary_directory = tempfile::Builder::new()
        .prefix("obr-logical-install-")
        .tempdir()
        .context("creating temporary logical install view")?;
    let mut files = Vec::with_capacity(selected_mappings.len());
    let mut total_bytes = 0_u64;
    for mapping in selected_mappings {
        let source_relative = safe_path(mapping.physical_source.to_string_lossy().as_ref())?;
        let destination_relative =
            safe_path(mapping.logical_destination.to_string_lossy().as_ref())?;
        let source = checked_regular_source(&physical_root, &source_relative)?;
        let metadata = fs::metadata(&source)
            .with_context(|| format!("reading staged source file {}", source.display()))?;
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .context("materialized byte count overflow")?;
        if total_bytes > MAX_MATERIALIZED_BYTES {
            bail!("logical install view exceeds {MAX_MATERIALIZED_BYTES} bytes");
        }
        let destination = temporary_directory.path().join(&destination_relative);
        if destination.exists() {
            bail!(
                "logical destination already exists: {}",
                destination_relative.display()
            );
        }
        fs::create_dir_all(
            destination
                .parent()
                .context("logical destination has no parent")?,
        )?;
        let copied = fs::copy(&source, &destination).with_context(|| {
            format!(
                "copying {} to logical destination {}",
                source_relative.display(),
                destination_relative.display()
            )
        })?;
        if copied != metadata.len() {
            bail!(
                "short copy for logical destination {}",
                destination_relative.display()
            );
        }
        files.push(MaterializedFile {
            physical_source: source_relative,
            logical_destination: destination_relative,
            bytes: copied,
        });
    }
    Ok(StagedInstallView {
        temporary_directory,
        files,
        total_bytes,
    })
}

/// Resolves and materializes one deterministic install component from an already
/// bounded physical staging tree. Optional or multi-choice FOMODs remain
/// explicit and return an error instead of guessing a user's selection.
pub fn resolve_staged_install_view(physical_root: &Path) -> Result<ResolvedStagedInstallView> {
    let mut files = Vec::new();
    let mut module_configs = Vec::new();
    for entry in WalkDir::new(physical_root).follow_links(false) {
        let entry = entry.context("walking the staged install source")?;
        if entry.file_type().is_symlink() {
            bail!("staged install source contains a filesystem link");
        }
        if !entry.file_type().is_file() {
            continue;
        }
        if files.len() >= MAX_SOURCE_FILES {
            bail!("staged install source exceeds the bounded file count");
        }
        let relative = entry.path().strip_prefix(physical_root)?.to_path_buf();
        if relative
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase()
            .ends_with("fomod/moduleconfig.xml")
        {
            module_configs.push(entry.path().to_path_buf());
        }
        files.push(relative);
    }
    let module_config = match module_configs.as_slice() {
        [] => None,
        [path] => {
            let bytes = fs::metadata(path)?.len();
            if bytes == 0 || bytes > MAX_FOMOD_XML_BYTES as u64 {
                bail!("FOMOD ModuleConfig.xml is empty or exceeds the bounded byte limit");
            }
            Some(fs::read(path)?)
        }
        _ => bail!("staged install source contains multiple FOMOD ModuleConfig.xml files"),
    };
    let plan = resolve_install_plan(&files, module_config.as_deref())?;
    let selections = deterministic_selections(&plan.choice_groups)?;
    let view = stage_install_view(physical_root, &plan, &selections)?;
    Ok(ResolvedStagedInstallView { plan, view })
}

fn deterministic_selections(groups: &[InstallChoiceGroup]) -> Result<Vec<OptionSelection>> {
    groups
        .iter()
        .enumerate()
        .map(|(group, value)| {
            let options = match value.behavior {
                GroupBehavior::SelectExactlyOne | GroupBehavior::SelectAtLeastOne
                    if value.options.len() == 1 =>
                {
                    vec![0]
                }
                GroupBehavior::SelectAll => (0..value.options.len()).collect(),
                GroupBehavior::SelectExactlyOne | GroupBehavior::SelectAtLeastOne => {
                    bail!(
                        "FOMOD choice group {} requires a user selection among {} options",
                        value.name,
                        value.options.len()
                    )
                }
                GroupBehavior::SelectAtMostOne | GroupBehavior::SelectAny => {
                    bail!(
                        "FOMOD choice group {} is optional and requires an explicit user selection",
                        value.name
                    )
                }
            };
            Ok(OptionSelection { group, options })
        })
        .collect()
}

fn validate_selections(
    groups: &[InstallChoiceGroup],
    selections: &[OptionSelection],
) -> Result<BTreeMap<usize, BTreeSet<usize>>> {
    let mut selected = BTreeMap::new();
    for selection in selections {
        let group = groups
            .get(selection.group)
            .with_context(|| format!("unknown FOMOD choice group {}", selection.group))?;
        let options: BTreeSet<usize> = selection.options.iter().copied().collect();
        if options.len() != selection.options.len() {
            bail!("FOMOD choice group {} repeats an option", selection.group);
        }
        if options.iter().any(|option| *option >= group.options.len()) {
            bail!(
                "FOMOD choice group {} selects an unknown option",
                selection.group
            );
        }
        if selected.insert(selection.group, options).is_some() {
            bail!(
                "FOMOD choice group {} is selected more than once",
                selection.group
            );
        }
    }
    for (index, group) in groups.iter().enumerate() {
        let count = selected.get(&index).map_or(0, BTreeSet::len);
        let valid = match group.behavior {
            GroupBehavior::SelectExactlyOne => count == 1,
            GroupBehavior::SelectAtMostOne => count <= 1,
            GroupBehavior::SelectAtLeastOne => count >= 1,
            GroupBehavior::SelectAny => true,
            GroupBehavior::SelectAll => count == group.options.len(),
        };
        if !valid {
            bail!(
                "FOMOD choice group {} has {} selected options, violating {:?}",
                group.name,
                count,
                group.behavior
            );
        }
    }
    Ok(selected)
}

fn checked_regular_source(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for component in relative.components() {
        path.push(component);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("reading staged source path {}", relative.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "staged source path contains a filesystem link: {}",
                relative.display()
            );
        }
    }
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() {
        bail!(
            "staged source mapping is not a regular file: {}",
            relative.display()
        );
    }
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(root) {
        bail!(
            "staged source mapping escapes its source root: {}",
            relative.display()
        );
    }
    Ok(canonical)
}

impl SourceIndex {
    fn new(files: &[PathBuf]) -> Result<Self> {
        if files.is_empty() {
            bail!("the selected source contains no files");
        }
        if files.len() > MAX_SOURCE_FILES {
            bail!("source contains more than {MAX_SOURCE_FILES} files");
        }
        let mut ordered = Vec::with_capacity(files.len());
        let mut by_key = BTreeMap::new();
        for path in files {
            let normalized = safe_path(path.to_string_lossy().as_ref())?;
            let key = path_key(&normalized);
            if let Some(previous) = by_key.insert(key, normalized.clone()) {
                bail!(
                    "source paths collide case-insensitively: {} and {}",
                    previous.display(),
                    normalized.display()
                );
            }
            ordered.push(normalized);
        }
        ordered.sort_by_key(|path| path_key(path));
        Ok(Self { ordered, by_key })
    }

    fn exact(&self, raw: &str) -> Result<PathBuf> {
        let normalized = safe_path(raw)?;
        self.by_key
            .get(&path_key(&normalized))
            .cloned()
            .with_context(|| format!("FOMOD source file is absent: {}", normalized.display()))
    }
}

fn safe_path(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() || raw.chars().any(|c| c == '\0' || c.is_control()) {
        bail!("empty or control-character path is unsafe");
    }
    let raw = raw.replace('\\', "/");
    if raw.starts_with('/') || raw.ends_with('/') || raw.contains("//") {
        bail!("absolute or empty-segment path is unsafe: {raw}");
    }
    let mut parts = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(':') {
            bail!("unsafe relative path component in {raw}");
        }
        if part.ends_with('.') || part.ends_with(' ') {
            bail!("Windows-ambiguous path component in {raw}");
        }
        let device = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let numbered_device = device.len() == 4
            && matches!(&device[..3], "COM" | "LPT")
            && matches!(device.as_bytes()[3], b'1'..=b'9');
        if matches!(device.as_str(), "CON" | "PRN" | "AUX" | "NUL") || numbered_device {
            bail!("reserved Windows path component in {raw}");
        }
        parts.push(part);
    }
    Ok(PathBuf::from(parts.join("/")))
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/").to_lowercase()
}

fn parts(path: &Path) -> Vec<String> {
    path.to_string_lossy()
        .replace('\\', "/")
        .split('/')
        .map(ToOwned::to_owned)
        .collect()
}

fn eq_part(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn make_plan(
    evidence: LayoutEvidence,
    sources: &SourceIndex,
    mut mappings: Vec<InstallMapping>,
    choice_groups: Vec<InstallChoiceGroup>,
) -> Result<InstallPlan> {
    validate_destination_collisions(&mappings, &choice_groups)?;
    mappings.sort_by(|a, b| {
        a.scope
            .cmp(&b.scope)
            .then(a.priority.cmp(&b.priority))
            .then(path_key(&a.logical_destination).cmp(&path_key(&b.logical_destination)))
            .then(path_key(&a.physical_source).cmp(&path_key(&b.physical_source)))
    });
    let mapped: BTreeSet<String> = mappings
        .iter()
        .map(|mapping| path_key(&mapping.physical_source))
        .collect();
    let unmapped_sources = sources
        .ordered
        .iter()
        .filter(|path| !mapped.contains(&path_key(path)))
        .cloned()
        .collect();
    Ok(InstallPlan {
        api: INSTALL_PLAN_API,
        evidence,
        mappings,
        choice_groups,
        unmapped_sources,
    })
}

fn scopes_can_coexist(a: &MappingScope, b: &MappingScope, groups: &[InstallChoiceGroup]) -> bool {
    match (a, b) {
        (MappingScope::Required, _) | (_, MappingScope::Required) => true,
        (
            MappingScope::Option {
                group: ga,
                option: oa,
            },
            MappingScope::Option {
                group: gb,
                option: ob,
            },
        ) if ga == gb && oa != ob => matches!(
            groups[*ga].behavior,
            GroupBehavior::SelectAny | GroupBehavior::SelectAtLeastOne | GroupBehavior::SelectAll
        ),
        _ => true,
    }
}

fn validate_destination_collisions(
    mappings: &[InstallMapping],
    groups: &[InstallChoiceGroup],
) -> Result<()> {
    for (index, left) in mappings.iter().enumerate() {
        for right in &mappings[index + 1..] {
            if !scopes_can_coexist(&left.scope, &right.scope, groups) {
                continue;
            }
            let left_key = path_key(&left.logical_destination);
            let right_key = path_key(&right.logical_destination);
            let exact = left_key == right_key;
            let ancestor = left_key.starts_with(&(right_key.clone() + "/"))
                || right_key.starts_with(&(left_key.clone() + "/"));
            if exact || ancestor {
                bail!(
                    "logical destination collision between {} and {} at {} / {}",
                    left.physical_source.display(),
                    right.physical_source.display(),
                    left.logical_destination.display(),
                    right.logical_destination.display()
                );
            }
        }
    }
    Ok(())
}

fn canonical_plan(sources: &SourceIndex) -> Result<Option<InstallPlan>> {
    let mut roots = BTreeMap::<String, usize>::new();
    for path in &sources.ordered {
        let components = parts(path);
        for (index, part) in components.iter().enumerate() {
            if eq_part(part, "Content") {
                roots.insert(components[..index].join("/").to_lowercase(), index);
            }
        }
    }
    if roots.is_empty() {
        return Ok(None);
    }
    if roots.len() != 1 {
        bail!("multiple canonical Content roots make the install layout ambiguous");
    }
    let (_, content_index) = roots.into_iter().next().expect("one canonical root");
    let mut mappings = Vec::new();
    let mut install_payload_count = 0_usize;
    for path in &sources.ordered {
        let components = parts(path);
        let under_root = components
            .get(content_index)
            .is_some_and(|part| eq_part(part, "Content"));
        if !under_root && likely_install_payload(path) {
            // This can be a manual Data + Content/Paks layout. Do not silently
            // discard the TES half merely because one canonical subtree exists.
            return Ok(None);
        }
        if under_root {
            if likely_install_payload(path) {
                install_payload_count += 1;
            }
            let destination = safe_path(&components[content_index..].join("/"))?;
            mappings.push(InstallMapping {
                physical_source: path.clone(),
                logical_destination: destination,
                priority: 0,
                scope: MappingScope::Required,
            });
        }
    }
    if mappings.is_empty() || install_payload_count == 0 {
        return Ok(None);
    }
    make_plan(LayoutEvidence::Canonical, sources, mappings, Vec::new()).map(Some)
}

fn likely_install_payload(path: &PathBuf) -> bool {
    match extension(path).as_str() {
        "esp" | "esm" | "esl" | "pak" | "ucas" | "utoc" => true,
        "ini" => parts(path).iter().any(|part| eq_part(part, "SyncMap")),
        _ => false,
    }
}

fn attr(reader: &Reader<&[u8]>, start: &BytesStart<'_>, wanted: &[u8]) -> Result<Option<String>> {
    for attribute in start.attributes() {
        let attribute = attribute.context("reading FOMOD XML attribute")?;
        if attribute.key.as_ref().eq_ignore_ascii_case(wanted) {
            let value = attribute
                .decode_and_unescape_value(reader.decoder())
                .context("decoding FOMOD XML attribute")?
                .into_owned();
            if value.chars().count() > MAX_XML_VALUE_CHARS {
                bail!("FOMOD XML attribute exceeds the bounded value length");
            }
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn parse_group_behavior(value: &str) -> Result<GroupBehavior> {
    match value.to_ascii_lowercase().as_str() {
        "selectexactlyone" => Ok(GroupBehavior::SelectExactlyOne),
        "selectatmostone" => Ok(GroupBehavior::SelectAtMostOne),
        "selectatleastone" => Ok(GroupBehavior::SelectAtLeastOne),
        "selectany" => Ok(GroupBehavior::SelectAny),
        "selectall" => Ok(GroupBehavior::SelectAll),
        _ => bail!("unsupported FOMOD group type: {value}"),
    }
}

fn event_name(start: &BytesStart<'_>) -> String {
    String::from_utf8_lossy(start.local_name().as_ref()).to_ascii_lowercase()
}

#[derive(Clone, Debug)]
enum XmlFrame {
    Required,
    Group(usize),
    Option { group: usize, option: usize },
    Other,
}

fn current_scope(stack: &[XmlFrame]) -> Result<MappingScope> {
    if let Some((group, option)) = stack.iter().rev().find_map(|frame| match frame {
        XmlFrame::Option { group, option } => Some((*group, *option)),
        _ => None,
    }) {
        return Ok(MappingScope::Option { group, option });
    }
    if stack
        .iter()
        .any(|frame| matches!(frame, XmlFrame::Required))
    {
        return Ok(MappingScope::Required);
    }
    bail!("FOMOD file mapping is outside required files or a named option")
}

fn fomod_destination(raw: Option<String>, source: &Path) -> Result<PathBuf> {
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .context("FOMOD source has no filename")?;
    let mut raw = raw.unwrap_or_default().trim().replace('\\', "/");
    if raw.is_empty() {
        raw = source_name.to_owned();
    } else if raw.ends_with('/') {
        raw.push_str(source_name);
    }
    let mut destination = safe_path(&raw)?;
    let components = parts(&destination);
    if components.len() > 1
        && eq_part(&components[0], "OblivionRemastered")
        && (eq_part(&components[1], "Content") || eq_part(&components[1], "Binaries"))
    {
        destination = safe_path(&components[1..].join("/"))?;
    } else if eq_part(&components[0], "Data") {
        destination = safe_path(&format!(
            "Content/Dev/ObvData/Data/{}",
            components[1..].join("/")
        ))?;
    } else if !eq_part(&components[0], "Content") && !eq_part(&components[0], "Binaries") {
        // FOMOD destinations are conventionally relative to the game's Data
        // directory. Remastered manifests can opt into another game-root role
        // by naming Content or Binaries explicitly.
        destination = safe_path(&format!(
            "Content/Dev/ObvData/Data/{}",
            components.join("/")
        ))?;
    }
    Ok(destination)
}

fn normalize_fomod_xml(xml: &[u8]) -> Result<Vec<u8>> {
    let utf16_little_endian = xml.starts_with(&[0xff, 0xfe])
        || (xml.len() >= 4 && xml[0] == b'<' && xml[1] == 0 && xml[3] == 0);
    let utf16_big_endian = xml.starts_with(&[0xfe, 0xff])
        || (xml.len() >= 4 && xml[0] == 0 && xml[1] == b'<' && xml[2] == 0);
    if !utf16_little_endian && !utf16_big_endian {
        if xml.contains(&0) {
            bail!("FOMOD XML contains NUL bytes without a recognized UTF-16 encoding");
        }
        std::str::from_utf8(xml).context("FOMOD XML is neither UTF-8 nor recognized UTF-16")?;
        return Ok(xml.to_vec());
    }
    let payload = if xml.starts_with(&[0xff, 0xfe]) || xml.starts_with(&[0xfe, 0xff]) {
        &xml[2..]
    } else {
        xml
    };
    if payload.len() % 2 != 0 {
        bail!("UTF-16 FOMOD XML has an odd byte length");
    }
    let words = payload
        .chunks_exact(2)
        .map(|pair| {
            if utf16_little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    let decoded = String::from_utf16(&words).context("FOMOD XML contains invalid UTF-16")?;
    if decoded.contains('\0') {
        bail!("decoded FOMOD XML contains an embedded NUL character");
    }
    Ok(decoded.trim_start_matches('\u{feff}').as_bytes().to_vec())
}

fn parse_fomod(sources: &SourceIndex, xml: &[u8]) -> Result<InstallPlan> {
    if xml.is_empty() || xml.len() > MAX_FOMOD_XML_BYTES {
        bail!("FOMOD ModuleConfig.xml is empty or exceeds {MAX_FOMOD_XML_BYTES} bytes");
    }
    let normalized_xml = normalize_fomod_xml(xml)?;
    let mut reader = Reader::from_reader(normalized_xml.as_slice());
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;
    let mut stack = Vec::new();
    let mut mappings = Vec::new();
    let mut groups: Vec<InstallChoiceGroup> = Vec::new();
    let mut events = 0_usize;

    loop {
        events += 1;
        if events > MAX_FOMOD_EVENTS {
            bail!("FOMOD XML exceeds the bounded event count");
        }
        match reader
            .read_event()
            .context("parsing FOMOD ModuleConfig.xml")?
        {
            Event::Start(start) => {
                let name = event_name(&start);
                let frame = match name.as_str() {
                    "requiredinstallfiles" => XmlFrame::Required,
                    "moduledependencies"
                    | "conditionalfileinstalls"
                    | "dependencies"
                    | "filedependency"
                    | "flagdependency"
                    | "gamedependency"
                    | "fommdependency"
                    | "visible"
                    | "conditionflags"
                    | "typedescriptor"
                    | "dependencytype" => {
                        bail!(
                            "conditional or type-dependent FOMOD element is not supported by this bounded reader: {name}"
                        )
                    }
                    "group" => {
                        if groups.len() >= MAX_FOMOD_GROUPS {
                            bail!("FOMOD exceeds the bounded choice-group count");
                        }
                        let group_name = attr(&reader, &start, b"name")?
                            .filter(|name| !name.trim().is_empty())
                            .context("FOMOD group has no name")?;
                        let behavior = parse_group_behavior(
                            &attr(&reader, &start, b"type")?.context("FOMOD group has no type")?,
                        )?;
                        let index = groups.len();
                        groups.push(InstallChoiceGroup {
                            name: group_name,
                            behavior,
                            options: Vec::new(),
                        });
                        XmlFrame::Group(index)
                    }
                    "plugin" => {
                        let group = stack
                            .iter()
                            .rev()
                            .find_map(|frame| match frame {
                                XmlFrame::Group(group) => Some(*group),
                                _ => None,
                            })
                            .context("FOMOD plugin option is outside a group")?;
                        let option_name = attr(&reader, &start, b"name")?
                            .filter(|name| !name.trim().is_empty())
                            .context("FOMOD plugin option has no name")?;
                        let option = groups[group].options.len();
                        if groups
                            .iter()
                            .map(|group| group.options.len())
                            .sum::<usize>()
                            >= MAX_FOMOD_OPTIONS
                        {
                            bail!("FOMOD exceeds the bounded option count");
                        }
                        groups[group]
                            .options
                            .push(InstallOption { name: option_name });
                        XmlFrame::Option { group, option }
                    }
                    "file" => {
                        add_fomod_file(&reader, &start, &stack, sources, &mut mappings)?;
                        XmlFrame::Other
                    }
                    "folder" => {
                        bail!("FOMOD folder mappings are not supported by this bounded reader")
                    }
                    _ => XmlFrame::Other,
                };
                stack.push(frame);
                if stack.len() > MAX_FOMOD_DEPTH {
                    bail!("FOMOD XML exceeds the bounded nesting depth");
                }
            }
            Event::Empty(start) => {
                let name = event_name(&start);
                if name == "file" {
                    add_fomod_file(&reader, &start, &stack, sources, &mut mappings)?;
                } else if name == "folder" {
                    bail!("FOMOD folder mappings are not supported by this bounded reader");
                } else if matches!(
                    name.as_str(),
                    "moduledependencies"
                        | "conditionalfileinstalls"
                        | "dependencies"
                        | "filedependency"
                        | "flagdependency"
                        | "gamedependency"
                        | "fommdependency"
                        | "visible"
                        | "conditionflags"
                        | "typedescriptor"
                        | "dependencytype"
                ) {
                    bail!(
                        "conditional or type-dependent FOMOD element is not supported by this bounded reader: {name}"
                    );
                }
            }
            Event::End(_) => {
                stack.pop().context("unexpected FOMOD closing element")?;
            }
            Event::DocType(_) => bail!("FOMOD XML document types are not allowed"),
            Event::Eof => break,
            _ => {}
        }
    }
    if !stack.is_empty() {
        bail!("FOMOD XML ended with unclosed elements");
    }
    if mappings.is_empty() {
        bail!("FOMOD contains no supported file mappings");
    }
    if groups.iter().any(|group| group.options.is_empty()) {
        bail!("FOMOD contains an empty choice group");
    }
    make_plan(LayoutEvidence::Fomod, sources, mappings, groups)
}

fn add_fomod_file(
    reader: &Reader<&[u8]>,
    start: &BytesStart<'_>,
    stack: &[XmlFrame],
    sources: &SourceIndex,
    mappings: &mut Vec<InstallMapping>,
) -> Result<()> {
    if mappings.len() >= MAX_FOMOD_MAPPINGS {
        bail!("FOMOD exceeds the bounded file-mapping count");
    }
    let source_raw = attr(reader, start, b"source")?
        .filter(|source| !source.trim().is_empty())
        .context("FOMOD file mapping has no source")?;
    let physical_source = sources.exact(source_raw.trim())?;
    let logical_destination =
        fomod_destination(attr(reader, start, b"destination")?, &physical_source)?;
    let priority = attr(reader, start, b"priority")?
        .map(|value| value.parse::<i32>().context("invalid FOMOD file priority"))
        .transpose()?
        .unwrap_or(0);
    mappings.push(InstallMapping {
        physical_source,
        logical_destination,
        priority,
        scope: current_scope(stack)?,
    });
    Ok(())
}

#[derive(Clone, Debug)]
struct ManualPath {
    source: PathBuf,
    wrapper: String,
    tail: Vec<String>,
}

fn phrase(part: &str, values: &[&str]) -> bool {
    values.iter().any(|value| part.eq_ignore_ascii_case(value))
}

fn manual_data_path(path: &PathBuf) -> Option<ManualPath> {
    let components = parts(path);
    for (index, part) in components.iter().enumerate() {
        if phrase(part, &["Place in Data", "Place in Data Folder", "Data"])
            && index + 1 < components.len()
        {
            return Some(ManualPath {
                source: path.clone(),
                wrapper: components[..index].join("/").to_lowercase(),
                tail: components[index + 1..].to_vec(),
            });
        }
    }
    None
}

fn manual_paks_path(path: &PathBuf) -> Option<ManualPath> {
    let components = parts(path);
    for (index, part) in components.iter().enumerate() {
        if phrase(
            part,
            &[
                "Place in Paks",
                "Place in Paks Folder",
                "Place in Content Paks Mods",
                "Place in Content Paks Mods Folder",
                "Content Paks Mods",
                "Mods",
            ],
        ) && index + 1 < components.len()
        {
            return Some(ManualPath {
                source: path.clone(),
                wrapper: components[..index].join("/").to_lowercase(),
                tail: components[index + 1..].to_vec(),
            });
        }
        if eq_part(part, "Paks") && index + 1 < components.len() {
            let mut tail_index = index + 1;
            if components
                .get(tail_index)
                .is_some_and(|part| phrase(part, &["~mods", "Mods"]))
            {
                tail_index += 1;
            }
            if tail_index < components.len() {
                let mut wrapper = components[..index].to_vec();
                if wrapper.last().is_some_and(|part| eq_part(part, "Content")) {
                    wrapper.pop();
                }
                return Some(ManualPath {
                    source: path.clone(),
                    wrapper: wrapper.join("/").to_lowercase(),
                    tail: components[tail_index..].to_vec(),
                });
            }
        }
    }
    None
}

fn manual_plan(sources: &SourceIndex) -> Result<InstallPlan> {
    let data_candidates: Vec<ManualPath> = sources
        .ordered
        .iter()
        .filter_map(manual_data_path)
        .collect();
    let pak_candidates: Vec<ManualPath> = sources
        .ordered
        .iter()
        .filter_map(manual_paks_path)
        .filter(|path| matches!(extension(&path.source).as_str(), "pak" | "ucas" | "utoc"))
        .collect();

    let plugins: Vec<&ManualPath> = data_candidates
        .iter()
        .filter(|path| {
            path.tail.len() == 1
                && matches!(extension(&path.source).as_str(), "esp" | "esm" | "esl")
        })
        .collect();
    if plugins.len() != 1 {
        bail!(
            "manual layout requires exactly one structurally anchored plugin; found {}",
            plugins.len()
        );
    }
    let plugin = plugins[0];
    let plugin_stem = plugin
        .source
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("manual plugin has no valid stem")?;
    let sync_maps: Vec<&ManualPath> = data_candidates
        .iter()
        .filter(|path| {
            path.tail.len() == 2
                && eq_part(&path.tail[0], "SyncMap")
                && extension(&path.source) == "ini"
                && path
                    .source
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .is_some_and(|stem| stem.eq_ignore_ascii_case(plugin_stem))
        })
        .collect();
    if sync_maps.len() != 1 {
        bail!(
            "manual layout requires one same-stem SyncMap for the plugin; found {}",
            sync_maps.len()
        );
    }
    let sync_map = sync_maps[0];
    if plugin.wrapper != sync_map.wrapper {
        bail!("plugin and SyncMap do not share one structural wrapper");
    }

    let matching_paks: Vec<&ManualPath> = pak_candidates
        .iter()
        .filter(|path| path.wrapper == plugin.wrapper && path.tail.len() == 1)
        .collect();
    if matching_paks.is_empty() {
        bail!("manual layout has no container siblings under the plugin wrapper");
    }
    let mut triples: BTreeMap<String, BTreeMap<String, &ManualPath>> = BTreeMap::new();
    for path in matching_paks {
        let stem = path
            .source
            .file_stem()
            .and_then(|stem| stem.to_str())
            .context("container file has no valid stem")?
            .to_lowercase();
        let ext = extension(&path.source);
        if triples
            .entry(stem)
            .or_default()
            .insert(ext.clone(), path)
            .is_some()
        {
            bail!("duplicate manual container sibling for extension {ext}");
        }
    }
    if triples.values().any(|files| {
        files.len() != 3
            || !files.contains_key("pak")
            || !files.contains_key("ucas")
            || !files.contains_key("utoc")
    }) {
        bail!("manual container files do not form complete PAK/UCAS/UTOC sibling triples");
    }

    let payload_candidates = data_candidates
        .iter()
        .filter(|candidate| {
            matches!(
                extension(&candidate.source).as_str(),
                "esp" | "esm" | "esl" | "ini"
            )
        })
        .count();
    if payload_candidates != 2 || pak_candidates.len() != triples.len() * 3 {
        bail!("manual layout contains additional or cross-wrapper payload candidates");
    }

    let mut mappings = vec![
        InstallMapping {
            physical_source: plugin.source.clone(),
            logical_destination: safe_path(&format!(
                "Content/Dev/ObvData/Data/{}",
                plugin.tail.join("/")
            ))?,
            priority: 0,
            scope: MappingScope::Required,
        },
        InstallMapping {
            physical_source: sync_map.source.clone(),
            logical_destination: safe_path(&format!(
                "Content/Dev/ObvData/Data/{}",
                sync_map.tail.join("/")
            ))?,
            priority: 0,
            scope: MappingScope::Required,
        },
    ];
    for files in triples.values() {
        for path in files.values() {
            mappings.push(InstallMapping {
                physical_source: path.source.clone(),
                logical_destination: safe_path(&format!(
                    "Content/Paks/~mods/{}",
                    path.tail.join("/")
                ))?,
                priority: 0,
                scope: MappingScope::Required,
            });
        }
    }
    make_plan(
        LayoutEvidence::ManualStructural,
        sources,
        mappings,
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(values: &[&str]) -> Vec<PathBuf> {
        values.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn canonical_wrapper_is_logically_removed_but_physically_preserved() {
        let source = files(&[
            "Wrapper/OblivionRemastered/Content/Dev/ObvData/Data/Example.esp",
            "Wrapper/OblivionRemastered/Content/Dev/ObvData/Data/SyncMap/Example.ini",
            "Wrapper/OblivionRemastered/Content/Paks/~mods/Example.pak",
            "README.txt",
        ]);
        let plan = resolve_install_plan(&source, None).unwrap();
        assert_eq!(plan.evidence, LayoutEvidence::Canonical);
        assert!(supports_logical_install_publication(&plan));
        assert_eq!(plan.mappings.len(), 3);
        assert_eq!(
            plan.mappings[0].physical_source,
            PathBuf::from("Wrapper/OblivionRemastered/Content/Dev/ObvData/Data/Example.esp")
        );
        assert!(plan.mappings.iter().any(|mapping| {
            mapping.logical_destination == Path::new("Content/Dev/ObvData/Data/Example.esp")
        }));
        assert_eq!(plan.unmapped_sources, files(&["README.txt"]));
    }

    #[test]
    fn content_named_documentation_is_not_claimed_as_an_install_root() {
        let source = files(&["Documentation/Content/Readme.txt"]);
        assert!(resolve_install_plan(&source, None).is_err());
    }

    #[test]
    fn infers_place_in_data_and_place_in_paks_as_one_component() {
        let source = files(&[
            "Wrapped/Place in Data/Example.esp",
            "Wrapped/Place in Data/SyncMap/Example.ini",
            "Wrapped/Place in Paks/Example.pak",
            "Wrapped/Place in Paks/Example.ucas",
            "Wrapped/Place in Paks/Example.utoc",
            "Wrapped/readme.md",
        ]);
        let plan = resolve_install_plan(&source, None).unwrap();
        assert_eq!(plan.evidence, LayoutEvidence::ManualStructural);
        assert_eq!(plan.mappings.len(), 5);
        assert!(plan.mappings.iter().any(|mapping| {
            mapping.physical_source == Path::new("Wrapped/Place in Data/Example.esp")
                && mapping.logical_destination == Path::new("Content/Dev/ObvData/Data/Example.esp")
        }));
        assert!(plan.mappings.iter().any(|mapping| {
            mapping.physical_source == Path::new("Wrapped/Place in Paks/Example.utoc")
                && mapping.logical_destination == Path::new("Content/Paks/~mods/Example.utoc")
        }));
    }

    #[test]
    fn infers_content_paks_mods_label_variant() {
        let source = files(&[
            "Wrapped/Data/Example.esm",
            "Wrapped/Data/SyncMap/Example.ini",
            "Wrapped/Content Paks Mods/Example.pak",
            "Wrapped/Content Paks Mods/Example.ucas",
            "Wrapped/Content Paks Mods/Example.utoc",
        ]);
        let plan = resolve_install_plan(&source, None).unwrap();
        assert_eq!(plan.evidence, LayoutEvidence::ManualStructural);
    }

    #[test]
    fn infers_hybrid_data_and_canonical_content_paks_layout() {
        let source = files(&[
            "Wrapped/Data/Example.esp",
            "Wrapped/Data/SyncMap/Example.ini",
            "Wrapped/Content/Paks/~mods/Example.pak",
            "Wrapped/Content/Paks/~mods/Example.ucas",
            "Wrapped/Content/Paks/~mods/Example.utoc",
        ]);
        let plan = resolve_install_plan(&source, None).unwrap();
        assert_eq!(plan.evidence, LayoutEvidence::ManualStructural);
        assert_eq!(plan.mappings.len(), 5);
    }

    #[test]
    fn parses_required_and_mutually_exclusive_fomod_mappings() {
        let source = files(&[
            "fomod/ModuleConfig.xml",
            "payload/base.esp",
            "options/low/asset.pak",
            "options/high/asset.pak",
        ]);
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
          <config>
            <requiredInstallFiles>
              <file source="payload/base.esp" destination="Data/Base.esp" priority="7" />
            </requiredInstallFiles>
            <installSteps><installStep><optionalFileGroups>
              <group name="Quality" type="SelectExactlyOne"><plugins>
                <plugin name="Low"><files>
                  <file source="options/low/asset.pak" destination="Content/Paks/~mods/Asset.pak" />
                </files></plugin>
                <plugin name="High"><files>
                  <file source="options/high/asset.pak" destination="content/paks/~mods/asset.PAK" priority="2" />
                </files></plugin>
              </plugins></group>
            </optionalFileGroups></installStep></installSteps>
          </config>"#;
        let plan = resolve_install_plan(&source, Some(xml)).unwrap();
        assert_eq!(plan.evidence, LayoutEvidence::Fomod);
        assert!(!supports_logical_install_publication(&plan));
        assert_eq!(plan.choice_groups.len(), 1);
        assert_eq!(plan.choice_groups[0].options.len(), 2);
        assert_eq!(plan.mappings.len(), 3);
        assert!(plan.mappings.iter().any(|mapping| {
            mapping.logical_destination == Path::new("Content/Dev/ObvData/Data/Base.esp")
                && mapping.priority == 7
                && mapping.scope == MappingScope::Required
        }));
    }

    #[test]
    fn parses_utf16le_fomod_without_a_bom_or_encoding_declaration() {
        let source = files(&["fomod/ModuleConfig.xml", "payload/base.esp"]);
        let text = r#"<config><requiredInstallFiles><file source="payload/base.esp" destination="Data/Base.esp" /></requiredInstallFiles></config>"#;
        let xml = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let plan = resolve_install_plan(&source, Some(&xml)).unwrap();
        assert_eq!(plan.evidence, LayoutEvidence::Fomod);
        assert_eq!(plan.mappings.len(), 1);
        assert_eq!(
            plan.mappings[0].logical_destination,
            PathBuf::from("Content/Dev/ObvData/Data/Base.esp")
        );
    }

    #[test]
    fn rejects_ambiguous_manual_components_and_incomplete_triples() {
        let ambiguous = files(&[
            "One/Place in Data/A.esp",
            "One/Place in Data/SyncMap/A.ini",
            "Two/Place in Data/B.esp",
            "Two/Place in Data/SyncMap/B.ini",
            "One/Place in Paks/A.pak",
            "One/Place in Paks/A.ucas",
            "One/Place in Paks/A.utoc",
        ]);
        assert!(resolve_install_plan(&ambiguous, None).is_err());

        let incomplete = files(&[
            "Place in Data/A.esp",
            "Place in Data/SyncMap/A.ini",
            "Place in Paks/A.pak",
            "Place in Paks/A.utoc",
        ]);
        let error = resolve_install_plan(&incomplete, None).unwrap_err();
        assert!(error.to_string().contains("complete PAK/UCAS/UTOC"));
    }

    #[test]
    fn rejects_hostile_and_case_colliding_source_paths() {
        for hostile in [
            "../A.esp",
            "/absolute/A.esp",
            "C:\\mods\\A.esp",
            "safe/CON.txt",
        ] {
            assert!(resolve_install_plan(&files(&[hostile]), None).is_err());
        }
        assert!(resolve_install_plan(&files(&["Data/A.esp", "data/a.ESP"]), None).is_err());
    }

    #[test]
    fn rejects_hostile_fomod_destination_and_required_collision() {
        let source = files(&["a.bin", "b.bin"]);
        let traversal = br#"<config><requiredInstallFiles>
            <file source="a.bin" destination="../escape.bin" />
          </requiredInstallFiles></config>"#;
        assert!(resolve_install_plan(&source, Some(traversal)).is_err());

        let collision = br#"<config><requiredInstallFiles>
            <file source="a.bin" destination="Content/Paks/A.bin" />
            <file source="b.bin" destination="content/paks/a.BIN" />
          </requiredInstallFiles></config>"#;
        let error = resolve_install_plan(&source, Some(collision)).unwrap_err();
        assert!(error.to_string().contains("destination collision"));

        let ancestor_collision = br#"<config><requiredInstallFiles>
            <file source="a.bin" destination="Content/Paks/A.bin" />
            <file source="b.bin" destination="content/paks/a.bin/child" />
          </requiredInstallFiles></config>"#;
        assert!(resolve_install_plan(&source, Some(ancestor_collision)).is_err());
    }

    #[test]
    fn rejects_condition_bearing_fomods_until_conditions_are_modeled() {
        let source = files(&["fomod/ModuleConfig.xml", "payload/base.esp"]);
        let module_dependency = br#"<config>
          <moduleDependencies operator="And">
            <fileDependency file="Required.esp" state="Active" />
          </moduleDependencies>
          <requiredInstallFiles>
            <file source="payload/base.esp" destination="Data/Base.esp" />
          </requiredInstallFiles>
        </config>"#;
        assert!(resolve_install_plan(&source, Some(module_dependency)).is_err());

        let typed_option = br#"<config><installSteps><installStep><optionalFileGroups>
          <group name="Choice" type="SelectAny"><plugins>
            <plugin name="Optional"><files>
              <file source="payload/base.esp" destination="Data/Base.esp" />
            </files><typeDescriptor><type name="Optional" /></typeDescriptor></plugin>
          </plugins></group>
        </optionalFileGroups></installStep></installSteps></config>"#;
        assert!(resolve_install_plan(&source, Some(typed_option)).is_err());
    }

    #[test]
    fn string_inventory_and_selected_fomod_view_are_copy_only() {
        let temporary = tempfile::tempdir().unwrap();
        for (path, contents) in [
            ("fomod/ModuleConfig.xml", b"metadata".as_slice()),
            ("payload/base.esp", b"plugin".as_slice()),
            ("options/low/asset.pak", b"low".as_slice()),
            ("options/high/asset.pak", b"high".as_slice()),
            ("docs/readme.txt", b"documentation".as_slice()),
        ] {
            let target = temporary.path().join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, contents).unwrap();
        }
        let inventory: Vec<String> = [
            "fomod/ModuleConfig.xml",
            "payload/base.esp",
            "options/low/asset.pak",
            "options/high/asset.pak",
            "docs/readme.txt",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
        let xml = br#"<config>
          <requiredInstallFiles>
            <file source="payload/base.esp" destination="Base.esp" />
          </requiredInstallFiles>
          <installSteps><installStep><optionalFileGroups>
            <group name="Quality" type="SelectExactlyOne"><plugins>
              <plugin name="Low"><files>
                <file source="options/low/asset.pak" destination="Content/Paks/~mods/Asset.pak" />
              </files></plugin>
              <plugin name="High"><files>
                <file source="options/high/asset.pak" destination="Content/Paks/~mods/Asset.pak" />
              </files></plugin>
            </plugins></group>
          </optionalFileGroups></installStep></installSteps>
        </config>"#;
        let plan = resolve_install_plan_strings(&inventory, Some(xml)).unwrap();
        let view = stage_install_view(
            temporary.path(),
            &plan,
            &[OptionSelection {
                group: 0,
                options: vec![1],
            }],
        )
        .unwrap();

        assert_eq!(view.files.len(), 2);
        assert_eq!(view.total_bytes, 10);
        assert_eq!(
            fs::read(view.root().join("Content/Dev/ObvData/Data/Base.esp")).unwrap(),
            b"plugin"
        );
        assert_eq!(
            fs::read(view.root().join("Content/Paks/~mods/Asset.pak")).unwrap(),
            b"high"
        );
        assert!(!view.root().join("fomod/ModuleConfig.xml").exists());
        assert!(!view.root().join("docs/readme.txt").exists());
        assert_eq!(
            fs::read(temporary.path().join("options/high/asset.pak")).unwrap(),
            b"high"
        );
    }

    #[test]
    fn materializer_rejects_missing_required_option_selection() {
        let source = files(&["choice/a.bin"]);
        let xml = br#"<config><installSteps><installStep><optionalFileGroups>
          <group name="Choice" type="SelectExactlyOne"><plugins>
            <plugin name="A"><files>
              <file source="choice/a.bin" destination="Data/a.bin" />
            </files></plugin>
          </plugins></group>
        </optionalFileGroups></installStep></installSteps></config>"#;
        let plan = resolve_install_plan(&source, Some(xml)).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir_all(temporary.path().join("choice")).unwrap();
        fs::write(temporary.path().join("choice/a.bin"), b"a").unwrap();
        let error = stage_install_view(temporary.path(), &plan, &[]).unwrap_err();
        assert!(error.to_string().contains("violating SelectExactlyOne"));
    }

    #[test]
    fn deterministic_selection_accepts_one_required_choice_and_rejects_optional_guessing() {
        assert_eq!(
            deterministic_selections(&[InstallChoiceGroup {
                name: "Main".to_owned(),
                behavior: GroupBehavior::SelectExactlyOne,
                options: vec![InstallOption {
                    name: "Install".to_owned(),
                }],
            }])
            .unwrap()[0]
                .options,
            vec![0]
        );
        assert!(
            deterministic_selections(&[InstallChoiceGroup {
                name: "Optional".to_owned(),
                behavior: GroupBehavior::SelectAny,
                options: vec![InstallOption {
                    name: "Extra".to_owned(),
                }],
            }])
            .is_err()
        );
    }

    fn write_fixture_tree(root: &Path, rows: &[(&str, &[u8])]) {
        for (path, bytes) in rows {
            let target = root.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, bytes).unwrap();
        }
    }

    fn container_ownership(plan: &InstallPlan) -> BTreeSet<PathBuf> {
        plan.mappings
            .iter()
            .filter(|mapping| {
                let path = mapping
                    .logical_destination
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_ascii_lowercase();
                path.starts_with("content/paks/~mods/")
                    && matches!(
                        extension(&mapping.logical_destination).as_str(),
                        "pak" | "ucas" | "utoc"
                    )
            })
            .map(|mapping| mapping.logical_destination.clone())
            .collect()
    }

    fn exercise_physical_publication(rows: &[(&str, &[u8])], physical_utoc: &str) {
        let temporary = tempfile::tempdir().unwrap();
        let physical = temporary.path().join("physical");
        write_fixture_tree(&physical, rows);
        let source_sha256 = sha256_directory(&physical).unwrap();
        let resolved = resolve_staged_install_view(&physical).unwrap();
        let owned = container_ownership(&resolved.plan);
        let context = build_logical_update_context(
            &physical,
            &resolved,
            source_sha256.clone(),
            "native-additive-syncmap-v1",
            &owned,
        )
        .unwrap();

        let logical_candidate = temporary.path().join("logical-candidate");
        copy_tree(resolved.view.root(), &logical_candidate).unwrap();
        let logical_utoc = context
            .selected_mappings
            .iter()
            .find(|mapping| extension(&mapping.logical_destination) == "utoc")
            .unwrap()
            .logical_destination
            .clone();
        fs::write(logical_candidate.join(&logical_utoc), b"rebuilt-utoc").unwrap();
        fs::write(
            logical_candidate.join("nested-adapter-report.json"),
            b"report",
        )
        .unwrap();

        let output = temporary.path().join("physical-candidate");
        let verification = reconstruct_logical_update_candidate(
            &context,
            &physical,
            &logical_candidate,
            &[PathBuf::from("nested-adapter-report.json")],
            &output,
        )
        .unwrap();

        assert_eq!(verification.original_file_count, rows.len());
        assert_eq!(verification.changed_mapped_file_count, 1);
        assert!(verification.path_inventory_preserved);
        assert_eq!(
            fs::read(output.join(physical_utoc)).unwrap(),
            b"rebuilt-utoc"
        );
        assert_eq!(
            fs::read(output.join("docs/readme.txt")).unwrap(),
            b"documentation"
        );
        assert!(!output.join("nested-adapter-report.json").exists());
        assert_eq!(sha256_directory(&physical).unwrap(), source_sha256);
    }

    #[test]
    fn canonical_wrapper_publication_preserves_physical_paths_and_pass_through_bytes() {
        exercise_physical_publication(
            &[
                (
                    "Wrapper/OblivionRemastered/Content/Dev/ObvData/Data/Fixture.esp",
                    b"plugin",
                ),
                (
                    "Wrapper/OblivionRemastered/Content/Dev/ObvData/Data/SyncMap/Fixture.ini",
                    b"sync-map",
                ),
                (
                    "Wrapper/OblivionRemastered/Content/Paks/~mods/Fixture.pak",
                    b"pak",
                ),
                (
                    "Wrapper/OblivionRemastered/Content/Paks/~mods/Fixture.ucas",
                    b"ucas",
                ),
                (
                    "Wrapper/OblivionRemastered/Content/Paks/~mods/Fixture.utoc",
                    b"utoc",
                ),
                ("docs/readme.txt", b"documentation"),
            ],
            "Wrapper/OblivionRemastered/Content/Paks/~mods/Fixture.utoc",
        );
    }

    #[test]
    fn manual_structural_publication_preserves_place_in_layout() {
        exercise_physical_publication(
            &[
                ("Wrapped/Place in Data/Fixture.esp", b"plugin"),
                ("Wrapped/Place in Data/SyncMap/Fixture.ini", b"sync-map"),
                ("Wrapped/Place in Paks/Fixture.pak", b"pak"),
                ("Wrapped/Place in Paks/Fixture.ucas", b"ucas"),
                ("Wrapped/Place in Paks/Fixture.utoc", b"utoc"),
                ("docs/readme.txt", b"documentation"),
            ],
            "Wrapped/Place in Paks/Fixture.utoc",
        );
    }

    #[test]
    fn publication_rejects_unowned_changes_and_added_artifacts() {
        let temporary = tempfile::tempdir().unwrap();
        let physical = temporary.path().join("physical");
        write_fixture_tree(
            &physical,
            &[
                (
                    "Wrapper/OblivionRemastered/Content/Dev/ObvData/Data/Fixture.esp",
                    b"plugin",
                ),
                (
                    "Wrapper/OblivionRemastered/Content/Dev/ObvData/Data/SyncMap/Fixture.ini",
                    b"sync-map",
                ),
                (
                    "Wrapper/OblivionRemastered/Content/Paks/~mods/Fixture.pak",
                    b"pak",
                ),
                (
                    "Wrapper/OblivionRemastered/Content/Paks/~mods/Fixture.ucas",
                    b"ucas",
                ),
                (
                    "Wrapper/OblivionRemastered/Content/Paks/~mods/Fixture.utoc",
                    b"utoc",
                ),
            ],
        );
        let resolved = resolve_staged_install_view(&physical).unwrap();
        let context = build_logical_update_context(
            &physical,
            &resolved,
            sha256_directory(&physical).unwrap(),
            "native-additive-syncmap-v1",
            &container_ownership(&resolved.plan),
        )
        .unwrap();

        let changed = temporary.path().join("changed");
        copy_tree(resolved.view.root(), &changed).unwrap();
        fs::write(
            changed.join("Content/Dev/ObvData/Data/Fixture.esp"),
            b"mutated-plugin",
        )
        .unwrap();
        let error = reconstruct_logical_update_candidate(
            &context,
            &physical,
            &changed,
            &[],
            &temporary.path().join("rejected-unowned"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unowned logical artifact"));

        let added = temporary.path().join("added");
        copy_tree(resolved.view.root(), &added).unwrap();
        fs::write(added.join("unexpected.bin"), b"unexpected").unwrap();
        let error = reconstruct_logical_update_candidate(
            &context,
            &physical,
            &added,
            &[],
            &temporary.path().join("rejected-added"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("added or removed logical artifacts")
        );
    }
}
