use crate::archive::{
    MAX_ARCHIVE_ENTRIES, extract_archive_files_with_extensions_bounded, sha256_bytes, sha256_file,
};
use crate::game::normalize_install_root;
use crate::retoc::{PackageStoreEntry, RetocTool};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;

pub const LAYERED_IOSTORE_DEPENDENCY_API: &str = "zen-layered-iostore-dependency-resolver-v1";
const MAX_STAGED_IOSTORE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_PROVIDER_COUNT: usize = 256;
const MAX_PACKAGE_COUNT: usize = 1_000_000;
const MAX_DEPENDENCY_EDGE_COUNT: usize = 2_000_000;
const MAX_COLLISION_COUNT: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageProviderLayer {
    SelectedMod,
    ConnectedDependency,
    InstalledActiveMod,
    GameContainer,
    StockMain,
}

impl PackageProviderLayer {
    pub fn precedence(self) -> usize {
        match self {
            Self::SelectedMod => 0,
            Self::ConnectedDependency => 1,
            Self::InstalledActiveMod => 2,
            Self::GameContainer => 3,
            Self::StockMain => 4,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayeredContainerInput {
    pub relative_utoc: String,
    pub utoc_bytes: u64,
    pub utoc_sha256: String,
    pub pak_present: bool,
    pub packages: Vec<PackageStoreEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayeredPackageProviderInput {
    pub layer: PackageProviderLayer,
    pub provider_id: String,
    pub containers: Vec<LayeredContainerInput>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayeredContainerReport {
    pub relative_utoc: String,
    pub utoc_bytes: u64,
    pub utoc_sha256: String,
    pub pak_present: bool,
    pub package_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayeredProviderReport {
    pub layer: PackageProviderLayer,
    pub precedence: usize,
    pub provider_id: String,
    pub container_count: usize,
    pub package_count: usize,
    pub containers: Vec<LayeredContainerReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayeredLayerSummary {
    pub layer: PackageProviderLayer,
    pub precedence: usize,
    pub provider_count: usize,
    pub container_count: usize,
    pub package_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayeredPackageLocation {
    pub layer: PackageProviderLayer,
    pub precedence: usize,
    pub provider_id: String,
    pub container: String,
    pub package_id: u64,
    pub package_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayeredDependencyEdge {
    pub source: LayeredPackageLocation,
    pub dependency_package_id: u64,
    pub resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<LayeredPackageLocation>,
    pub shadowed_candidate_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossLayerPackageCollision {
    pub higher_priority: LayeredPackageLocation,
    pub lower_priority: LayeredPackageLocation,
    pub package_id_collision: bool,
    pub package_path_collision: bool,
    pub exact_identity: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayeredIoStoreDependencyReport {
    pub api: String,
    pub status: String,
    pub mutation_policy: String,
    pub resolution_complete: bool,
    /// SHA-256 of this report with this field set to the empty string.
    pub logical_sha256: String,
    pub provider_count: usize,
    pub container_count: usize,
    pub total_package_count: usize,
    pub reachable_package_count: usize,
    pub dependency_edge_count: usize,
    pub resolved_edge_count: usize,
    pub unresolved_edge_count: usize,
    pub cross_layer_collision_count: usize,
    pub excluded_installed_selected_source_count: usize,
    pub excluded_non_iostore_dependency_source_count: usize,
    pub excluded_incomplete_container_count: usize,
    pub layers: Vec<LayeredLayerSummary>,
    pub providers: Vec<LayeredProviderReport>,
    pub dependency_edges: Vec<LayeredDependencyEdge>,
    pub cross_layer_collisions: Vec<CrossLayerPackageCollision>,
    pub excluded_installed_selected_sources: Vec<String>,
    pub excluded_non_iostore_dependency_sources: Vec<String>,
    pub excluded_incomplete_containers: Vec<String>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InternalPackage {
    location: LayeredPackageLocation,
    imported_package_ids: Vec<u64>,
}

#[derive(Default)]
struct CollisionFlags {
    package_id: bool,
    package_path: bool,
}

fn validate_label(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(|character| character.is_control())
    {
        bail!("{label} is empty, too long, or contains control characters");
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn normalized_relative_path(value: &str, label: &str) -> Result<String> {
    if value.is_empty() || value.contains('\0') || value.contains(':') {
        bail!("{label} is not a safe relative path");
    }
    let replaced = value.replace('\\', "/");
    let path = Path::new(&replaced);
    if path.is_absolute() {
        bail!("{label} is not a safe relative path");
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .with_context(|| format!("{label} is not Unicode"))?,
            ),
            Component::CurDir => {}
            _ => bail!("{label} contains traversal or an absolute prefix"),
        }
    }
    if parts.is_empty() {
        bail!("{label} is empty after normalization");
    }
    Ok(parts.join("/"))
}

fn normalized_package_path(value: &str) -> Result<String> {
    if value.is_empty() || value.contains('\0') || value.contains(':') {
        bail!("package path is empty or unsafe");
    }
    let replaced = value.replace('\\', "/");
    if replaced.starts_with('/') {
        bail!("package path is absolute");
    }
    let mut parts = Vec::new();
    let mut saw_content = false;
    let mut leading_parent_count = 0_usize;
    for raw in replaced.split('/') {
        if raw.is_empty() || raw == "." {
            continue;
        }
        if raw == ".." {
            if saw_content {
                bail!("package path traverses after its logical root");
            }
            leading_parent_count += 1;
            if leading_parent_count > 3 {
                bail!("package path traverses beyond the bounded Retoc mount prefix");
            }
            continue;
        }
        saw_content = true;
        parts.push(raw);
    }
    if parts.is_empty() {
        bail!("package path is empty after normalization");
    }
    Ok(parts.join("/").to_ascii_lowercase())
}

fn location_for(package: &InternalPackage) -> LayeredPackageLocation {
    package.location.clone()
}

fn build_report(
    mut inputs: Vec<LayeredPackageProviderInput>,
    mut excluded_installed_selected_sources: Vec<String>,
    mut excluded_non_iostore_dependency_sources: Vec<String>,
    mut excluded_incomplete_containers: Vec<String>,
) -> Result<LayeredIoStoreDependencyReport> {
    if inputs.is_empty() || inputs.len() > MAX_PROVIDER_COUNT {
        bail!("layered package provider count is outside its bounded limit");
    }
    inputs.sort_by(|left, right| {
        left.layer.precedence().cmp(&right.layer.precedence()).then(
            left.provider_id
                .to_ascii_lowercase()
                .cmp(&right.provider_id.to_ascii_lowercase()),
        )
    });

    let mut provider_names = BTreeSet::new();
    let mut providers = Vec::new();
    let mut packages = Vec::new();
    for input in &mut inputs {
        validate_label(&input.provider_id, "package provider ID")?;
        if !provider_names.insert((input.layer, input.provider_id.to_ascii_lowercase())) {
            bail!("one provider layer repeats a case-insensitive provider ID");
        }
        if input.containers.is_empty() {
            bail!("package provider contains no containers");
        }
        input.containers.sort_by(|left, right| {
            left.relative_utoc
                .to_ascii_lowercase()
                .cmp(&right.relative_utoc.to_ascii_lowercase())
        });
        let mut container_names = BTreeSet::new();
        let mut container_reports = Vec::new();
        let mut provider_package_count = 0_usize;
        for container in &mut input.containers {
            container.relative_utoc =
                normalized_relative_path(&container.relative_utoc, "provider container UTOC path")?;
            if !container_names.insert(container.relative_utoc.to_ascii_lowercase()) {
                bail!("package provider repeats a case-insensitive container path");
            }
            if !valid_sha256(&container.utoc_sha256) {
                bail!("provider container has an invalid UTOC SHA-256");
            }
            if container.packages.is_empty() && input.layer != PackageProviderLayer::GameContainer {
                bail!("provider container has no package-store entries");
            }
            container.packages.sort_by(|left, right| {
                left.package_id.cmp(&right.package_id).then(
                    left.path
                        .to_ascii_lowercase()
                        .cmp(&right.path.to_ascii_lowercase()),
                )
            });
            for package in &mut container.packages {
                let package_path = normalized_package_path(&package.path)?;
                package.imported_package_ids.sort_unstable();
                package.imported_package_ids.dedup();
                packages.push(InternalPackage {
                    location: LayeredPackageLocation {
                        layer: input.layer,
                        precedence: input.layer.precedence(),
                        provider_id: input.provider_id.clone(),
                        container: container.relative_utoc.clone(),
                        package_id: package.package_id,
                        package_path,
                    },
                    imported_package_ids: package.imported_package_ids.clone(),
                });
            }
            provider_package_count = provider_package_count
                .checked_add(container.packages.len())
                .context("provider package count overflow")?;
            container_reports.push(LayeredContainerReport {
                relative_utoc: container.relative_utoc.clone(),
                utoc_bytes: container.utoc_bytes,
                utoc_sha256: container.utoc_sha256.to_ascii_lowercase(),
                pak_present: container.pak_present,
                package_count: container.packages.len(),
            });
        }
        providers.push(LayeredProviderReport {
            layer: input.layer,
            precedence: input.layer.precedence(),
            provider_id: input.provider_id.clone(),
            container_count: container_reports.len(),
            package_count: provider_package_count,
            containers: container_reports,
        });
    }
    if packages.is_empty() || packages.len() > MAX_PACKAGE_COUNT {
        bail!("layered package count is outside its bounded limit");
    }
    packages.sort_by(|left, right| left.location.cmp(&right.location));

    let selected_indexes = packages
        .iter()
        .enumerate()
        .filter_map(|(index, package)| {
            (package.location.layer == PackageProviderLayer::SelectedMod).then_some(index)
        })
        .collect::<Vec<_>>();
    if selected_indexes.is_empty() {
        bail!("layered dependency resolution requires selected-mod package roots");
    }

    let mut same_layer_ids = BTreeMap::<(PackageProviderLayer, u64), usize>::new();
    let mut same_layer_paths = BTreeMap::<(PackageProviderLayer, String), usize>::new();
    let mut by_id = BTreeMap::<u64, Vec<usize>>::new();
    let mut by_path = BTreeMap::<String, Vec<usize>>::new();
    for (index, package) in packages.iter().enumerate() {
        if let Some(existing) =
            same_layer_ids.insert((package.location.layer, package.location.package_id), index)
        {
            bail!(
                "ambiguous same-layer package ID {} appears in {} and {}",
                package.location.package_id,
                packages[existing].location.container,
                package.location.container
            );
        }
        if let Some(existing) = same_layer_paths.insert(
            (
                package.location.layer,
                package.location.package_path.clone(),
            ),
            index,
        ) {
            bail!(
                "ambiguous same-layer package path {} appears in {} and {}",
                package.location.package_path,
                packages[existing].location.container,
                package.location.container
            );
        }
        by_id
            .entry(package.location.package_id)
            .or_default()
            .push(index);
        by_path
            .entry(package.location.package_path.clone())
            .or_default()
            .push(index);
    }

    let mut collision_flags = BTreeMap::<(usize, usize), CollisionFlags>::new();
    for indexes in by_id.values() {
        for (offset, left) in indexes.iter().enumerate() {
            for right in indexes.iter().skip(offset + 1) {
                let (higher, lower) =
                    if packages[*left].location.precedence < packages[*right].location.precedence {
                        (*left, *right)
                    } else {
                        (*right, *left)
                    };
                collision_flags
                    .entry((higher, lower))
                    .or_default()
                    .package_id = true;
            }
        }
    }
    for indexes in by_path.values() {
        for (offset, left) in indexes.iter().enumerate() {
            for right in indexes.iter().skip(offset + 1) {
                let (higher, lower) =
                    if packages[*left].location.precedence < packages[*right].location.precedence {
                        (*left, *right)
                    } else {
                        (*right, *left)
                    };
                collision_flags
                    .entry((higher, lower))
                    .or_default()
                    .package_path = true;
            }
        }
    }
    if collision_flags.len() > MAX_COLLISION_COUNT {
        bail!("cross-layer collision report exceeds its bounded limit");
    }
    let cross_layer_collisions = collision_flags
        .into_iter()
        .map(|((higher, lower), flags)| CrossLayerPackageCollision {
            higher_priority: location_for(&packages[higher]),
            lower_priority: location_for(&packages[lower]),
            package_id_collision: flags.package_id,
            package_path_collision: flags.package_path,
            exact_identity: flags.package_id && flags.package_path,
        })
        .collect::<Vec<_>>();

    let mut pending = selected_indexes.into_iter().collect::<BTreeSet<_>>();
    let mut visited = BTreeSet::new();
    let mut dependency_edges = Vec::new();
    while let Some(source_index) = pending.pop_first() {
        if !visited.insert(source_index) {
            continue;
        }
        let source = &packages[source_index];
        for dependency_package_id in &source.imported_package_ids {
            if dependency_edges.len() >= MAX_DEPENDENCY_EDGE_COUNT {
                bail!("layered dependency edge graph exceeds its bounded limit");
            }
            let candidates = by_id.get(dependency_package_id);
            let target_index = candidates.and_then(|values| values.first()).copied();
            if let Some(target_index) = target_index {
                pending.insert(target_index);
            }
            dependency_edges.push(LayeredDependencyEdge {
                source: location_for(source),
                dependency_package_id: *dependency_package_id,
                resolved: target_index.is_some(),
                target: target_index.map(|index| location_for(&packages[index])),
                shadowed_candidate_count: candidates
                    .map(|values| values.len().saturating_sub(1))
                    .unwrap_or(0),
            });
        }
    }
    dependency_edges.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then(left.dependency_package_id.cmp(&right.dependency_package_id))
    });
    let resolved_edge_count = dependency_edges.iter().filter(|edge| edge.resolved).count();
    let unresolved_edge_count = dependency_edges.len().saturating_sub(resolved_edge_count);

    let mut layers = Vec::new();
    for layer in [
        PackageProviderLayer::SelectedMod,
        PackageProviderLayer::ConnectedDependency,
        PackageProviderLayer::InstalledActiveMod,
        PackageProviderLayer::GameContainer,
        PackageProviderLayer::StockMain,
    ] {
        let rows = providers
            .iter()
            .filter(|provider| provider.layer == layer)
            .collect::<Vec<_>>();
        layers.push(LayeredLayerSummary {
            layer,
            precedence: layer.precedence(),
            provider_count: rows.len(),
            container_count: rows.iter().map(|provider| provider.container_count).sum(),
            package_count: rows.iter().map(|provider| provider.package_count).sum(),
        });
    }
    excluded_installed_selected_sources.sort_by_key(|value| value.to_ascii_lowercase());
    excluded_installed_selected_sources.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    excluded_non_iostore_dependency_sources.sort_by_key(|value| value.to_ascii_lowercase());
    excluded_non_iostore_dependency_sources
        .dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    excluded_incomplete_containers.sort_by_key(|value| value.to_ascii_lowercase());
    excluded_incomplete_containers.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    let mut blockers = Vec::new();
    if unresolved_edge_count > 0 {
        blockers.push(format!(
            "unresolved-layered-package-dependencies:found-{unresolved_edge_count}"
        ));
    }
    let mut warnings = vec![
        "Layer precedence is selected mod, connected dependencies, installed active mods, game/DLC containers, then stock main; configured precedence is evidence, not a live mount-order claim."
            .to_owned(),
        "This read-only report proves package-store identity and dependency resolution only; it does not prove export compatibility, gameplay behavior, save compatibility, or runtime loading."
            .to_owned(),
    ];
    if !cross_layer_collisions.is_empty() {
        warnings.push(format!(
            "Cross-layer package identity collisions were resolved by declared precedence and retained as diagnostics: found {}.",
            cross_layer_collisions.len()
        ));
    }
    if !excluded_non_iostore_dependency_sources.is_empty() {
        warnings.push(format!(
            "Connected dependency sources without IoStore container triples were retained as out-of-lane inputs and excluded from package resolution: found {}.",
            excluded_non_iostore_dependency_sources.len()
        ));
    }
    if !excluded_incomplete_containers.is_empty() {
        warnings.push(format!(
            "Incomplete PAK/UCAS/UTOC container group(s) cannot provide IoStore packages and were excluded from layered resolution; complete or remove them to make this environment claim exact: {}.",
            excluded_incomplete_containers.join("; ")
        ));
    }
    let resolution_complete = blockers.is_empty();
    let mut report = LayeredIoStoreDependencyReport {
        api: LAYERED_IOSTORE_DEPENDENCY_API.to_owned(),
        status: if resolution_complete {
            "complete-report-only"
        } else {
            "blocked"
        }
        .to_owned(),
        mutation_policy: "report-only".to_owned(),
        resolution_complete,
        logical_sha256: String::new(),
        provider_count: providers.len(),
        container_count: providers
            .iter()
            .map(|provider| provider.container_count)
            .sum(),
        total_package_count: packages.len(),
        reachable_package_count: visited.len(),
        dependency_edge_count: dependency_edges.len(),
        resolved_edge_count,
        unresolved_edge_count,
        cross_layer_collision_count: cross_layer_collisions.len(),
        excluded_installed_selected_source_count: excluded_installed_selected_sources.len(),
        excluded_non_iostore_dependency_source_count: excluded_non_iostore_dependency_sources.len(),
        excluded_incomplete_container_count: excluded_incomplete_containers.len(),
        layers,
        providers,
        dependency_edges,
        cross_layer_collisions,
        excluded_installed_selected_sources,
        excluded_non_iostore_dependency_sources,
        excluded_incomplete_containers,
        blockers,
        warnings,
    };
    report.logical_sha256 = sha256_bytes(&serde_json::to_vec(&report)?);
    Ok(report)
}

pub fn resolve_layered_package_stores(
    providers: Vec<LayeredPackageProviderInput>,
) -> Result<LayeredIoStoreDependencyReport> {
    build_report(providers, Vec::new(), Vec::new(), Vec::new())
}

struct StagedSource {
    _temporary: Option<TempDir>,
    root: PathBuf,
}

#[derive(Clone, Debug)]
struct ContainerFiles {
    relative_utoc: String,
    pak: Option<PathBuf>,
    ucas: PathBuf,
    utoc: PathBuf,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ContainerFingerprint {
    pak_sha256: String,
    ucas_sha256: String,
    utoc_sha256: String,
}

impl ContainerFingerprint {
    fn logical_sha256(&self) -> String {
        sha256_bytes(
            format!(
                "pak:{}\nucas:{}\nutoc:{}\n",
                self.pak_sha256, self.ucas_sha256, self.utoc_sha256
            )
            .as_bytes(),
        )
    }
}

#[derive(Default)]
struct ContainerMembers {
    relative_stem: Option<String>,
    pak: Option<PathBuf>,
    ucas: Option<PathBuf>,
    utoc: Option<PathBuf>,
}

/// A PAK/UCAS/UTOC stem group that is missing at least one member. The group
/// is named so an excluded or rejected source is always attributable to one
/// concrete container instead of a generic message.
#[derive(Clone, Debug, Eq, PartialEq)]
struct IncompleteContainerGroup {
    location: String,
    missing: Vec<&'static str>,
}

impl IncompleteContainerGroup {
    fn describe(&self) -> String {
        format!("{} (missing: {})", self.location, self.missing.join(", "))
    }
}

fn require_complete_container_triples(
    incomplete: &[IncompleteContainerGroup],
    context: &str,
) -> Result<()> {
    if incomplete.is_empty() {
        return Ok(());
    }
    bail!(
        "{context} contains {} incomplete PAK/UCAS/UTOC triple(s): {}",
        incomplete.len(),
        incomplete
            .iter()
            .map(IncompleteContainerGroup::describe)
            .collect::<Vec<_>>()
            .join("; ")
    );
}

fn stage_mod_source(input: &Path, prefix: &str) -> Result<StagedSource> {
    if input.is_dir() {
        return Ok(StagedSource {
            _temporary: None,
            root: input.to_path_buf(),
        });
    }
    if !input.is_file() {
        bail!("layered package source is not a file or directory");
    }
    let temporary = tempfile::Builder::new().prefix(prefix).tempdir()?;
    let selected = extract_archive_files_with_extensions_bounded(
        input,
        temporary.path(),
        &["pak", "ucas", "utoc"],
        MAX_STAGED_IOSTORE_BYTES,
        MAX_STAGED_IOSTORE_BYTES,
    )?;
    if selected == 0 {
        bail!("layered package archive contains no IoStore container members");
    }
    Ok(StagedSource {
        root: temporary.path().to_path_buf(),
        _temporary: Some(temporary),
    })
}

fn stage_optional_dependency_source(input: &Path, prefix: &str) -> Result<Option<StagedSource>> {
    if input.is_dir() {
        return Ok(Some(StagedSource {
            _temporary: None,
            root: input.to_path_buf(),
        }));
    }
    if !input.is_file() {
        bail!("connected dependency source is not a file or directory");
    }
    let temporary = tempfile::Builder::new().prefix(prefix).tempdir()?;
    let selected = extract_archive_files_with_extensions_bounded(
        input,
        temporary.path(),
        &["pak", "ucas", "utoc"],
        MAX_STAGED_IOSTORE_BYTES,
        MAX_STAGED_IOSTORE_BYTES,
    )?;
    if selected == 0 {
        return Ok(None);
    }
    Ok(Some(StagedSource {
        root: temporary.path().to_path_buf(),
        _temporary: Some(temporary),
    }))
}

fn discover_mod_container_triples(
    root: &Path,
    recursive: bool,
    require_any: bool,
    report_prefix: Option<&str>,
) -> Result<(Vec<ContainerFiles>, Vec<IncompleteContainerGroup>)> {
    if !root.is_dir() {
        if require_any {
            bail!("layered package source directory is unavailable");
        }
        return Ok((Vec::new(), Vec::new()));
    }
    let mut walk = WalkDir::new(root).follow_links(false);
    if !recursive {
        walk = walk.max_depth(1);
    }
    let mut members = BTreeMap::<String, ContainerMembers>::new();
    let mut selected_bytes = 0_u64;
    for (index, entry) in walk.into_iter().enumerate() {
        if index >= MAX_ARCHIVE_ENTRIES {
            bail!("layered package source exceeds the bounded entry limit");
        }
        let entry = entry.context("walking layered package source")?;
        if entry.path() == root {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!("layered package source contains a filesystem link");
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
        if !matches!(extension.as_str(), "pak" | "ucas" | "utoc") {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .context("layered package member escaped its source root")?;
        let relative_stem = normalized_relative_path(
            &relative.with_extension("").to_string_lossy(),
            "layered package container stem",
        )?;
        let key = relative_stem.to_ascii_lowercase();
        let row = members.entry(key).or_default();
        if let Some(existing) = &row.relative_stem {
            if !existing.eq_ignore_ascii_case(&relative_stem) {
                bail!(
                    "layered package source repeats a case-insensitive container stem: {existing} vs {relative_stem}"
                );
            }
        } else {
            row.relative_stem = Some(relative_stem.clone());
        }
        let slot = match extension.as_str() {
            "pak" => &mut row.pak,
            "ucas" => &mut row.ucas,
            "utoc" => &mut row.utoc,
            _ => unreachable!(),
        };
        if slot.replace(entry.path().to_path_buf()).is_some() {
            bail!(
                "layered package source repeats a container member: {relative_stem}.{extension}"
            );
        }
        selected_bytes = selected_bytes
            .checked_add(entry.metadata()?.len())
            .context("layered package source byte count overflow")?;
        if selected_bytes > MAX_STAGED_IOSTORE_BYTES {
            bail!("layered package source exceeds the bounded byte limit");
        }
    }
    if members.is_empty() {
        if require_any {
            bail!("layered package source contains no container triples");
        }
        return Ok((Vec::new(), Vec::new()));
    }
    let mut containers = Vec::new();
    let mut incomplete = Vec::new();
    for row in members.into_values() {
        let relative_stem = row
            .relative_stem
            .context("layered container group lost its stem")?;
        let location = if let Some(prefix) = report_prefix {
            format!("{prefix}/{relative_stem}")
        } else {
            relative_stem.clone()
        };
        let missing = [
            (row.pak.is_none(), "pak"),
            (row.ucas.is_none(), "ucas"),
            (row.utoc.is_none(), "utoc"),
        ]
        .into_iter()
        .filter_map(|(absent, member)| absent.then_some(member))
        .collect::<Vec<_>>();
        if !missing.is_empty() {
            incomplete.push(IncompleteContainerGroup { location, missing });
            continue;
        }
        containers.push(ContainerFiles {
            relative_utoc: format!("{location}.utoc"),
            pak: row.pak,
            ucas: row.ucas.unwrap(),
            utoc: row.utoc.unwrap(),
        });
    }
    containers.sort_by(|left, right| {
        left.relative_utoc
            .to_ascii_lowercase()
            .cmp(&right.relative_utoc.to_ascii_lowercase())
    });
    incomplete.sort_by(|left, right| {
        left.location
            .to_ascii_lowercase()
            .cmp(&right.location.to_ascii_lowercase())
    });
    Ok((containers, incomplete))
}

fn discover_game_containers(paks: &Path) -> Result<(Vec<ContainerFiles>, ContainerFiles)> {
    if !paks.is_dir() {
        bail!("connected game Paks directory is unavailable");
    }
    let mut members = BTreeMap::<String, ContainerMembers>::new();
    for (index, entry) in fs::read_dir(paks)
        .context("reading connected game Paks directory")?
        .enumerate()
    {
        if index >= MAX_ARCHIVE_ENTRIES {
            bail!("connected game Paks directory exceeds the bounded entry limit");
        }
        let entry = entry.context("reading a connected game Paks entry")?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!("connected game Paks directory contains a filesystem link");
        }
        if !file_type.is_file() {
            continue;
        }
        let extension = entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "pak" | "ucas" | "utoc") {
            continue;
        }
        let stem = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .context("connected game container stem is not Unicode")?
            .to_owned();
        let row = members.entry(stem.to_ascii_lowercase()).or_default();
        row.relative_stem.get_or_insert(stem);
        let slot = match extension.as_str() {
            "pak" => &mut row.pak,
            "ucas" => &mut row.ucas,
            "utoc" => &mut row.utoc,
            _ => unreachable!(),
        };
        if slot.replace(entry.path()).is_some() {
            bail!("connected game repeats a case-insensitive container member");
        }
    }

    let main_key = "oblivionremastered-windows";
    let mut stock_main = None;
    let mut game = Vec::new();
    for (key, row) in members {
        let name = row.relative_stem.clone().unwrap_or_else(|| key.clone());
        let missing = [(row.ucas.is_none(), "ucas"), (row.utoc.is_none(), "utoc")]
            .into_iter()
            .filter_map(|(absent, member)| absent.then_some(member))
            .collect::<Vec<_>>();
        let (Some(stem), Some(ucas), Some(utoc)) = (row.relative_stem, row.ucas, row.utoc) else {
            bail!(
                "connected game container {name} is an incomplete IoStore group (missing: {})",
                missing.join(", ")
            );
        };
        if key == main_key && row.pak.is_none() {
            bail!("connected game stock main container has no matching PAK");
        }
        if key != main_key && key != "global" && row.pak.is_none() {
            bail!("connected game/DLC container {stem} has no matching PAK");
        }
        let container = ContainerFiles {
            relative_utoc: format!("Content/Paks/{stem}.utoc"),
            pak: row.pak,
            ucas,
            utoc,
        };
        if key == main_key {
            stock_main = Some(container);
        } else {
            game.push(container);
        }
    }
    game.sort_by(|left, right| {
        left.relative_utoc
            .to_ascii_lowercase()
            .cmp(&right.relative_utoc.to_ascii_lowercase())
    });
    if game.is_empty() {
        bail!("connected game contains no non-main game/DLC package-store container");
    }
    Ok((
        game,
        stock_main.context("connected game stock main container is unavailable")?,
    ))
}

fn container_fingerprint(container: &ContainerFiles) -> Result<ContainerFingerprint> {
    Ok(ContainerFingerprint {
        pak_sha256: container
            .pak
            .as_ref()
            .map(|path| sha256_file(path))
            .transpose()?
            .unwrap_or_default(),
        ucas_sha256: sha256_file(&container.ucas)?,
        utoc_sha256: sha256_file(&container.utoc)?,
    })
}

fn provider_from_containers(
    layer: PackageProviderLayer,
    provider_id: String,
    containers: &[ContainerFiles],
    retoc: &RetocTool,
) -> Result<LayeredPackageProviderInput> {
    let mut rows = Vec::new();
    let mut package_count = 0_usize;
    for container in containers {
        if matches!(
            layer,
            PackageProviderLayer::SelectedMod
                | PackageProviderLayer::ConnectedDependency
                | PackageProviderLayer::InstalledActiveMod
        ) {
            retoc
                .verify(&container.utoc, "retoc verify layered package provider")
                .map_err(|_| {
                    anyhow::anyhow!("layered package provider failed UTOC verification")
                })?;
        }
        let (_, packages) = retoc
            .package_store_entries_allow_empty(&container.utoc)
            .map_err(|_| {
                anyhow::anyhow!("layered package provider package store could not be read")
            })?;
        if packages.is_empty() && layer != PackageProviderLayer::GameContainer {
            bail!("layered package provider contains no asset package-store entries");
        }
        package_count = package_count
            .checked_add(packages.len())
            .context("layered provider package count overflow")?;
        if package_count > MAX_PACKAGE_COUNT {
            bail!("one layered provider exceeds the bounded package limit");
        }
        rows.push(LayeredContainerInput {
            relative_utoc: container.relative_utoc.clone(),
            utoc_bytes: fs::metadata(&container.utoc)?.len(),
            utoc_sha256: sha256_file(&container.utoc)?,
            pak_present: container.pak.is_some(),
            packages,
        });
    }
    Ok(LayeredPackageProviderInput {
        layer,
        provider_id,
        containers: rows,
    })
}

fn containers_content_sha256(containers: &[ContainerFiles]) -> Result<String> {
    let mut rows = containers
        .iter()
        .map(|container| {
            Ok(format!(
                "{}\t{}",
                container.relative_utoc.to_ascii_lowercase(),
                container_fingerprint(container)?.logical_sha256()
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    rows.sort();
    Ok(sha256_bytes(rows.join("\n").as_bytes()))
}

fn safe_source_leaf(path: &Path) -> String {
    let raw = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("dependency");
    let mut result = String::new();
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
            result.push(character.to_ascii_lowercase());
        } else if !result.ends_with('-') {
            result.push('-');
        }
    }
    result.trim_matches('-').chars().take(96).collect()
}

/// Builds a read-only transitive package dependency report from the selected
/// mod, explicitly connected dependency inputs, the connected game's active
/// `~mods`, non-main game containers, and stock main package store.
pub fn probe_layered_iostore_dependencies(
    selected_mod_input: &Path,
    dependency_inputs: &[PathBuf],
    current_game_root: &Path,
) -> Result<LayeredIoStoreDependencyReport> {
    if dependency_inputs.len() >= MAX_PROVIDER_COUNT {
        bail!("connected dependency input count exceeds the bounded provider limit");
    }
    let game_root = normalize_install_root(current_game_root);
    let game_paks = game_root.join(r"OblivionRemastered\Content\Paks");
    let installed_mods = game_paks.join("~mods");
    if selected_mod_input.is_dir() && installed_mods.is_dir() {
        let selected_canonical = fs::canonicalize(selected_mod_input);
        let installed_canonical = fs::canonicalize(&installed_mods);
        if selected_canonical.is_ok()
            && installed_canonical.is_ok()
            && selected_canonical? == installed_canonical?
        {
            bail!("the connected game's active ~mods directory cannot be the selected mod source");
        }
    }

    let retoc = RetocTool::materialize()?;
    let selected_staged = stage_mod_source(selected_mod_input, "obr-layered-selected-")?;
    let (selected_containers, selected_incomplete) =
        discover_mod_container_triples(&selected_staged.root, true, true, None)?;
    require_complete_container_triples(&selected_incomplete, "the selected mod source")?;
    if selected_containers.is_empty() {
        bail!("the selected mod source contains no complete PAK/UCAS/UTOC container triples");
    }
    let selected_fingerprints = selected_containers
        .iter()
        .map(container_fingerprint)
        .collect::<Result<BTreeSet<_>>>()?;
    let selected_provider = provider_from_containers(
        PackageProviderLayer::SelectedMod,
        "selected-mod".to_owned(),
        &selected_containers,
        &retoc,
    )?;
    let mut providers = vec![selected_provider];

    let mut excluded_non_iostore_dependency_sources = Vec::new();
    let mut excluded_incomplete_containers = Vec::new();
    for (index, input) in dependency_inputs.iter().enumerate() {
        let Some(staged) = stage_optional_dependency_source(input, "obr-layered-dependency-")?
        else {
            excluded_non_iostore_dependency_sources.push(format!(
                "connected-source-{index}:{}",
                safe_source_leaf(input)
            ));
            continue;
        };
        let (containers, incomplete) =
            discover_mod_container_triples(&staged.root, true, false, None)?;
        for group in &incomplete {
            excluded_incomplete_containers.push(format!(
                "connected-source-{index}:{}:{}",
                safe_source_leaf(input),
                group.describe()
            ));
        }
        if containers.is_empty() {
            excluded_non_iostore_dependency_sources.push(format!(
                "connected-source-{index}:{}",
                safe_source_leaf(input)
            ));
            continue;
        }
        let fingerprint = containers_content_sha256(&containers)?;
        let mut provider = provider_from_containers(
            PackageProviderLayer::ConnectedDependency,
            "connected-dependency".to_owned(),
            &containers,
            &retoc,
        )?;
        provider.provider_id = format!(
            "connected-dependency:{}:{}",
            safe_source_leaf(input),
            &fingerprint[..12]
        );
        providers.push(provider);
    }

    let mut excluded_installed_selected_sources = Vec::new();
    let (installed_containers, installed_incomplete) =
        discover_mod_container_triples(&installed_mods, true, false, Some("Content/Paks/~mods"))?;
    for group in &installed_incomplete {
        excluded_incomplete_containers.push(format!("installed-active-mod:{}", group.describe()));
    }
    for container in installed_containers {
        let fingerprint = container_fingerprint(&container)?;
        if selected_fingerprints.contains(&fingerprint) {
            excluded_installed_selected_sources.push(container.relative_utoc.clone());
            continue;
        }
        let mut provider = provider_from_containers(
            PackageProviderLayer::InstalledActiveMod,
            "installed-active-mod".to_owned(),
            std::slice::from_ref(&container),
            &retoc,
        )?;
        provider.provider_id = format!(
            "installed-active-mod:{}",
            &fingerprint.logical_sha256()[..12]
        );
        providers.push(provider);
    }

    let (game_containers, stock_main) = discover_game_containers(&game_paks)?;
    for container in game_containers {
        let stem = Path::new(&container.relative_utoc)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("game-container")
            .to_ascii_lowercase();
        providers.push(provider_from_containers(
            PackageProviderLayer::GameContainer,
            format!("game-container:{stem}"),
            std::slice::from_ref(&container),
            &retoc,
        )?);
    }
    providers.push(provider_from_containers(
        PackageProviderLayer::StockMain,
        "stock-main".to_owned(),
        std::slice::from_ref(&stock_main),
        &retoc,
    )?);

    build_report(
        providers,
        excluded_installed_selected_sources,
        excluded_non_iostore_dependency_sources,
        excluded_incomplete_containers,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(id: u64, path: &str, imports: &[u64]) -> PackageStoreEntry {
        PackageStoreEntry {
            package_id: id,
            path: path.to_owned(),
            imported_package_ids: imports.to_vec(),
        }
    }

    fn provider(
        layer: PackageProviderLayer,
        provider_id: &str,
        container: &str,
        packages: Vec<PackageStoreEntry>,
    ) -> LayeredPackageProviderInput {
        LayeredPackageProviderInput {
            layer,
            provider_id: provider_id.to_owned(),
            containers: vec![LayeredContainerInput {
                relative_utoc: container.to_owned(),
                utoc_bytes: 123,
                utoc_sha256: "a".repeat(64),
                pak_present: true,
                packages,
            }],
        }
    }

    fn complete_provider_set() -> Vec<LayeredPackageProviderInput> {
        vec![
            provider(
                PackageProviderLayer::SelectedMod,
                "selected",
                "selected/Root.utoc",
                vec![package(
                    10,
                    "../../../OblivionRemastered/Content/Selected/Root.uasset",
                    &[20],
                )],
            ),
            provider(
                PackageProviderLayer::ConnectedDependency,
                "dependency",
                "dependency/Body.utoc",
                vec![package(
                    20,
                    "../../../OblivionRemastered/Content/Shared/Body.uasset",
                    &[30],
                )],
            ),
            provider(
                PackageProviderLayer::InstalledActiveMod,
                "installed",
                "installed/Body.utoc",
                vec![
                    package(
                        20,
                        "../../../OblivionRemastered/Content/Shared/Body.uasset",
                        &[],
                    ),
                    package(
                        30,
                        "../../../OblivionRemastered/Content/Installed/Material.uasset",
                        &[],
                    ),
                ],
            ),
            provider(
                PackageProviderLayer::GameContainer,
                "global",
                "Content/Paks/global.utoc",
                vec![package(
                    30,
                    "../../../OblivionRemastered/Content/Game/Material.uasset",
                    &[],
                )],
            ),
            provider(
                PackageProviderLayer::StockMain,
                "stock",
                "Content/Paks/OblivionRemastered-Windows.utoc",
                vec![package(
                    20,
                    "../../../OblivionRemastered/Content/Stock/Body.uasset",
                    &[],
                )],
            ),
        ]
    }

    #[test]
    fn resolves_transitive_dependencies_by_declared_layer_precedence() {
        let report = resolve_layered_package_stores(complete_provider_set()).unwrap();
        assert_eq!(report.api, LAYERED_IOSTORE_DEPENDENCY_API);
        assert_eq!(report.status, "complete-report-only");
        assert!(report.resolution_complete);
        assert_eq!(report.dependency_edge_count, 2);
        assert_eq!(report.reachable_package_count, 3);
        assert_eq!(report.cross_layer_collision_count, 4);

        let first = report
            .dependency_edges
            .iter()
            .find(|edge| edge.dependency_package_id == 20)
            .unwrap();
        assert_eq!(
            first.target.as_ref().unwrap().layer,
            PackageProviderLayer::ConnectedDependency
        );
        assert_eq!(first.shadowed_candidate_count, 2);
        let second = report
            .dependency_edges
            .iter()
            .find(|edge| edge.dependency_package_id == 30)
            .unwrap();
        assert_eq!(
            second.target.as_ref().unwrap().layer,
            PackageProviderLayer::InstalledActiveMod
        );
        assert!(report.cross_layer_collisions.iter().any(|collision| {
            collision.exact_identity
                && collision.higher_priority.layer == PackageProviderLayer::ConnectedDependency
                && collision.lower_priority.layer == PackageProviderLayer::InstalledActiveMod
        }));
    }

    #[test]
    fn unresolved_edges_are_retained_as_report_blockers() {
        let providers = vec![
            provider(
                PackageProviderLayer::SelectedMod,
                "selected",
                "Selected.utoc",
                vec![package(10, "Game/Selected.uasset", &[999])],
            ),
            provider(
                PackageProviderLayer::StockMain,
                "stock",
                "Stock.utoc",
                vec![package(20, "Game/Stock.uasset", &[])],
            ),
        ];
        let report = resolve_layered_package_stores(providers).unwrap();
        assert_eq!(report.status, "blocked");
        assert_eq!(report.unresolved_edge_count, 1);
        assert!(!report.dependency_edges[0].resolved);
        assert!(report.dependency_edges[0].target.is_none());
        assert!(report.blockers[0].starts_with("unresolved-layered-package-dependencies"));
    }

    #[test]
    fn rejects_ambiguous_same_layer_ids_and_paths() {
        let mut duplicate_id = complete_provider_set();
        duplicate_id.push(provider(
            PackageProviderLayer::ConnectedDependency,
            "second-dependency",
            "Second.utoc",
            vec![package(20, "Game/OtherBody.uasset", &[])],
        ));
        assert!(
            resolve_layered_package_stores(duplicate_id)
                .unwrap_err()
                .to_string()
                .contains("ambiguous same-layer package ID")
        );

        let duplicate_path = vec![
            provider(
                PackageProviderLayer::SelectedMod,
                "selected",
                "Selected.utoc",
                vec![package(10, "Game/Selected.uasset", &[])],
            ),
            provider(
                PackageProviderLayer::ConnectedDependency,
                "first",
                "First.utoc",
                vec![package(20, "Game/Shared.uasset", &[])],
            ),
            provider(
                PackageProviderLayer::ConnectedDependency,
                "second",
                "Second.utoc",
                vec![package(21, "game/shared.uasset", &[])],
            ),
        ];
        assert!(
            resolve_layered_package_stores(duplicate_path)
                .unwrap_err()
                .to_string()
                .contains("ambiguous same-layer package path")
        );
    }

    #[test]
    fn report_signature_is_stable_across_provider_and_import_order() {
        let providers = complete_provider_set();
        let first = resolve_layered_package_stores(providers.clone()).unwrap();
        let mut reversed = providers.into_iter().rev().collect::<Vec<_>>();
        for provider in &mut reversed {
            provider.containers.reverse();
            for container in &mut provider.containers {
                container.packages.reverse();
                for package in &mut container.packages {
                    package.imported_package_ids.reverse();
                }
            }
        }
        let second = resolve_layered_package_stores(reversed).unwrap();
        assert_eq!(first.logical_sha256, second.logical_sha256);
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_unsafe_report_and_package_paths() {
        let unsafe_container = vec![provider(
            PackageProviderLayer::SelectedMod,
            "selected",
            "../escape.utoc",
            vec![package(10, "Game/Selected.uasset", &[])],
        )];
        assert!(resolve_layered_package_stores(unsafe_container).is_err());

        let unsafe_package = vec![provider(
            PackageProviderLayer::SelectedMod,
            "selected",
            "Selected.utoc",
            vec![package(10, "Game/../Escape.uasset", &[])],
        )];
        assert!(resolve_layered_package_stores(unsafe_package).is_err());

        let excessive_mount_traversal = vec![provider(
            PackageProviderLayer::SelectedMod,
            "selected",
            "Selected.utoc",
            vec![package(10, "../../../../Escape.uasset", &[])],
        )];
        assert!(resolve_layered_package_stores(excessive_mount_traversal).is_err());
    }

    #[test]
    fn filesystem_discovery_names_incomplete_triples() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("Fixture.pak"), b"pak").unwrap();
        fs::write(temporary.path().join("Fixture.utoc"), b"utoc").unwrap();
        let (containers, incomplete) =
            discover_mod_container_triples(temporary.path(), true, true, None).unwrap();
        assert!(containers.is_empty());
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].describe(), "Fixture (missing: ucas)");
        let error = require_complete_container_triples(&incomplete, "the selected mod source")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Fixture"), "{error}");
        assert!(error.contains("missing: ucas"), "{error}");
        fs::write(temporary.path().join("Fixture.ucas"), b"ucas").unwrap();
        let (containers, incomplete) =
            discover_mod_container_triples(temporary.path(), true, true, None).unwrap();
        assert!(incomplete.is_empty());
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].relative_utoc, "Fixture.utoc");
    }

    #[test]
    fn installed_discovery_retains_complete_triples_next_to_incomplete_leftovers() {
        let temporary = tempfile::tempdir().unwrap();
        for extension in ["pak", "ucas", "utoc"] {
            fs::write(temporary.path().join(format!("Good_P.{extension}")), extension).unwrap();
        }
        fs::write(temporary.path().join("Leftover_P.utoc"), b"junk").unwrap();
        fs::write(temporary.path().join("LegacyPakOnly_P.pak"), b"pak").unwrap();
        let (containers, incomplete) = discover_mod_container_triples(
            temporary.path(),
            true,
            false,
            Some("Content/Paks/~mods"),
        )
        .unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].relative_utoc, "Content/Paks/~mods/Good_P.utoc");
        assert_eq!(incomplete.len(), 2);
        assert_eq!(
            incomplete[0].describe(),
            "Content/Paks/~mods/Leftover_P (missing: pak, ucas)"
        );
        assert_eq!(
            incomplete[1].describe(),
            "Content/Paks/~mods/LegacyPakOnly_P (missing: ucas, utoc)"
        );
    }

    #[test]
    fn incomplete_container_exclusions_surface_in_report_warnings() {
        let report = build_report(
            complete_provider_set(),
            Vec::new(),
            Vec::new(),
            vec!["installed-active-mod:Content/Paks/~mods/Leftover_P (missing: ucas)".to_owned()],
        )
        .unwrap();
        assert_eq!(report.excluded_incomplete_container_count, 1);
        assert!(report.resolution_complete);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("Leftover_P") && warning.contains("missing: ucas")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn connected_runtime_archive_without_iostore_is_out_of_lane() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        fs::create_dir_all(&source).unwrap();
        let readme = source.join("readme.txt");
        fs::write(&readme, b"runtime tool").unwrap();
        let archive = temporary.path().join("runtime-tool.zip");
        crate::archive::create_zip_from_paths(&archive, &source, &[readme]).unwrap();

        assert!(
            stage_optional_dependency_source(&archive, "obr-layered-optional-test-")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn recursive_installed_discovery_preserves_nested_container_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let nested = temporary.path().join("Pack/Containers");
        fs::create_dir_all(&nested).unwrap();
        for extension in ["pak", "ucas", "utoc"] {
            fs::write(nested.join(format!("Fixture.{extension}")), extension).unwrap();
        }

        let (containers, incomplete) = discover_mod_container_triples(
            temporary.path(),
            true,
            true,
            Some("Content/Paks/~mods"),
        )
        .unwrap();
        assert!(incomplete.is_empty());
        assert_eq!(containers.len(), 1);
        assert_eq!(
            containers[0].relative_utoc,
            "Content/Paks/~mods/Pack/Containers/Fixture.utoc"
        );
    }

    #[test]
    fn selected_source_fingerprint_hashes_every_container_member() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        for root in [&first, &second] {
            fs::write(root.join("Fixture.pak"), b"pak").unwrap();
            fs::write(root.join("Fixture.utoc"), b"utoc").unwrap();
        }
        fs::write(first.join("Fixture.ucas"), b"first").unwrap();
        fs::write(second.join("Fixture.ucas"), b"other").unwrap();

        let (first, _) = discover_mod_container_triples(&first, true, true, None).unwrap();
        let (second, _) = discover_mod_container_triples(&second, true, true, None).unwrap();
        assert_ne!(
            container_fingerprint(&first[0]).unwrap(),
            container_fingerprint(&second[0]).unwrap()
        );
    }

    #[test]
    fn filesystem_discovery_rejects_links_when_the_platform_can_create_one() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target.bin");
        let link = temporary.path().join("linked.pak");
        fs::write(&target, b"target").unwrap();
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_file(&target, &link);
        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(&target, &link);
        if created.is_ok() {
            assert!(discover_mod_container_triples(temporary.path(), true, false, None).is_err());
        }
    }

    #[test]
    fn empty_script_only_game_container_remains_visible_without_affecting_resolution() {
        let providers = vec![
            provider(
                PackageProviderLayer::SelectedMod,
                "selected",
                "Selected.utoc",
                vec![package(10, "Game/Selected.uasset", &[20])],
            ),
            provider(
                PackageProviderLayer::GameContainer,
                "global",
                "Content/Paks/global.utoc",
                Vec::new(),
            ),
            provider(
                PackageProviderLayer::StockMain,
                "stock",
                "Content/Paks/OblivionRemastered-Windows.utoc",
                vec![package(20, "Game/Stock.uasset", &[])],
            ),
        ];
        let report = resolve_layered_package_stores(providers).unwrap();
        assert!(report.resolution_complete);
        let global = report
            .providers
            .iter()
            .find(|provider| provider.provider_id == "global")
            .unwrap();
        assert_eq!(global.package_count, 0);
        assert_eq!(global.container_count, 1);
    }

    #[test]
    fn game_discovery_separates_global_and_stock_main_topologies() {
        let temporary = tempfile::tempdir().unwrap();
        for name in ["global.ucas", "global.utoc"] {
            fs::write(temporary.path().join(name), b"game").unwrap();
        }
        for name in [
            "OblivionRemastered-Windows.pak",
            "OblivionRemastered-Windows.ucas",
            "OblivionRemastered-Windows.utoc",
        ] {
            fs::write(temporary.path().join(name), b"stock").unwrap();
        }
        let (game, stock) = discover_game_containers(temporary.path()).unwrap();
        assert_eq!(game.len(), 1);
        assert_eq!(game[0].relative_utoc, "Content/Paks/global.utoc");
        assert!(game[0].pak.is_none());
        assert_eq!(
            stock.relative_utoc,
            "Content/Paks/OblivionRemastered-Windows.utoc"
        );
        assert!(stock.pak.is_some());
    }

    #[test]
    fn game_discovery_requires_complete_non_global_dlc_triples() {
        let temporary = tempfile::tempdir().unwrap();
        for name in ["global.ucas", "global.utoc", "DlcOne.ucas", "DlcOne.utoc"] {
            fs::write(temporary.path().join(name), b"game").unwrap();
        }
        for name in [
            "OblivionRemastered-Windows.pak",
            "OblivionRemastered-Windows.ucas",
            "OblivionRemastered-Windows.utoc",
        ] {
            fs::write(temporary.path().join(name), b"stock").unwrap();
        }
        assert!(discover_game_containers(temporary.path()).is_err());
        fs::write(temporary.path().join("DlcOne.pak"), b"dlc").unwrap();
        let (game, _) = discover_game_containers(temporary.path()).unwrap();
        assert_eq!(game.len(), 2);
    }

    #[test]
    #[ignore = "requires OBR_TEST_LAYERED_MOD and OBR_TEST_GAME to point to private local fixtures"]
    fn probes_a_connected_game_with_real_retoc_package_stores() {
        let selected = PathBuf::from(std::env::var_os("OBR_TEST_LAYERED_MOD").unwrap());
        let game = PathBuf::from(std::env::var_os("OBR_TEST_GAME").unwrap());
        let report = probe_layered_iostore_dependencies(&selected, &[], &game).unwrap();
        assert_eq!(report.api, LAYERED_IOSTORE_DEPENDENCY_API);
        assert_eq!(report.logical_sha256.len(), 64);
        assert!(report.provider_count >= 3);
        assert!(
            report
                .layers
                .iter()
                .any(|layer| layer.layer == PackageProviderLayer::StockMain)
        );
    }
}
