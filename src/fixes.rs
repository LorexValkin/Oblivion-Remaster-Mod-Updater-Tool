use crate::retoc::{PackageEntry, PackageStoreEntry, RetocTool};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::Path;

pub const DEPENDENCY_TRACE_API: &str = "zen-dependency-trace-v1";
pub const EXACT_DEPENDENCY_EXTRACTION_API: &str = "zen-exact-dependency-extraction-v1";
pub const DEPENDENCY_PRESERVATION_API: &str = "zen-dependency-preservation-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyOrigin {
    BundledMod,
    CurrentGame,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyEdgeTrace {
    pub source_package_id: u64,
    pub source_package_path: String,
    pub dependency_package_id: u64,
    pub dependency_package_path: String,
    pub origin: DependencyOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyTrace {
    pub api: String,
    pub source_package_count: usize,
    pub dependency_edge_count: usize,
    pub bundled_edge_count: usize,
    pub current_game_edge_count: usize,
    pub edges: Vec<DependencyEdgeTrace>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactExtractionReport {
    pub api: String,
    pub package_count: usize,
    pub filters: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyPreservationReport {
    pub api: String,
    pub package_count: usize,
    pub dependency_edge_count: usize,
    pub preserved: bool,
}

fn normalized_package_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("../")
        .trim_start_matches("./")
        .to_ascii_lowercase()
}

fn index_package_store<'a>(
    entries: &'a [PackageStoreEntry],
    label: &str,
) -> Result<HashMap<u64, &'a PackageStoreEntry>> {
    let mut by_id = HashMap::new();
    let mut paths = HashSet::new();
    for entry in entries {
        if by_id.insert(entry.package_id, entry).is_some() {
            bail!("{label} repeats package ID {}", entry.package_id);
        }
        let path = normalized_package_path(&entry.path);
        if !paths.insert(path) {
            bail!("{label} repeats package path {}", entry.path);
        }
    }
    Ok(by_id)
}

pub fn trace_package_dependencies(
    source: &[PackageStoreEntry],
    current_game: &[PackageStoreEntry],
) -> Result<DependencyTrace> {
    let source_by_id = index_package_store(source, "source dependency graph")?;
    let current_by_id = index_package_store(current_game, "current-game dependency graph")?;
    let mut edges = Vec::new();
    for package in source {
        for dependency in &package.imported_package_ids {
            let (target, origin) = if let Some(target) = source_by_id.get(dependency) {
                (*target, DependencyOrigin::BundledMod)
            } else if let Some(target) = current_by_id.get(dependency) {
                (*target, DependencyOrigin::CurrentGame)
            } else {
                bail!(
                    "package {} ({}) has unresolved dependency {} in both the bundled mod and current game",
                    package.path,
                    package.package_id,
                    dependency
                );
            };
            edges.push(DependencyEdgeTrace {
                source_package_id: package.package_id,
                source_package_path: package.path.clone(),
                dependency_package_id: *dependency,
                dependency_package_path: target.path.clone(),
                origin,
            });
        }
    }
    edges.sort_by(|left, right| {
        left.source_package_id
            .cmp(&right.source_package_id)
            .then(left.dependency_package_id.cmp(&right.dependency_package_id))
            .then(left.source_package_path.cmp(&right.source_package_path))
    });
    let bundled_edge_count = edges
        .iter()
        .filter(|edge| edge.origin == DependencyOrigin::BundledMod)
        .count();
    let current_game_edge_count = edges.len() - bundled_edge_count;
    Ok(DependencyTrace {
        api: DEPENDENCY_TRACE_API.to_owned(),
        source_package_count: source.len(),
        dependency_edge_count: edges.len(),
        bundled_edge_count,
        current_game_edge_count,
        edges,
    })
}

pub fn package_filter_path(path: &str) -> Result<String> {
    let normalized = path.replace('\\', "/");
    let mut parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .peekable();
    while parts.peek().is_some_and(|part| matches!(*part, "." | "..")) {
        parts.next();
    }
    let parts = parts.collect::<Vec<_>>();
    if parts.is_empty() || parts.iter().any(|part| matches!(*part, "." | "..")) {
        bail!("package filter path contains unresolved traversal: {path}");
    }
    let content_index = parts
        .iter()
        .position(|part| part.eq_ignore_ascii_case("Content"))
        .with_context(|| format!("package filter path has no Content root: {path}"))?;
    if content_index > 1 || content_index + 1 >= parts.len() {
        bail!("package filter path has an unsupported mount layout: {path}");
    }
    let extension = Path::new(parts.last().unwrap())
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !matches!(extension.to_ascii_lowercase().as_str(), "uasset" | "umap") {
        bail!("package filter path is not a UAsset or UMap: {path}");
    }
    Ok(parts.join("/"))
}

pub fn extract_packages_with_dependency_view(
    retoc: &RetocTool,
    dependency_view: &Path,
    output: &Path,
    packages: &[PackageEntry],
    label: &str,
) -> Result<ExactExtractionReport> {
    fs::create_dir_all(output)?;
    if fs::read_dir(output)?.next().is_some() {
        bail!("exact extraction output is not empty: {}", output.display());
    }
    let mut filters = Vec::with_capacity(packages.len());
    for package in packages {
        let filter = package_filter_path(&package.path)?;
        let result = retoc.run([
            OsString::from("to-legacy"),
            dependency_view.as_os_str().to_owned(),
            output.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
            OsString::from("--filter"),
            OsString::from(&filter),
        ])?;
        let package_label = format!("{label} {}", package.path);
        let (extracted, failed) = RetocTool::extraction_summary(&result, &package_label)?;
        if failed != 0 || extracted != 1 {
            bail!(
                "{package_label} expected exactly one package; extracted {extracted}, failed {failed}"
            );
        }
        filters.push(filter);
    }
    Ok(ExactExtractionReport {
        api: EXACT_DEPENDENCY_EXTRACTION_API.to_owned(),
        package_count: packages.len(),
        filters,
    })
}

pub fn verify_dependency_preservation(
    source: &[PackageStoreEntry],
    rebuilt: &[PackageStoreEntry],
) -> Result<DependencyPreservationReport> {
    let source_by_id = index_package_store(source, "source package store")?;
    let rebuilt_by_id = index_package_store(rebuilt, "rebuilt package store")?;
    let source_ids = source_by_id.keys().copied().collect::<BTreeSet<_>>();
    let rebuilt_ids = rebuilt_by_id.keys().copied().collect::<BTreeSet<_>>();
    if source_ids != rebuilt_ids {
        bail!(
            "rebuilt package IDs changed. Source: {:?}; rebuilt: {:?}",
            source_ids,
            rebuilt_ids
        );
    }
    let mut dependency_edge_count = 0;
    for package_id in source_ids {
        let source_package = source_by_id[&package_id];
        let rebuilt_package = rebuilt_by_id[&package_id];
        if normalized_package_path(&source_package.path)
            != normalized_package_path(&rebuilt_package.path)
        {
            bail!(
                "rebuilt package path changed for ID {package_id}: source {}, rebuilt {}",
                source_package.path,
                rebuilt_package.path
            );
        }
        let source_dependencies = source_package
            .imported_package_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let rebuilt_dependencies = rebuilt_package
            .imported_package_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if source_dependencies != rebuilt_dependencies {
            bail!(
                "rebuilt dependencies changed for {} ({}). Source: {:?}; rebuilt: {:?}",
                source_package.path,
                package_id,
                source_dependencies,
                rebuilt_dependencies
            );
        }
        dependency_edge_count += source_dependencies.len();
    }
    Ok(DependencyPreservationReport {
        api: DEPENDENCY_PRESERVATION_API.to_owned(),
        package_count: source.len(),
        dependency_edge_count,
        preserved: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(id: u64, path: &str, dependencies: &[u64]) -> PackageStoreEntry {
        PackageStoreEntry {
            package_id: id,
            path: path.to_owned(),
            imported_package_ids: dependencies.to_vec(),
        }
    }

    #[test]
    fn traces_bundled_and_current_game_dependency_edges() {
        let source = vec![
            package(10, "../../../Content/Forms/A.uasset", &[20, 30]),
            package(
                20,
                "../../../OblivionRemastered/Content/Art/SM_A.uasset",
                &[30],
            ),
        ];
        let current = vec![package(
            30,
            "../../../OblivionRemastered/Content/Materials/M_A.uasset",
            &[],
        )];

        let trace = trace_package_dependencies(&source, &current).unwrap();

        assert_eq!(trace.source_package_count, 2);
        assert_eq!(trace.dependency_edge_count, 3);
        assert_eq!(trace.bundled_edge_count, 1);
        assert_eq!(trace.current_game_edge_count, 2);
    }

    #[test]
    fn refuses_an_unresolved_dependency_edge() {
        let error = trace_package_dependencies(
            &[package(10, "../../../Content/Forms/A.uasset", &[99])],
            &[],
        )
        .unwrap_err();

        assert!(error.to_string().contains("unresolved dependency 99"));
    }

    #[test]
    fn detects_unknown_package_rewrites_after_rebuild() {
        let source = [package(
            10,
            "../../../OblivionRemastered/Content/Art/SM_A.uasset",
            &[30],
        )];
        let rebuilt = [package(
            10,
            "../../../OblivionRemastered/Content/Art/SM_A.uasset",
            &[8_312_870_539_305_733_357],
        )];

        let error = verify_dependency_preservation(&source, &rebuilt).unwrap_err();

        assert!(error.to_string().contains("rebuilt dependencies changed"));
    }

    #[test]
    fn verifies_an_unchanged_dependency_graph() {
        let source = [package(10, "../../../Content/Forms/A.uasset", &[20, 30])];
        let rebuilt = [package(10, "../../../Content/Forms/A.uasset", &[30, 20])];

        let report = verify_dependency_preservation(&source, &rebuilt).unwrap();

        assert!(report.preserved);
        assert_eq!(report.package_count, 1);
        assert_eq!(report.dependency_edge_count, 2);
    }

    #[test]
    fn normalizes_project_and_rootless_content_filters() {
        assert_eq!(
            package_filter_path("../../../OblivionRemastered/Content/Art/SM_A.uasset").unwrap(),
            "OblivionRemastered/Content/Art/SM_A.uasset"
        );
        assert_eq!(
            package_filter_path("../../../Content/Forms/A.uasset").unwrap(),
            "Content/Forms/A.uasset"
        );
    }
}
