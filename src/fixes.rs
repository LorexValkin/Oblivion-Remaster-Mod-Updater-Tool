use crate::retoc::{PackageEntry, PackageStoreEntry, RetocTool};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::Path;

pub const DEPENDENCY_TRACE_API: &str = "zen-dependency-trace-v1";
pub const DEPENDENCY_DIAGNOSTIC_API: &str = "zen-dependency-diagnostic-v1";
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
pub struct UnresolvedDependencyEdgeTrace {
    pub source_package_id: u64,
    pub source_package_path: String,
    pub missing_dependency_package_id: u64,
    /// Mounted package names spelled inside the consumer package's own Zen
    /// name map whose derived package ID equals the missing dependency ID.
    /// Empty whenever no hash-exact authored name was recovered; the field is
    /// evidence only and never resolves, drops, or rebinds the edge.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authored_package_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyDiagnosticReport {
    pub api: String,
    pub bundled_package_count: usize,
    pub current_game_package_count: usize,
    pub dependency_edge_count: usize,
    pub resolved_edge_count: usize,
    pub unresolved_edge_count: usize,
    pub bundled_edge_count: usize,
    pub current_game_edge_count: usize,
    pub fully_resolved: bool,
    pub resolved_edges: Vec<DependencyEdgeTrace>,
    pub unresolved_edges: Vec<UnresolvedDependencyEdgeTrace>,
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

fn normalized_package_path(path: &str) -> Result<String> {
    if path.is_empty() || path.contains('\0') || path.contains(':') {
        bail!("package path is empty or unsafe: {path}");
    }
    let replaced = path.replace('\\', "/");
    if replaced.starts_with('/') {
        bail!("package path is absolute: {path}");
    }
    let mut parts = Vec::new();
    let mut leading_parent_count = 0_usize;
    for part in replaced.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if !parts.is_empty() {
                bail!("package path traverses after its logical root: {path}");
            }
            leading_parent_count += 1;
            if leading_parent_count > 3 {
                bail!("package path exceeds the bounded Retoc mount prefix: {path}");
            }
            continue;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        bail!("package path is empty after normalization: {path}");
    }
    Ok(parts.join("/").to_ascii_lowercase())
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
        let path = normalized_package_path(&entry.path)?;
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
    let diagnostic = diagnose_package_dependencies(source, current_game)?;
    if let Some(unresolved) = diagnostic.unresolved_edges.first() {
        bail!(
            "package {} ({}) has unresolved dependency {} in both the bundled mod and current game",
            unresolved.source_package_path,
            unresolved.source_package_id,
            unresolved.missing_dependency_package_id
        );
    }
    Ok(DependencyTrace {
        api: DEPENDENCY_TRACE_API.to_owned(),
        source_package_count: diagnostic.bundled_package_count,
        dependency_edge_count: diagnostic.resolved_edge_count,
        bundled_edge_count: diagnostic.bundled_edge_count,
        current_game_edge_count: diagnostic.current_game_edge_count,
        edges: diagnostic.resolved_edges,
    })
}

pub fn diagnose_package_dependencies(
    source: &[PackageStoreEntry],
    current_game: &[PackageStoreEntry],
) -> Result<DependencyDiagnosticReport> {
    let source_by_id = index_package_store(source, "source dependency graph")?;
    let current_by_id = index_package_store(current_game, "current-game dependency graph")?;
    let mut resolved_edges = Vec::new();
    let mut unresolved_edges = Vec::new();
    for package in source {
        for dependency in &package.imported_package_ids {
            let resolved = source_by_id
                .get(dependency)
                .map(|target| (*target, DependencyOrigin::BundledMod))
                .or_else(|| {
                    current_by_id
                        .get(dependency)
                        .map(|target| (*target, DependencyOrigin::CurrentGame))
                });
            if let Some((target, origin)) = resolved {
                resolved_edges.push(DependencyEdgeTrace {
                    source_package_id: package.package_id,
                    source_package_path: package.path.clone(),
                    dependency_package_id: *dependency,
                    dependency_package_path: target.path.clone(),
                    origin,
                });
            } else {
                unresolved_edges.push(UnresolvedDependencyEdgeTrace {
                    source_package_id: package.package_id,
                    source_package_path: package.path.clone(),
                    missing_dependency_package_id: *dependency,
                    authored_package_names: Vec::new(),
                });
            }
        }
    }
    resolved_edges.sort_by(|left, right| {
        left.source_package_id
            .cmp(&right.source_package_id)
            .then(left.dependency_package_id.cmp(&right.dependency_package_id))
            .then(left.source_package_path.cmp(&right.source_package_path))
            .then(
                left.dependency_package_path
                    .cmp(&right.dependency_package_path),
            )
    });
    unresolved_edges.sort_by(|left, right| {
        left.source_package_id
            .cmp(&right.source_package_id)
            .then(
                left.missing_dependency_package_id
                    .cmp(&right.missing_dependency_package_id),
            )
            .then(left.source_package_path.cmp(&right.source_package_path))
    });
    let bundled_edge_count = resolved_edges
        .iter()
        .filter(|edge| edge.origin == DependencyOrigin::BundledMod)
        .count();
    let current_game_edge_count = resolved_edges.len() - bundled_edge_count;
    let resolved_edge_count = resolved_edges.len();
    let unresolved_edge_count = unresolved_edges.len();
    Ok(DependencyDiagnosticReport {
        api: DEPENDENCY_DIAGNOSTIC_API.to_owned(),
        bundled_package_count: source.len(),
        current_game_package_count: current_game.len(),
        dependency_edge_count: resolved_edge_count + unresolved_edge_count,
        resolved_edge_count,
        unresolved_edge_count,
        bundled_edge_count,
        current_game_edge_count,
        fully_resolved: unresolved_edges.is_empty(),
        resolved_edges,
        unresolved_edges,
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
    let extension = Path::new(parts.last().unwrap())
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !matches!(extension.to_ascii_lowercase().as_str(), "uasset" | "umap") {
        bail!("package filter path is not a UAsset or UMap: {path}");
    }
    let content_index = parts
        .iter()
        .position(|part| part.eq_ignore_ascii_case("Content"));
    if let Some(content_index) = content_index {
        if content_index > 1 || content_index + 1 >= parts.len() {
            bail!("package filter path has an unsupported mount layout: {path}");
        }
        Ok(parts.join("/"))
    } else {
        // Bare mount-root packages (../../../Leaf.uasset) have no Content
        // directory; they are only used as retoc --filter values, which match
        // by substring. The filename without extension is the safest filter.
        Ok((*parts.last().unwrap()).to_owned())
    }
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
        let bare_root = !package
            .path
            .replace('\\', "/")
            .split('/')
            .filter(|part| !part.is_empty() && *part != "." && *part != "..")
            .any(|part| part.eq_ignore_ascii_case("Content"));
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
        if failed != 0 || extracted == 0 {
            bail!(
                "{package_label} extracted no packages; extracted {extracted}, failed {failed}"
            );
        }
        // Bare mount-root packages (../../../Leaf.uasset) use a stem-only
        // filter that can match more than one entry; the composite migration
        // resolves them by package ID, so imprecise extraction is safe here.
        if !bare_root && extracted != 1 {
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
        if normalized_package_path(&source_package.path)?
            != normalized_package_path(&rebuilt_package.path)?
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
    fn diagnoses_every_dependency_edge_deterministically() {
        let source = vec![
            package(20, "../../../Content/Forms/B.uasset", &[99, 30]),
            package(10, "../../../Content/Forms/A.uasset", &[98, 30, 20]),
        ];
        let current = vec![package(
            30,
            "../../../OblivionRemastered/Content/Materials/M_A.uasset",
            &[],
        )];

        let report = diagnose_package_dependencies(&source, &current).unwrap();

        assert_eq!(report.api, DEPENDENCY_DIAGNOSTIC_API);
        assert_eq!(report.bundled_package_count, 2);
        assert_eq!(report.current_game_package_count, 1);
        assert_eq!(report.dependency_edge_count, 5);
        assert_eq!(report.resolved_edge_count, 3);
        assert_eq!(report.unresolved_edge_count, 2);
        assert_eq!(report.bundled_edge_count, 1);
        assert_eq!(report.current_game_edge_count, 2);
        assert!(!report.fully_resolved);
        assert_eq!(
            report
                .resolved_edges
                .iter()
                .map(|edge| (
                    edge.source_package_id,
                    edge.dependency_package_id,
                    &edge.origin
                ))
                .collect::<Vec<_>>(),
            vec![
                (10, 20, &DependencyOrigin::BundledMod),
                (10, 30, &DependencyOrigin::CurrentGame),
                (20, 30, &DependencyOrigin::CurrentGame),
            ]
        );
        assert_eq!(
            report
                .unresolved_edges
                .iter()
                .map(|edge| (
                    edge.source_package_id,
                    edge.missing_dependency_package_id,
                    edge.source_package_path.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                (10, 98, "../../../Content/Forms/A.uasset"),
                (20, 99, "../../../Content/Forms/B.uasset"),
            ]
        );
        assert!(
            report
                .unresolved_edges
                .iter()
                .all(|edge| edge.authored_package_names.is_empty())
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["api"], DEPENDENCY_DIAGNOSTIC_API);
        assert_eq!(json["unresolvedEdges"][0]["missingDependencyPackageId"], 98);
        assert!(
            json["unresolvedEdges"][0]
                .as_object()
                .unwrap()
                .get("authoredPackageNames")
                .is_none(),
            "unproven authored names must stay out of the serialized report"
        );

        let reordered = diagnose_package_dependencies(
            &[
                package(10, "../../../Content/Forms/A.uasset", &[20, 30, 98]),
                package(20, "../../../Content/Forms/B.uasset", &[30, 99]),
            ],
            &current,
        )
        .unwrap();
        assert_eq!(report, reordered);
    }

    #[test]
    fn dependency_diagnostic_fails_closed_on_duplicate_graph_entries() {
        let duplicate_id = diagnose_package_dependencies(
            &[
                package(10, "../../../Content/Forms/A.uasset", &[]),
                package(10, "../../../Content/Forms/B.uasset", &[]),
            ],
            &[],
        )
        .unwrap_err();
        assert!(duplicate_id.to_string().contains("repeats package ID 10"));

        let duplicate_path = diagnose_package_dependencies(
            &[],
            &[
                package(
                    20,
                    "../../../OblivionRemastered/Content/Materials/M_A.uasset",
                    &[],
                ),
                package(
                    30,
                    "..\\..\\..\\oblivionremastered\\content\\materials\\m_a.uasset",
                    &[],
                ),
            ],
        )
        .unwrap_err();
        assert!(duplicate_path.to_string().contains("repeats package path"));
    }

    #[test]
    fn dependency_diagnostic_rejects_unsafe_package_paths() {
        for path in [
            "../../../Content/Forms/../Unsafe.uasset",
            "../../../../Content/Forms/Unsafe.uasset",
            "/Content/Forms/Unsafe.uasset",
            "C:/Content/Forms/Unsafe.uasset",
        ] {
            assert!(
                diagnose_package_dependencies(&[package(10, path, &[])], &[]).is_err(),
                "unsafe package path was accepted: {path}"
            );
        }
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
