use crate::archive::{MAX_ARCHIVE_ENTRIES, copy_tree, extract_archive, sha256_bytes};
use crate::fixes::{DependencyDiagnosticReport, diagnose_package_dependencies};
use crate::game::normalize_install_root;
use crate::retoc::{
    PackageEntry, PackageStoreEntry, RetocTool, game_package_names_for_ids, unreal_package_id,
};
use crate::uasset::{
    BlueprintAliasRoleEvidence, CompositePackageAssetKind, CompositePackageImportRepair,
    PackageIdentityAlias, TextureAssetDiagnostic, classify_composite_package_asset,
    create_package_identity_alias, inspect_static_mesh_asset, inspect_texture_asset,
    prove_blueprint_alias_role, repair_composite_skeletal_mesh_imports,
    repair_current_template_imports, repair_legacy_body_setups, repair_single_external_import,
    repair_static_mesh_imports, suppress_optional_blueprint_dependency,
    unresolved_package_store_dependencies, verify_identical_export_payloads,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

pub const ARMOR_REPLACEMENT_ADAPTER: &str = "native-armor-replacement-v1";
pub const MIXED_ARMOR_REPLACEMENT_ADAPTER: &str = "native-mixed-armor-expansion-v1";
pub const TEXTURE_REPLACEMENT_ADAPTER: &str = "native-texture-replacement-v1";
pub const ADDITIVE_STATIC_MESH_ADAPTER: &str = "native-static-mesh-v2";
pub const HETEROGENEOUS_REPLACEMENT_ADAPTER: &str = "native-heterogeneous-static-mesh-texture-v1";
pub const COMPOSITE_PACKAGE_REBASE_ADAPTER: &str = "native-composite-package-rebase-v2";
pub const MIXED_REPLACEMENT_PACKAGE_DIAGNOSTIC_API: &str =
    "zen-mixed-replacement-package-diagnostic-v1";
const MAX_REPLACEMENT_PACKAGES: usize = 4096;
const MAX_MIXED_REPLACEMENT_DIAGNOSTIC_PACKAGES: usize = MAX_ARCHIVE_ENTRIES;
const MAX_MIXED_REPLACEMENT_DIAGNOSTIC_DEPENDENCY_EDGES: usize = 1_000_000;
const ARMOR_PATH_PREFIX: &str = "oblivionremastered/content/art/armor/";
const ARMOR_FORM_PATH_PREFIX: &str = "oblivionremastered/content/forms/items/armor/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementScope {
    Armor,
    MixedArmor,
    Texture,
    AdditiveStaticMesh,
    HeterogeneousReplacement,
    CompositePackage,
}

#[derive(Clone, Debug)]
pub struct ReplacementContainer {
    pub name: String,
    pub utoc: PathBuf,
    pub ucas: PathBuf,
    pub pak: PathBuf,
    pub relative_utoc: PathBuf,
    pub packages: Vec<PackageEntry>,
    pub package_store: Vec<PackageStoreEntry>,
    /// Bare mount-root packages whose identity was resolved to a current-game
    /// package by unique package ID plus filename agreement. Recorded so every
    /// lane can disclose the resolution instead of silently treating the
    /// package as an exact-path replacement.
    pub root_alias_replacements: Vec<RootAliasPackageResolution>,
}

#[derive(Clone, Debug)]
pub struct RootAliasPackageResolution {
    pub package_id: u64,
    pub authored_path: String,
    pub current_path: String,
}

#[derive(Clone, Debug)]
pub struct ReplacementInspection {
    pub containers: Vec<ReplacementContainer>,
    pub packages: Vec<PackageEntry>,
    pub target_utoc: PathBuf,
    pub target_dependencies: HashMap<u64, PackageEntry>,
    pub target_package_imports: HashMap<u64, Vec<u64>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompositeIdentityAliasPlan {
    pub consumer_package_id: u64,
    pub consumer_package_path: String,
    pub source_package: PackageEntry,
    pub target_package: PackageEntry,
    pub expected_class: String,
    pub identity: PackageIdentityAlias,
    pub role: BlueprintAliasRoleEvidence,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompositeOptionalDependencySuppressionPlan {
    pub consumer_package_id: u64,
    pub consumer_package_path: String,
    pub temporary_source_package: PackageEntry,
    pub target_package: PackageEntry,
    pub expected_class: String,
    pub temporary_identity: PackageIdentityAlias,
    pub role: BlueprintAliasRoleEvidence,
}

#[derive(Clone, Debug)]
pub struct CompositeIdentityAliasProvider {
    pub provider_name: String,
    pub provider_utoc: PathBuf,
    pub provider_ucas: PathBuf,
    pub provider_pak: PathBuf,
    pub legacy_root: PathBuf,
    pub relative_utoc: PathBuf,
}

/// One stale dependency edge that is rebound to the current game revision by
/// its consumer's serialized-role donor repair instead of an identity alias.
/// The successor is never chosen from the retired package name: the consumer's
/// same-identity current-game donor decides it, and the import repair
/// hard-fails without donor class and serialized-role evidence.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompositeDonorRebindPlan {
    pub consumer_package_id: u64,
    pub consumer_package_path: String,
    pub target_package_id: u64,
    pub target_package_name: String,
    pub expected_class: String,
    pub evidence: String,
    pub policy: String,
}

#[derive(Clone, Debug)]
pub struct CompositeIdentityRecovery {
    /// Persistent alias provider container. Ships with the candidate because
    /// live rebuilt imports keep referencing its aliased identities.
    pub provider: Option<CompositeIdentityAliasProvider>,
    /// Rebuild-only provider for temporary optional-component identities.
    /// Mounted into extraction views so stale imports resolve during the
    /// dependency-complete rebuild, and never shipped: every suppression
    /// rewrites its consumer import to a bundled package before publication.
    pub temporary_provider: Option<CompositeIdentityAliasProvider>,
    pub aliases: Vec<CompositeIdentityAliasPlan>,
    pub suppressions: Vec<CompositeOptionalDependencySuppressionPlan>,
    pub donor_rebinds: Vec<CompositeDonorRebindPlan>,
}

#[derive(Clone, Debug)]
pub struct MixedArmorInspection {
    pub mesh: ReplacementInspection,
    pub companion_containers: Vec<ReplacementContainer>,
    pub packages: Vec<PackageEntry>,
    pub donor_packages: HashMap<u64, PackageEntry>,
    pub companion_dependency_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementProbeSummary {
    pub container_count: usize,
    pub package_count: usize,
    pub asset_kind: String,
    pub package_paths: Vec<String>,
    pub texture_assets: Vec<TextureAssetDiagnostic>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeterogeneousReplacementAssetKind {
    StaticMesh,
    Texture2D,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeterogeneousReplacementPackageProbe {
    pub package_id: u64,
    pub source_path: String,
    pub current_path: String,
    pub asset_kind: HeterogeneousReplacementAssetKind,
    pub imported_package_ids: Vec<u64>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeterogeneousReplacementProbeSummary {
    pub adapter: String,
    pub container_count: usize,
    pub package_count: usize,
    pub static_mesh_count: usize,
    pub texture_count: usize,
    pub packages: Vec<HeterogeneousReplacementPackageProbe>,
}

#[derive(Clone, Debug)]
pub(crate) enum ProvenHeterogeneousAsset {
    StaticMesh { imports: Vec<String> },
    Texture2D(TextureAssetDiagnostic),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixedReplacementIdentityStatus {
    ExactReplacement,
    /// The container stores this package at its mount root with no
    /// project/Content prefix, and the authoritative package ID matches
    /// exactly one current-game package whose filename also matches. The
    /// package ID is the load-time identity in IoStore, so this is an
    /// unambiguous replacement of that current package, disclosed separately
    /// from an exact path match.
    ExactReplacementViaRootAlias,
    Additive,
    PathConflict,
    PackageIdConflict,
    PathAndPackageIdConflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MixedReplacementContainerDiagnostic {
    pub name: String,
    pub relative_utoc: String,
    pub package_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MixedReplacementPackageDiagnostic {
    pub container: String,
    pub container_name: String,
    pub name: String,
    pub path: String,
    pub package_id: u64,
    pub imported_package_ids: Vec<u64>,
    pub identity_status: MixedReplacementIdentityStatus,
    pub current_path_match_package_id: Option<u64>,
    pub current_id_match_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MixedReplacementPackageDiagnosticReport {
    pub api: String,
    pub status: String,
    pub mutation_policy: String,
    pub automatic_update_enabled: bool,
    pub container_count: usize,
    pub source_package_count: usize,
    pub current_game_package_count: usize,
    pub exact_replacement_count: usize,
    pub root_alias_replacement_count: usize,
    pub additive_package_count: usize,
    pub conflict_package_count: usize,
    pub path_conflict_count: usize,
    pub package_id_conflict_count: usize,
    pub containers: Vec<MixedReplacementContainerDiagnostic>,
    pub packages: Vec<MixedReplacementPackageDiagnostic>,
    pub dependencies: DependencyDiagnosticReport,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
struct DiagnosticContainer {
    name: String,
    relative_utoc: String,
    package_store: Vec<PackageStoreEntry>,
}

pub fn stage_input(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    if source.is_dir() {
        copy_tree(source, destination)
    } else {
        extract_archive(source, destination)
    }
}

fn normalized_package_identity_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("../")
        .trim_start_matches("./")
        .trim_matches('/')
        .to_ascii_lowercase()
}

fn diagnostic_package_name(path: &str) -> String {
    path.replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_owned()
}

/// Recognizes a package stored directly at its container mount root: after
/// dropping leading traversal segments, exactly one UAsset/UMap filename must
/// remain with no directory or embedded traversal. Such a path carries no
/// project or Content location of its own, so it can only ever be resolved
/// through its authoritative package ID; anything else returns `None`.
fn bare_root_alias_leaf(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let mut segments = normalized
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .peekable();
    while segments.peek().is_some_and(|segment| *segment == "..") {
        segments.next();
    }
    let leaf = segments.next()?;
    if leaf == ".." || segments.next().is_some() {
        return None;
    }
    let lower = leaf.to_ascii_lowercase();
    if !(lower.ends_with(".uasset") || lower.ends_with(".umap")) {
        return None;
    }
    Some(leaf.to_owned())
}

/// Adapter-side counterpart of the mixed diagnostic's bare-root alias rule:
/// a package stored directly at its container mount root carries no location
/// of its own, so it is classified by its proven current identity — and only
/// then. The evidence is exactly the diagnostic's: the package ID must name
/// exactly one current package (a duplicated ID is ambiguous and disqualifies
/// itself) and the filenames must agree case-insensitively. Anything less
/// returns `None` so the caller keeps its original fail-closed rejection.
fn resolve_bare_root_package_identity(
    authored_path: &str,
    package_id: u64,
    current_store: &[PackageStoreEntry],
) -> Option<String> {
    let leaf = bare_root_alias_leaf(authored_path)?;
    let mut matches = current_store
        .iter()
        .filter(|entry| entry.package_id == package_id);
    let target = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    if !leaf.eq_ignore_ascii_case(&diagnostic_package_name(&target.path)) {
        return None;
    }
    Some(target.path.clone())
}

fn safe_diagnostic_candidate_root(candidate_root: Option<&str>) -> Result<PathBuf> {
    let Some(raw) = candidate_root else {
        return Ok(PathBuf::new());
    };
    let path = Path::new(raw);
    if raw.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        bail!("mixed replacement candidate root is not a safe relative path");
    }
    Ok(if raw == "." {
        PathBuf::new()
    } else {
        path.to_path_buf()
    })
}

#[derive(Default)]
struct DiagnosticTriple {
    pak: Option<PathBuf>,
    ucas: Option<PathBuf>,
    utoc: Option<PathBuf>,
}

fn discover_diagnostic_containers(
    root: &Path,
    retoc: &RetocTool,
) -> Result<Vec<DiagnosticContainer>> {
    if !root.is_dir() {
        bail!("mixed replacement candidate root is unavailable");
    }
    let mut triples = BTreeMap::<String, DiagnosticTriple>::new();
    let mut file_count = 0_usize;
    for entry in WalkDir::new(root) {
        let entry =
            entry.map_err(|_| anyhow::anyhow!("mixed replacement tree could not be read"))?;
        if entry.file_type().is_symlink() {
            bail!("mixed replacement input contains a filesystem link");
        }
        if !entry.file_type().is_file() {
            continue;
        }
        file_count += 1;
        if file_count > MAX_ARCHIVE_ENTRIES {
            bail!("mixed replacement input exceeds the bounded file limit");
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("mixed replacement file escaped its candidate root"))?;
        // Passive documentation is inert and must not abort the diagnostic;
        // the adapter-side container discovery applies the same allowance.
        if is_passive_documentation_path(relative) {
            continue;
        }
        let extension = relative
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "pak" | "ucas" | "utoc") {
            bail!(
                "mixed replacement input is not Unreal-container-only: {}",
                relative.to_string_lossy().replace('\\', "/")
            );
        }
        let key = relative
            .with_extension("")
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        let triple = triples.entry(key).or_default();
        let slot = match extension.as_str() {
            "pak" => &mut triple.pak,
            "ucas" => &mut triple.ucas,
            "utoc" => &mut triple.utoc,
            _ => unreachable!(),
        };
        if slot.replace(entry.path().to_path_buf()).is_some() {
            bail!("mixed replacement input repeats a container member");
        }
    }
    if triples.is_empty() {
        bail!("mixed replacement input contains no container triples");
    }

    let mut containers = Vec::with_capacity(triples.len());
    let mut package_count = 0_usize;
    for triple in triples.into_values() {
        let (Some(_pak), Some(_ucas), Some(utoc)) = (triple.pak, triple.ucas, triple.utoc) else {
            bail!("mixed replacement input contains an incomplete PAK/UCAS/UTOC triple");
        };
        let relative_utoc = utoc
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("mixed replacement UTOC escaped its candidate root"))?
            .to_string_lossy()
            .replace('\\', "/");
        let name = utoc
            .file_stem()
            .and_then(|value| value.to_str())
            .context("mixed replacement container name is not UTF-8")?
            .to_owned();
        retoc
            .verify(&utoc, "retoc verify mixed replacement source")
            .map_err(|_| {
                anyhow::anyhow!("mixed replacement container failed structural verification")
            })?;
        let (_, mut package_store) = retoc.package_store_entries(&utoc).map_err(|_| {
            anyhow::anyhow!("mixed replacement container package store could not be read")
        })?;
        package_store.sort_by(|left, right| {
            normalized_package_identity_path(&left.path)
                .cmp(&normalized_package_identity_path(&right.path))
                .then(left.package_id.cmp(&right.package_id))
        });
        package_count = package_count
            .checked_add(package_store.len())
            .context("mixed replacement package count overflow")?;
        if package_count > MAX_MIXED_REPLACEMENT_DIAGNOSTIC_PACKAGES {
            bail!(
                "mixed replacement package inventory exceeds the bounded diagnostic package limit"
            );
        }
        containers.push(DiagnosticContainer {
            name,
            relative_utoc,
            package_store,
        });
    }
    Ok(containers)
}

fn build_mixed_replacement_diagnostic_report(
    mut containers: Vec<DiagnosticContainer>,
    current: Vec<PackageStoreEntry>,
) -> Result<MixedReplacementPackageDiagnosticReport> {
    containers.sort_by(|left, right| {
        left.relative_utoc
            .to_ascii_lowercase()
            .cmp(&right.relative_utoc.to_ascii_lowercase())
    });
    let source = containers
        .iter()
        .flat_map(|container| container.package_store.iter().cloned())
        .collect::<Vec<_>>();
    if source.is_empty() || source.len() > MAX_MIXED_REPLACEMENT_DIAGNOSTIC_PACKAGES {
        bail!("mixed replacement diagnostic source package count is outside its bounded limit");
    }
    let dependency_edge_count = source.iter().try_fold(0_usize, |count, package| {
        count
            .checked_add(package.imported_package_ids.len())
            .context("mixed replacement dependency edge count overflow")
    })?;
    if dependency_edge_count > MAX_MIXED_REPLACEMENT_DIAGNOSTIC_DEPENDENCY_EDGES {
        bail!("mixed replacement dependency graph exceeds the bounded edge limit");
    }

    // This validates unique package IDs and normalized paths in both stores before
    // any identity result is emitted, and retains every unresolved edge in its report.
    let dependencies = diagnose_package_dependencies(&source, &current)?;
    let current_by_id = current
        .iter()
        .map(|package| (package.package_id, package))
        .collect::<HashMap<_, _>>();
    let current_by_path = current
        .iter()
        .map(|package| (normalized_package_identity_path(&package.path), package))
        .collect::<HashMap<_, _>>();

    let mut packages = Vec::with_capacity(source.len());
    for container in &containers {
        for package in &container.package_store {
            let current_id_match = current_by_id.get(&package.package_id).copied();
            let current_path_match = current_by_path
                .get(&normalized_package_identity_path(&package.path))
                .copied();
            let identity_status = match (current_id_match, current_path_match) {
                (Some(by_id), Some(by_path))
                    if by_id.package_id == by_path.package_id
                        && normalized_package_identity_path(&by_id.path)
                            == normalized_package_identity_path(&package.path) =>
                {
                    MixedReplacementIdentityStatus::ExactReplacement
                }
                (None, None) => MixedReplacementIdentityStatus::Additive,
                (None, Some(_)) => MixedReplacementIdentityStatus::PathConflict,
                (Some(by_id), None) => {
                    // Both package stores were already validated to hold unique
                    // package IDs, so `by_id` is the only current package this
                    // ID can name. A mount-root file whose filename also
                    // matches that package is an unambiguous identity alias;
                    // any other ID-only match stays a fail-closed conflict.
                    if bare_root_alias_leaf(&package.path).is_some_and(|leaf| {
                        leaf.eq_ignore_ascii_case(&diagnostic_package_name(&by_id.path))
                    }) {
                        MixedReplacementIdentityStatus::ExactReplacementViaRootAlias
                    } else {
                        MixedReplacementIdentityStatus::PackageIdConflict
                    }
                }
                (Some(_), Some(_)) => MixedReplacementIdentityStatus::PathAndPackageIdConflict,
            };
            let mut imported_package_ids = package.imported_package_ids.clone();
            imported_package_ids.sort_unstable();
            packages.push(MixedReplacementPackageDiagnostic {
                container: container.relative_utoc.clone(),
                container_name: container.name.clone(),
                name: diagnostic_package_name(&package.path),
                path: package.path.clone(),
                package_id: package.package_id,
                imported_package_ids,
                identity_status,
                current_path_match_package_id: current_path_match.map(|target| target.package_id),
                current_id_match_path: current_id_match.map(|target| target.path.clone()),
            });
        }
    }
    packages.sort_by(|left, right| {
        normalized_package_identity_path(&left.path)
            .cmp(&normalized_package_identity_path(&right.path))
            .then(left.package_id.cmp(&right.package_id))
            .then(
                left.container
                    .to_ascii_lowercase()
                    .cmp(&right.container.to_ascii_lowercase()),
            )
    });

    let exact_replacement_count = packages
        .iter()
        .filter(|package| {
            package.identity_status == MixedReplacementIdentityStatus::ExactReplacement
        })
        .count();
    let additive_package_count = packages
        .iter()
        .filter(|package| package.identity_status == MixedReplacementIdentityStatus::Additive)
        .count();
    let path_conflict_count = packages
        .iter()
        .filter(|package| {
            matches!(
                package.identity_status,
                MixedReplacementIdentityStatus::PathConflict
                    | MixedReplacementIdentityStatus::PathAndPackageIdConflict
            )
        })
        .count();
    let package_id_conflict_count = packages
        .iter()
        .filter(|package| {
            matches!(
                package.identity_status,
                MixedReplacementIdentityStatus::PackageIdConflict
                    | MixedReplacementIdentityStatus::PathAndPackageIdConflict
            )
        })
        .count();
    let root_alias_replacement_count = packages
        .iter()
        .filter(|package| {
            package.identity_status == MixedReplacementIdentityStatus::ExactReplacementViaRootAlias
        })
        .count();
    let conflict_package_count = packages
        .iter()
        .filter(|package| {
            !matches!(
                package.identity_status,
                MixedReplacementIdentityStatus::ExactReplacement
                    | MixedReplacementIdentityStatus::ExactReplacementViaRootAlias
                    | MixedReplacementIdentityStatus::Additive
            )
        })
        .count();
    let mut blockers = Vec::new();
    if additive_package_count > 0 {
        blockers.push(format!(
            "additive-source-packages-require-a-separate-contract:found-{additive_package_count}"
        ));
    }
    if conflict_package_count > 0 {
        blockers.push(format!(
            "source-package-identity-conflicts-with-current-game:found-{conflict_package_count}"
        ));
    }
    if dependencies.unresolved_edge_count > 0 {
        blockers.push(format!(
            "unresolved-source-package-dependencies:found-{}",
            dependencies.unresolved_edge_count
        ));
    }
    let container_rows = containers
        .iter()
        .map(|container| MixedReplacementContainerDiagnostic {
            name: container.name.clone(),
            relative_utoc: container.relative_utoc.clone(),
            package_count: container.package_store.len(),
        })
        .collect::<Vec<_>>();
    // Disclose every root-alias identity resolution: the reader must be able
    // to see that the container path carried no location and that only the
    // unique package ID (plus filename agreement) named the current target.
    let mut warnings = packages
        .iter()
        .filter(|package| {
            package.identity_status == MixedReplacementIdentityStatus::ExactReplacementViaRootAlias
        })
        .map(|package| {
            format!(
                "Container '{}' stores {} at its mount root with no project/Content path; its package ID {} uniquely matches current package {} and the filenames agree, so it is classified as a replacement of that package via root alias.",
                package.container_name,
                package.path,
                package.package_id,
                package
                    .current_id_match_path
                    .as_deref()
                    .unwrap_or("<unavailable>"),
            )
        })
        .collect::<Vec<_>>();
    warnings.extend([
        "Current identity and external dependency evidence comes from the connected game's stock main package store; installed-mod and other-container precedence is not claimed."
            .to_owned(),
        "Package identity and dependency closure do not prove export-class conversion, shader compatibility, gameplay behavior, or runtime compatibility."
            .to_owned(),
        "This diagnostic cannot enable an updater adapter or mutate source, game, or output files."
            .to_owned(),
    ]);
    Ok(MixedReplacementPackageDiagnosticReport {
        api: MIXED_REPLACEMENT_PACKAGE_DIAGNOSTIC_API.to_owned(),
        status: if blockers.is_empty() {
            "complete-report-only"
        } else {
            "blocked"
        }
        .to_owned(),
        mutation_policy: "report-only".to_owned(),
        automatic_update_enabled: false,
        container_count: container_rows.len(),
        source_package_count: packages.len(),
        current_game_package_count: current.len(),
        exact_replacement_count,
        root_alias_replacement_count,
        additive_package_count,
        conflict_package_count,
        path_conflict_count,
        package_id_conflict_count,
        containers: container_rows,
        packages,
        dependencies,
        blockers,
        warnings,
    })
}

/// Stages an Unreal-container-only input and compares its complete package-store
/// inventory with the current game. This diagnostic is read-only and can never
/// authorize or perform an update.
pub fn diagnose_mixed_replacement_input(
    mod_input: &Path,
    candidate_root: Option<&str>,
    current_game_root: &Path,
) -> Result<MixedReplacementPackageDiagnosticReport> {
    let candidate_root = safe_diagnostic_candidate_root(candidate_root)?;
    let work = tempfile::Builder::new()
        .prefix("obr-mixed-replacement-diagnostic-")
        .tempdir()?;
    let staged = work.path().join("input");
    stage_input(mod_input, &staged)
        .map_err(|_| anyhow::anyhow!("mixed replacement input could not be staged safely"))?;
    let retoc = RetocTool::materialize()?;
    let containers = discover_diagnostic_containers(&staged.join(candidate_root), &retoc)?;
    let game_root = normalize_install_root(current_game_root);
    let stock_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    if !stock_utoc.is_file() {
        bail!("current game stock package store is unavailable");
    }
    let (_, current) = retoc
        .package_store_entries(&stock_utoc)
        .map_err(|_| anyhow::anyhow!("current game package store could not be read"))?;
    build_mixed_replacement_diagnostic_report(containers, current)
}

pub(crate) fn canonical_package_path(raw: &str) -> Result<String> {
    let path = raw.replace('\\', "/");
    let lower = path.to_ascii_lowercase();
    let marker = "oblivionremastered/content/";
    let offset = lower
        .find(marker)
        .with_context(|| format!("package path is outside OblivionRemastered content: {raw}"))?;
    let canonical = path[offset..].trim_matches('/').to_owned();
    if canonical.split('/').any(|segment| segment == "..") {
        bail!("package path contains traversal after normalization: {raw}");
    }
    Ok(canonical)
}
pub(crate) fn canonical_additive_static_mesh_path(raw: &str) -> Result<String> {
    let normalized = raw.replace('\\', "/");
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .skip_while(|part| *part == "..")
        .collect::<Vec<_>>();
    if parts.len() < 3 || !parts[1].eq_ignore_ascii_case("Content") || parts.contains(&"..") {
        bail!("StaticMesh candidate must use a <Project>/Content path without traversal: {raw}");
    }
    let path = parts.join("/");
    let leaf = path.rsplit('/').next().unwrap_or_default();
    if !leaf.to_ascii_lowercase().ends_with(".uasset") {
        bail!("StaticMesh candidate must be a UAsset: {raw}");
    }
    Ok(path)
}

fn canonical_composite_source_path(raw: &str) -> Result<String> {
    if let Ok(path) = canonical_additive_static_mesh_path(raw) {
        return Ok(path);
    }
    let normalized = raw.replace('\\', "/");
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>();
    if parts.len() != 1 || !parts[0].to_ascii_lowercase().ends_with(".uasset") {
        bail!(
            "composite package must use a <Project>/Content path or a single package-root alias: {raw}"
        );
    }
    Ok(parts[0].to_owned())
}

pub(crate) fn source_static_mesh_package_filter(source_package: &PackageEntry) -> Result<String> {
    // Retoc filters are case-sensitive, so source-container extraction must use
    // the exact spelling recorded by the source package store. Package identity
    // is validated separately before extraction; a current-game spelling must
    // never be substituted here.
    Ok(canonical_additive_static_mesh_path(&source_package.path)?
        .trim_end_matches(".uasset")
        .to_owned())
}

pub(crate) fn source_package_store_filter(source_package: &PackageEntry) -> Result<String> {
    Ok(canonical_additive_static_mesh_path(&source_package.path)?
        .trim_end_matches(".uasset")
        .to_owned())
}
fn package_key(path: &str) -> Result<String> {
    Ok(canonical_package_path(path)?.to_ascii_lowercase())
}

fn is_armor_skeletal_mesh(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.starts_with(ARMOR_PATH_PREFIX) || !lower.ends_with(".uasset") {
        return false;
    }
    lower
        .rsplit('/')
        .next()
        .is_some_and(|leaf| leaf.starts_with("sk_"))
}

fn is_skeletal_mesh_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.starts_with("oblivionremastered/content/art/") || !lower.ends_with(".uasset") {
        return false;
    }
    lower
        .rsplit('/')
        .next()
        .is_some_and(|leaf| leaf.starts_with("sk_"))
}

fn is_passive_documentation_path(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "txt" | "md" | "rtf" | "pdf" | "png" | "jpg" | "jpeg" | "gif" | "webp"
    ) || matches!(
        file_name.as_str(),
        "readme" | "license" | "licence" | "notice" | "changelog"
    )
}

fn is_texture_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("oblivionremastered/content/") && lower.ends_with(".uasset")
}

fn is_armor_form_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with(ARMOR_FORM_PATH_PREFIX) && lower.ends_with(".uasset")
}

/// Discovery without a current-game package store: bare mount-root packages
/// have no resolvable identity here and keep their original fail-closed
/// canonicalization rejection.
#[cfg(test)]
fn discover_containers(
    root: &Path,
    retoc: &RetocTool,
    scope: ReplacementScope,
) -> Result<Vec<ReplacementContainer>> {
    discover_containers_with_current(root, retoc, scope, || {
        bail!("no current package store is available for bare-root alias resolution")
    })
}

fn discover_containers_with_current<F>(
    root: &Path,
    retoc: &RetocTool,
    scope: ReplacementScope,
    load_current_store: F,
) -> Result<Vec<ReplacementContainer>>
where
    F: Fn() -> Result<Vec<PackageStoreEntry>>,
{
    let mut files = Vec::new();
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "replacement input contains a filesystem link: {}",
                entry.path().display()
            );
        }
        if entry.file_type().is_file() && !is_passive_documentation_path(entry.path()) {
            files.push(entry.path().to_path_buf());
        }
    }
    if files.is_empty() {
        bail!("replacement input contains no files");
    }
    for file in &files {
        let extension = file
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "pak" | "ucas" | "utoc") {
            bail!(
                "armor replacement adapter accepts only complete PAK/UCAS/UTOC triples; found {}",
                file.display()
            );
        }
    }

    let mut utocs = files
        .iter()
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("utoc"))
        })
        .cloned()
        .collect::<Vec<_>>();
    utocs.sort();
    if utocs.is_empty() || files.len() != utocs.len() * 3 {
        bail!("armor replacement input does not contain only complete container triples");
    }

    let mut names = HashSet::new();
    let mut containers = Vec::new();
    // The current store is loaded at most once per discovery, and only when a
    // bare mount-root package actually needs identity resolution.
    let mut current_store_cache: Option<Option<Vec<PackageStoreEntry>>> = None;
    for utoc in utocs {
        let name = utoc
            .file_stem()
            .and_then(|value| value.to_str())
            .context("replacement UTOC filename is not UTF-8")?
            .to_owned();
        if !name.to_ascii_lowercase().ends_with("_p") {
            bail!("replacement container must use an override _P suffix: {name}");
        }
        if !names.insert(name.to_ascii_lowercase()) {
            bail!("duplicate replacement container name: {name}");
        }
        let ucas = utoc.with_extension("ucas");
        let pak = utoc.with_extension("pak");
        if !ucas.is_file() || !pak.is_file() {
            bail!("replacement container {name} is missing its UCAS or PAK partner");
        }
        retoc.verify(&utoc, &format!("retoc verify replacement source {name}"))?;
        let (_, mut package_store) = retoc.package_store_entries(&utoc)?;
        let canonicalize = |path: &str| match scope {
            ReplacementScope::AdditiveStaticMesh | ReplacementScope::HeterogeneousReplacement => {
                canonical_additive_static_mesh_path(path)
            }
            ReplacementScope::CompositePackage => canonical_composite_source_path(path),
            _ => canonical_package_path(path),
        };
        let mut root_alias_replacements = Vec::new();
        for package in &mut package_store {
            package.path = match canonicalize(&package.path) {
                Ok(path) => path,
                Err(error) => {
                    // Bare mount-root packages carry no location of their own.
                    // The mixed diagnostic already classifies them by unique
                    // package ID plus filename agreement; the adapter-side
                    // canonicalization applies the same evidence rule here,
                    // records the resolution for disclosure, and keeps the
                    // original rejection for anything unproven. The composite
                    // scope's canonicalizer accepts bare roots itself and
                    // never reaches this branch for them.
                    let resolved = current_store_cache
                        .get_or_insert_with(|| load_current_store().ok())
                        .as_deref()
                        .and_then(|current_store| {
                            resolve_bare_root_package_identity(
                                &package.path,
                                package.package_id,
                                current_store,
                            )
                        });
                    let Some(canonical_current) =
                        resolved.and_then(|current_path| canonicalize(&current_path).ok())
                    else {
                        return Err(error);
                    };
                    root_alias_replacements.push(RootAliasPackageResolution {
                        package_id: package.package_id,
                        authored_path: package.path.clone(),
                        current_path: canonical_current.clone(),
                    });
                    canonical_current
                }
            };
            match scope {
                ReplacementScope::Armor if !is_skeletal_mesh_candidate(&package.path) => {
                    bail!(
                        "skeletal-mesh replacement adapter only accepts existing SK_ packages under /Content/Art: {}",
                        package.path
                    );
                }
                ReplacementScope::MixedArmor
                    if !is_armor_skeletal_mesh(&package.path)
                        && !is_armor_form_candidate(&package.path) =>
                {
                    bail!(
                        "mixed armor adapter accepts only SK_ mesh packages under /Content/Art/armor and companion packages under /Content/Forms/items/armor: {}",
                        package.path
                    );
                }
                ReplacementScope::Texture if !is_texture_candidate(&package.path) => {
                    bail!(
                        "texture replacement adapter accepts only UAsset packages under /Content pending structural Texture2D verification: {}",
                        package.path
                    );
                }
                ReplacementScope::AdditiveStaticMesh => {}
                ReplacementScope::HeterogeneousReplacement => {}
                ReplacementScope::CompositePackage => {}
                _ => {}
            }
        }
        let packages = package_store
            .iter()
            .map(|entry| PackageEntry {
                package_id: entry.package_id,
                path: entry.path.clone(),
            })
            .collect();
        containers.push(ReplacementContainer {
            relative_utoc: utoc.strip_prefix(root)?.to_path_buf(),
            name,
            utoc,
            ucas,
            pak,
            packages,
            package_store,
            root_alias_replacements,
        });
    }
    Ok(containers)
}

fn unique_container_parent(root: &Path) -> Result<PathBuf> {
    let mut parents = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("utoc"))
        })
        .filter_map(|entry| entry.path().parent().map(Path::to_path_buf))
        .collect::<Vec<_>>();
    parents.sort();
    parents.dedup();
    if parents.len() != 1 {
        bail!(
            "composite input requires every container triple in one physical folder; found {} folders",
            parents.len()
        );
    }
    Ok(parents.remove(0))
}

fn inspect_staged_for_scope(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
    scope: ReplacementScope,
) -> Result<ReplacementInspection> {
    let target_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    let containers = discover_containers_with_current(root, retoc, scope, || {
        Ok(retoc.package_store_entries(&target_utoc)?.1)
    })?;
    let mut packages = containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    if packages.len() > MAX_REPLACEMENT_PACKAGES {
        bail!(
            "armor replacement contains {} packages; adapter limit is {}",
            packages.len(),
            MAX_REPLACEMENT_PACKAGES
        );
    }
    packages.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
    });
    for pair in packages.windows(2) {
        if pair[0].path.eq_ignore_ascii_case(&pair[1].path) {
            bail!(
                "armor replacement package appears in multiple containers: {}",
                pair[0].path
            );
        }
    }

    if !target_utoc.is_file() {
        bail!(
            "current game package inventory is missing: {}",
            target_utoc.display()
        );
    }
    let (_, target_entries) = retoc.package_store_entries(&target_utoc)?;
    let target_packages = target_entries
        .iter()
        .cloned()
        .filter_map(|entry| package_key(&entry.path).ok().map(|key| (key, entry)))
        .collect::<HashMap<_, _>>();
    let target_by_id = target_entries
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let mut target_package_imports = HashMap::new();
    let mut required_dependency_ids = containers
        .iter()
        .flat_map(|container| container.package_store.iter())
        .flat_map(|entry| entry.imported_package_ids.iter().copied())
        .collect::<HashSet<_>>();
    for package in &packages {
        let key = package_key(&package.path)?;
        let target = target_packages.get(&key).with_context(|| {
            format!(
                "armor package is an addition, not a replacement: {}",
                package.path
            )
        })?;
        if target.package_id != package.package_id {
            bail!(
                "current game package ID changed for {}: mod {}, game {}",
                package.path,
                package.package_id,
                target.package_id
            );
        }
        target_package_imports.insert(package.package_id, target.imported_package_ids.clone());
        required_dependency_ids.extend(target.imported_package_ids.iter().copied());
    }
    let target_dependencies = required_dependency_ids
        .into_iter()
        .filter_map(|package_id| {
            target_by_id.get(&package_id).map(|entry| {
                (
                    package_id,
                    PackageEntry {
                        package_id,
                        path: entry.path.clone(),
                    },
                )
            })
        })
        .collect();

    Ok(ReplacementInspection {
        containers,
        packages,
        target_utoc,
        target_dependencies,
        target_package_imports,
    })
}

pub fn inspect_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<ReplacementInspection> {
    inspect_staged_for_scope(root, game_root, retoc, ReplacementScope::Armor)
}

fn sibling_donor_paths(path: &str) -> Result<Vec<String>> {
    let canonical = canonical_package_path(path)?;
    let lower = canonical.to_ascii_lowercase();
    if !lower.ends_with("_f.uasset") {
        bail!(
            "additive armor package has no guarded current-game donor rule (expected an _f skeletal mesh): {canonical}"
        );
    }
    let base = canonical[..canonical.len() - "_f.uasset".len()].to_owned();
    Ok(vec![format!("{base}_m.uasset"), format!("{base}.uasset")])
}

pub fn inspect_mixed_armor_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<MixedArmorInspection> {
    let target_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    let containers =
        discover_containers_with_current(root, retoc, ReplacementScope::MixedArmor, || {
            Ok(retoc.package_store_entries(&target_utoc)?.1)
        })?;
    let mut packages = containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    if packages.len() > MAX_REPLACEMENT_PACKAGES {
        bail!(
            "mixed armor input contains {} packages; adapter limit is {}",
            packages.len(),
            MAX_REPLACEMENT_PACKAGES
        );
    }
    packages.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
    });
    for pair in packages.windows(2) {
        if pair[0].path.eq_ignore_ascii_case(&pair[1].path) {
            bail!(
                "mixed armor package appears in multiple containers: {}",
                pair[0].path
            );
        }
    }

    let mut mesh_containers = Vec::new();
    let mut companion_containers = Vec::new();
    for container in containers {
        let mesh_count = container
            .packages
            .iter()
            .filter(|package| is_armor_skeletal_mesh(&package.path))
            .count();
        let companion_count = container
            .packages
            .iter()
            .filter(|package| is_armor_form_candidate(&package.path))
            .count();
        if mesh_count == container.packages.len() {
            mesh_containers.push(container);
        } else if companion_count == container.packages.len() {
            companion_containers.push(container);
        } else {
            bail!(
                "mixed armor container {} combines mesh and companion packages; this layout remains report-only",
                container.name
            );
        }
    }
    if mesh_containers.is_empty() || companion_containers.is_empty() {
        bail!(
            "mixed armor adapter requires separate mesh and /Forms/items/armor companion containers"
        );
    }

    if !target_utoc.is_file() {
        bail!(
            "current game package inventory is missing: {}",
            target_utoc.display()
        );
    }
    let (_, target_entries) = retoc.package_store_entries(&target_utoc)?;
    let target_packages = target_entries
        .iter()
        .cloned()
        .filter_map(|entry| package_key(&entry.path).ok().map(|key| (key, entry)))
        .collect::<HashMap<_, _>>();
    let target_by_id = target_entries
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let mod_package_ids = packages
        .iter()
        .map(|package| package.package_id)
        .collect::<HashSet<_>>();

    let mut companion_dependency_ids = HashSet::new();
    for container in &companion_containers {
        for package in &container.package_store {
            let current = target_packages
                .get(&package_key(&package.path)?)
                .with_context(|| {
                    format!(
                        "companion armor package is an addition, not a current form replacement: {}",
                        package.path
                    )
                })?;
            if current.package_id != package.package_id {
                bail!(
                    "current game package ID changed for companion {}: mod {}, game {}",
                    package.path,
                    package.package_id,
                    current.package_id
                );
            }
            for dependency in &package.imported_package_ids {
                if !mod_package_ids.contains(dependency) && !target_by_id.contains_key(dependency) {
                    bail!(
                        "companion package {} has unresolved external dependency {}; custom companion dependencies must be bundled or present in the current game",
                        package.path,
                        dependency
                    );
                }
                companion_dependency_ids.insert(*dependency);
            }
        }
    }

    let mesh_packages = mesh_containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    let mut donor_packages = HashMap::new();
    let mut target_package_imports = HashMap::new();
    let mut required_dependency_ids = HashSet::new();
    for package in &mesh_packages {
        let source_key = package_key(&package.path)?;
        let donor = if let Some(current) = target_packages.get(&source_key) {
            if current.package_id != package.package_id {
                bail!(
                    "current game package ID changed for {}: mod {}, game {}",
                    package.path,
                    package.package_id,
                    current.package_id
                );
            }
            current.clone()
        } else {
            let candidates = sibling_donor_paths(&package.path)?
                .into_iter()
                .filter_map(|candidate| {
                    package_key(&candidate)
                        .ok()
                        .and_then(|key| target_packages.get(&key).cloned())
                })
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                bail!(
                    "additive armor package {} requires exactly one current-game sibling donor (_m or unsuffixed); found {}",
                    package.path,
                    candidates.len()
                );
            }
            candidates[0].clone()
        };
        target_package_imports.insert(package.package_id, donor.imported_package_ids.clone());
        required_dependency_ids.extend(donor.imported_package_ids.iter().copied());
        let donor_path = canonical_package_path(&donor.path)?.to_ascii_lowercase();
        let donor_directory = donor_path
            .rsplit_once('/')
            .map(|(directory, _)| directory)
            .context("current armor donor path has no package directory")?;
        required_dependency_ids.extend(target_entries.iter().filter_map(|entry| {
            let path = canonical_package_path(&entry.path)
                .ok()?
                .to_ascii_lowercase();
            let (directory, leaf) = path.rsplit_once('/')?;
            (directory == donor_directory && leaf.starts_with("mic_") && leaf.ends_with(".uasset"))
                .then_some(entry.package_id)
        }));
        donor_packages.insert(
            package.package_id,
            PackageEntry {
                package_id: donor.package_id,
                path: donor.path.clone(),
            },
        );
    }
    let target_dependencies = required_dependency_ids
        .into_iter()
        .filter_map(|package_id| {
            target_by_id.get(&package_id).map(|entry| {
                (
                    package_id,
                    PackageEntry {
                        package_id,
                        path: entry.path.clone(),
                    },
                )
            })
        })
        .collect();

    Ok(MixedArmorInspection {
        mesh: ReplacementInspection {
            containers: mesh_containers,
            packages: mesh_packages,
            target_utoc,
            target_dependencies,
            target_package_imports,
        },
        companion_containers,
        packages,
        donor_packages,
        companion_dependency_count: companion_dependency_ids.len(),
    })
}

pub fn inspect_texture_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<ReplacementInspection> {
    let inspection = inspect_staged_for_scope(root, game_root, retoc, ReplacementScope::Texture)?;
    for container in &inspection.containers {
        for package in &container.package_store {
            if !package.imported_package_ids.is_empty() {
                bail!(
                    "Texture2D replacement {} declares imported packages; mixed material/blueprint dependency closures remain report-only",
                    package.path
                );
            }
        }
    }
    for package in &inspection.packages {
        let current_imports = inspection
            .target_package_imports
            .get(&package.package_id)
            .with_context(|| {
                format!(
                    "current texture import inventory is missing {}",
                    package.path
                )
            })?;
        if !current_imports.is_empty() {
            bail!(
                "current Texture2D target {} declares imported packages; this is not a pure texture payload",
                package.path
            );
        }
    }
    Ok(inspection)
}

pub fn inspect_additive_static_mesh_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<ReplacementInspection> {
    let target_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    let containers =
        discover_containers_with_current(root, retoc, ReplacementScope::AdditiveStaticMesh, || {
            Ok(retoc.package_store_entries(&target_utoc)?.1)
        })?;
    let mut packages = containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    if packages.is_empty() || packages.len() > MAX_REPLACEMENT_PACKAGES {
        bail!("StaticMesh input must contain 1..={MAX_REPLACEMENT_PACKAGES} packages");
    }
    packages.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
    });
    for pair in packages.windows(2) {
        if pair[0].path.eq_ignore_ascii_case(&pair[1].path)
            || pair[0].package_id == pair[1].package_id
        {
            bail!("StaticMesh packages must have unique paths and package IDs");
        }
    }

    let (_, target_entries) = retoc.package_store_entries(&target_utoc)?;
    let target_by_id = target_entries
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let target_by_path = target_entries
        .iter()
        .filter_map(|entry| {
            canonical_additive_static_mesh_path(&entry.path)
                .ok()
                .map(|path| (path.to_ascii_lowercase(), entry))
        })
        .collect::<HashMap<_, _>>();
    let source_ids = packages
        .iter()
        .map(|package| package.package_id)
        .collect::<HashSet<_>>();
    let target_dependencies = target_entries
        .iter()
        .map(|entry| {
            (
                entry.package_id,
                PackageEntry {
                    package_id: entry.package_id,
                    path: entry.path.clone(),
                },
            )
        })
        .collect::<HashMap<_, _>>();
    let mut target_package_imports = HashMap::new();

    // Package identity, not a project or filename convention, decides whether
    // this is an existing-game replacement or an additive package.
    for package in &packages {
        let canonical = canonical_additive_static_mesh_path(&package.path)?;
        if let Some(target) = target_by_path.get(&canonical.to_ascii_lowercase()) {
            if target.package_id != package.package_id {
                bail!(
                    "current game package ID changed for {}: mod {}, game {}",
                    package.path,
                    package.package_id,
                    target.package_id
                );
            }
            target_package_imports.insert(package.package_id, target.imported_package_ids.clone());
        } else if let Some(target) = target_by_id.get(&package.package_id) {
            // Some authoring pipelines keep a custom directory-index path but
            // intentionally reuse the stock package ID. Runtime identity follows
            // that ID, so this is an alias replacement rather than an addition.
            target_package_imports.insert(package.package_id, target.imported_package_ids.clone());
        }
    }

    for package in containers
        .iter()
        .flat_map(|container| &container.package_store)
    {
        for dependency in &package.imported_package_ids {
            if source_ids.contains(dependency) {
                continue;
            }
            target_by_id.get(dependency).with_context(|| {
                format!(
                    "StaticMesh package {} has unresolved external dependency {}",
                    package.path, dependency
                )
            })?;
        }
    }
    Ok(ReplacementInspection {
        containers,
        packages,
        target_utoc,
        target_dependencies,
        target_package_imports,
    })
}

fn matching_import_set(imports: &[u64]) -> BTreeSet<u64> {
    imports.iter().copied().collect()
}

fn validate_heterogeneous_package_identity(
    source: &PackageStoreEntry,
    target_by_path: Option<&PackageStoreEntry>,
    target_by_id: &PackageStoreEntry,
) -> Result<()> {
    if target_by_id.package_id != source.package_id {
        bail!(
            "current-game package ID does not match source identity for {}",
            source.path
        );
    }
    if let Some(target_by_path) = target_by_path {
        if target_by_path.package_id != source.package_id
            || !target_by_id.path.eq_ignore_ascii_case(&target_by_path.path)
        {
            bail!(
                "heterogeneous package identity is ambiguous for {}: source ID {}, path match ID {}, ID match path {}",
                source.path,
                source.package_id,
                target_by_path.package_id,
                target_by_id.path
            );
        }
        return Ok(());
    }

    let source_content = canonical_additive_static_mesh_path(&source.path)?
        .splitn(3, '/')
        .nth(2)
        .context("heterogeneous source package has no content-relative path")?
        .to_owned();
    let target_content = canonical_additive_static_mesh_path(&target_by_id.path)?
        .splitn(3, '/')
        .nth(2)
        .context("heterogeneous current package has no content-relative path")?
        .to_owned();
    if !source_content.eq_ignore_ascii_case(&target_content) {
        bail!(
            "package-ID alias changes more than the project root for {}: current path {}",
            source.path,
            target_by_id.path
        );
    }
    Ok(())
}

pub fn inspect_heterogeneous_replacement_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<ReplacementInspection> {
    let target_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    let containers = discover_containers_with_current(
        root,
        retoc,
        ReplacementScope::HeterogeneousReplacement,
        || Ok(retoc.package_store_entries(&target_utoc)?.1),
    )?;
    let mut packages = containers
        .iter()
        .flat_map(|container| container.packages.iter().cloned())
        .collect::<Vec<_>>();
    if packages.is_empty() || packages.len() > MAX_REPLACEMENT_PACKAGES {
        bail!(
            "heterogeneous replacement input must contain 1..={MAX_REPLACEMENT_PACKAGES} packages"
        );
    }
    packages.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
            .then(left.package_id.cmp(&right.package_id))
    });
    for pair in packages.windows(2) {
        if pair[0].path.eq_ignore_ascii_case(&pair[1].path)
            || pair[0].package_id == pair[1].package_id
        {
            bail!("heterogeneous replacement packages must have unique paths and package IDs");
        }
    }

    if !target_utoc.is_file() {
        bail!("current game stock package store is unavailable");
    }
    let (_, target_entries) = retoc.package_store_entries(&target_utoc)?;
    let source_store = containers
        .iter()
        .flat_map(|container| container.package_store.iter().cloned())
        .collect::<Vec<_>>();
    let dependencies = diagnose_package_dependencies(&source_store, &target_entries)?;
    if dependencies.unresolved_edge_count != 0 {
        bail!(
            "heterogeneous replacement has {} unresolved package dependency edge(s)",
            dependencies.unresolved_edge_count
        );
    }

    let target_by_id = target_entries
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let target_by_path = target_entries
        .iter()
        .filter_map(|entry| {
            canonical_additive_static_mesh_path(&entry.path)
                .ok()
                .map(|path| (path.to_ascii_lowercase(), entry))
        })
        .collect::<HashMap<_, _>>();
    let source_by_id = source_store
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let mut target_package_imports = HashMap::new();
    for package in &packages {
        let canonical = canonical_additive_static_mesh_path(&package.path)?;
        let by_path = target_by_path.get(&canonical.to_ascii_lowercase()).copied();
        let by_id = target_by_id.get(&package.package_id).with_context(|| {
            format!(
                "current game package ID is missing for heterogeneous replacement {}",
                package.path
            )
        })?;
        let source = source_by_id
            .get(&package.package_id)
            .context("heterogeneous source package store lost an inspected package")?;
        validate_heterogeneous_package_identity(source, by_path, by_id)?;
        target_package_imports.insert(package.package_id, by_id.imported_package_ids.clone());
    }
    let source_ids = source_by_id.keys().copied().collect::<HashSet<_>>();
    for source in source_by_id.values() {
        for dependency in &source.imported_package_ids {
            if !source_ids.contains(dependency) && !target_by_id.contains_key(dependency) {
                bail!(
                    "heterogeneous package {} has unresolved source dependency {}",
                    source.path,
                    dependency
                );
            }
        }
    }

    let target_dependencies = target_entries
        .into_iter()
        .map(|entry| {
            (
                entry.package_id,
                PackageEntry {
                    package_id: entry.package_id,
                    path: entry.path,
                },
            )
        })
        .collect();
    Ok(ReplacementInspection {
        containers,
        packages,
        target_utoc,
        target_dependencies,
        target_package_imports,
    })
}

/// Pools per-container composite packages into one identity view. Authors
/// sometimes cook the same package into more than one shipped container;
/// under equal mount order that duplication is benign and every copy is
/// preserved by the per-container rebuild, so entries whose package ID,
/// case-insensitive path, and import set all agree are deduplicated here.
/// Any partial identity overlap remains fail-closed.
pub(crate) fn pool_unique_composite_packages(
    packages: Vec<PackageEntry>,
    package_store: &[PackageStoreEntry],
) -> Result<Vec<PackageEntry>> {
    let mut imports_by_id = HashMap::<u64, BTreeSet<u64>>::new();
    for row in package_store {
        let imports = row
            .imported_package_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if let Some(existing) = imports_by_id.get(&row.package_id) {
            if *existing != imports {
                bail!("composite replacement packages must have unique paths and package IDs");
            }
        } else {
            imports_by_id.insert(row.package_id, imports);
        }
    }
    let mut pooled: Vec<PackageEntry> = Vec::new();
    let mut kept_by_id = HashMap::<u64, String>::new();
    for package in packages {
        match kept_by_id.get(&package.package_id) {
            Some(kept_path) => {
                if !kept_path.eq_ignore_ascii_case(&package.path) {
                    bail!(
                        "composite replacement packages must have unique paths and package IDs"
                    );
                }
            }
            None => {
                kept_by_id.insert(package.package_id, package.path.clone());
                pooled.push(package);
            }
        }
    }
    let mut sorted = pooled.clone();
    sorted.sort_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
    });
    for pair in sorted.windows(2) {
        if pair[0].path.eq_ignore_ascii_case(&pair[1].path) {
            bail!("composite replacement packages must have unique paths and package IDs");
        }
    }
    Ok(pooled)
}

pub fn inspect_composite_package_staged(
    root: &Path,
    game_root: &Path,
    retoc: &RetocTool,
) -> Result<ReplacementInspection> {
    let target_utoc =
        game_root.join(r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc");
    let containers =
        discover_containers_with_current(root, retoc, ReplacementScope::CompositePackage, || {
            Ok(retoc.package_store_entries(&target_utoc)?.1)
        })?;
    let pooled_store = containers
        .iter()
        .flat_map(|container| container.package_store.iter().cloned())
        .collect::<Vec<_>>();
    let packages = pool_unique_composite_packages(
        containers
            .iter()
            .flat_map(|container| container.packages.iter().cloned())
            .collect(),
        &pooled_store,
    )?;
    if packages.is_empty() || packages.len() > MAX_REPLACEMENT_PACKAGES {
        bail!("composite replacement input must contain 1..={MAX_REPLACEMENT_PACKAGES} packages");
    }

    if !target_utoc.is_file() {
        bail!("current game stock package store is unavailable");
    }
    let (_, target_entries) = retoc.package_store_entries(&target_utoc)?;
    let target_by_id = target_entries
        .iter()
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let target_by_path = target_entries
        .iter()
        .filter_map(|entry| {
            canonical_additive_static_mesh_path(&entry.path)
                .ok()
                .map(|path| (path.to_ascii_lowercase(), entry))
        })
        .collect::<HashMap<_, _>>();
    let source_store = containers
        .iter()
        .flat_map(|container| container.package_store.iter())
        .collect::<Vec<_>>();
    let source_ids = source_store
        .iter()
        .map(|entry| entry.package_id)
        .collect::<HashSet<_>>();
    let mut target_package_imports = HashMap::new();
    for source in &source_store {
        let standard_path = canonical_additive_static_mesh_path(&source.path).ok();
        let path_match = standard_path
            .as_ref()
            .and_then(|path| target_by_path.get(&path.to_ascii_lowercase()).copied());
        if let Some(current) = target_by_id.get(&source.package_id).copied() {
            if let Some(path) = standard_path {
                if path_match.is_some_and(|path_match| path_match.package_id != current.package_id)
                {
                    bail!("composite package path and package ID resolve to different targets");
                }
                let source_content = path
                    .splitn(3, '/')
                    .nth(2)
                    .context("composite source package has no content-relative path")?;
                let current_path = canonical_additive_static_mesh_path(&current.path)?;
                let current_content = current_path
                    .splitn(3, '/')
                    .nth(2)
                    .context("current composite package has no content-relative path")?;
                if !source_content.eq_ignore_ascii_case(current_content) {
                    bail!("existing composite package changes more than its project root");
                }
            } else {
                let source_leaf = source.path.rsplit('/').next().unwrap_or_default();
                let current_leaf = current.path.replace('\\', "/");
                let current_leaf = current_leaf.rsplit('/').next().unwrap_or_default();
                if !source_leaf.eq_ignore_ascii_case(current_leaf) {
                    bail!("package-root alias does not match the current package filename");
                }
            }
            target_package_imports.insert(source.package_id, current.imported_package_ids.clone());
        } else {
            let path = standard_path.with_context(|| {
                format!(
                    "additive composite package cannot use a package-root alias: {}",
                    source.path
                )
            })?;
            if path_match.is_some() {
                bail!("additive composite package collides with a current package path");
            }
            let _ = path;
        }
        let missing = source
            .imported_package_ids
            .iter()
            .filter(|dependency| {
                !source_ids.contains(dependency) && !target_by_id.contains_key(dependency)
            })
            .count();
        if missing > 2 {
            bail!(
                "composite package {} has {missing} unresolved package dependencies; guarded repair supports at most two role-proven stale dependencies per package",
                source.path
            );
        }
    }
    let target_dependencies = target_entries
        .into_iter()
        .map(|entry| {
            (
                entry.package_id,
                PackageEntry {
                    package_id: entry.package_id,
                    path: entry.path,
                },
            )
        })
        .collect();
    Ok(ReplacementInspection {
        containers,
        packages,
        target_utoc,
        target_dependencies,
        target_package_imports,
    })
}

pub(crate) fn composite_effective_package_path(
    package: &PackageEntry,
    inspection: &ReplacementInspection,
) -> Result<String> {
    if let Some(current) = inspection.target_dependencies.get(&package.package_id) {
        return Ok(current.path.clone());
    }
    canonical_additive_static_mesh_path(&package.path)
}

/// Builds the roundtrip extraction requests for a rebuilt composite
/// container. Retoc filters are case-sensitive and the rebuilt directory
/// index inherits the legacy tree's on-disk casing — which platform
/// directory-case pinning can mix between authored and current spellings —
/// so every package must be requested by the rebuilt container's OWN
/// materialized spelling. Identity is resolved by package ID: a duplicated
/// rebuilt ID or a requested identity missing from the rebuilt inventory
/// fails closed.
pub(crate) fn composite_roundtrip_requests(
    rebuilt_entries: &[PackageEntry],
    requested: &[PackageEntry],
) -> Result<Vec<(PackageEntry, String)>> {
    let mut by_id = HashMap::new();
    for entry in rebuilt_entries {
        if by_id.insert(entry.package_id, entry).is_some() {
            bail!(
                "rebuilt composite container repeats package ID {}",
                entry.package_id
            );
        }
    }
    requested
        .iter()
        .map(|package| {
            let rebuilt = by_id.get(&package.package_id).with_context(|| {
                format!(
                    "rebuilt composite container is missing requested package {}",
                    package.package_id
                )
            })?;
            canonical_additive_static_mesh_path(&rebuilt.path).with_context(|| {
                format!(
                    "rebuilt composite package {} has no canonical content path",
                    rebuilt.path
                )
            })?;
            Ok(((*rebuilt).clone(), rebuilt.path.clone()))
        })
        .collect()
}

fn mounted_game_package_name(path: &str) -> Result<String> {
    let canonical = canonical_additive_static_mesh_path(path)?;
    let parts = canonical.split('/').collect::<Vec<_>>();
    let content_index = parts
        .iter()
        .position(|part| part.eq_ignore_ascii_case("Content"))
        .context("canonical package path has no mounted Content root")?;
    if content_index != 1 || content_index + 1 >= parts.len() {
        bail!("canonical package path has an unsupported mounted Content layout");
    }
    let content = parts[content_index + 1..].join("/");
    Ok(format!(
        "/Game/{}",
        content
            .strip_suffix(".uasset")
            .or_else(|| content.strip_suffix(".umap"))
            .unwrap_or(&content)
    ))
}

fn mounted_game_legacy_path(package_name: &str) -> Result<String> {
    if !package_name
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/Game/"))
    {
        bail!("recovered dependency is not a mounted /Game package name");
    }
    Ok(format!(
        "../../../OblivionRemastered/Content/{}.uasset",
        package_name.trim_start_matches("/Game/")
    ))
}

fn package_leaf_without_extension(path: &str) -> String {
    path.replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .trim_end_matches(".uasset")
        .trim_end_matches(".umap")
        .to_owned()
}

fn differs_by_at_most_one_ascii_edit(left: &str, right: &str) -> bool {
    let left = left.to_ascii_lowercase().into_bytes();
    let right = right.to_ascii_lowercase().into_bytes();
    if left.len().abs_diff(right.len()) > 1 {
        return false;
    }
    if left.len() == right.len() {
        return left
            .iter()
            .zip(&right)
            .filter(|(left, right)| left != right)
            .count()
            <= 1;
    }
    let (shorter, longer) = if left.len() < right.len() {
        (&left, &right)
    } else {
        (&right, &left)
    };
    let mut short_index = 0_usize;
    let mut long_index = 0_usize;
    let mut skipped = false;
    while short_index < shorter.len() && long_index < longer.len() {
        if shorter[short_index] == longer[long_index] {
            short_index += 1;
            long_index += 1;
        } else if skipped {
            return false;
        } else {
            skipped = true;
            long_index += 1;
        }
    }
    true
}

/// Structural route for one recovered (missing) dependency edge.
///
/// This is the successor-decision seam for current-revision rebinding. The
/// route is only a dispatch hint taken from the retired package's leaf name;
/// every route re-proves its own evidence against the connected game before
/// anything is rebound, so a misrouted name can only fail truthfully, never
/// rebind incorrectly. A richer current-package-store successor search can
/// extend this seam without touching the container rebuild, roundtrip, or
/// disclosure plumbing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredDependencyRoute {
    /// The edge is satisfied by aliasing one structurally related bundled
    /// package under the retired identity, proven by decoded class, unique
    /// identity, and a serialized Blueprint role reference.
    BundledAlias(&'static str),
    /// The edge is a retired Unreal-editor default sidecar of an existing
    /// skeletal mesh (`<SK_Mesh>_Skeleton` / `<SK_Mesh>_PhysicsAsset`). The
    /// consumer's same-identity current-game donor decides the successor
    /// through the serialized-role import repair; the current game uses
    /// `SKEL_`/`PA_` naming for those classes, so these suffixes only occur
    /// as retired mod-cooked sidecars.
    CurrentDonorRebind(&'static str),
}

/// Proves a retired Unreal-editor sidecar identity by pure derivation: the
/// editor auto-names a mesh's sidecars `<MeshPackage>_Skeleton` and
/// `<MeshPackage>_PhysicsAsset`, so an unresolved import of consumer `P`
/// whose package ID equals the exact CityHash64 derivation of `P`'s own
/// mounted name plus one of those suffixes can only be that sidecar. This
/// needs no raw NameMap scan and no historical archive; author-renamed
/// sidecars that do not derive from the consumer name stay on the NameMap
/// recovery route.
pub(crate) fn derived_sidecar_route(
    consumer_mounted_name: &str,
    target_id: u64,
) -> Option<(String, &'static str)> {
    for (suffix, expected_class) in [("_Skeleton", "Skeleton"), ("_PhysicsAsset", "PhysicsAsset")] {
        let candidate = format!("{consumer_mounted_name}{suffix}");
        if unreal_package_id(&candidate).ok() == Some(target_id) {
            return Some((candidate, expected_class));
        }
    }
    None
}

/// Applies the current-donor gate for one stale sidecar edge and produces its
/// disclosed rebind plan: the consumer must be an existing same-identity
/// current-game package whose donor no longer imports the retired dependency.
/// The plan itself authorizes nothing; the serialized-role import repair must
/// still consume it or the lane fails.
fn plan_donor_rebind(
    inspection: &ReplacementInspection,
    consumer_id: u64,
    consumer_path: &str,
    target_id: u64,
    target_name: &str,
    expected_class: &str,
    evidence: &str,
) -> Result<CompositeDonorRebindPlan> {
    let current_imports = inspection
        .target_package_imports
        .get(&consumer_id)
        .with_context(|| {
            format!(
                "recovered stale {expected_class} dependency {target_name} requires a same-identity current-game donor for its consumer"
            )
        })?;
    if current_imports.contains(&target_id) {
        bail!(
            "current game still imports recovered dependency {target_name}; stale-dependency evidence is inconsistent"
        );
    }
    Ok(CompositeDonorRebindPlan {
        consumer_package_id: consumer_id,
        consumer_package_path: consumer_path.to_owned(),
        target_package_id: target_id,
        target_package_name: target_name.to_owned(),
        expected_class: expected_class.to_owned(),
        evidence: evidence.to_owned(),
        policy: "serialized-role-current-template-import-rebase-v1".to_owned(),
    })
}

pub(crate) fn recovered_dependency_route(target_leaf: &str) -> Option<RecoveredDependencyRoute> {
    let lower = target_leaf.to_ascii_lowercase();
    if lower.starts_with("mic_") {
        return Some(RecoveredDependencyRoute::BundledAlias(
            "MaterialInstanceConstant",
        ));
    }
    if lower.starts_with("sm_") {
        return Some(RecoveredDependencyRoute::BundledAlias("StaticMesh"));
    }
    if lower.starts_with("sk_") && lower.ends_with("_skeleton") {
        return Some(RecoveredDependencyRoute::CurrentDonorRebind("Skeleton"));
    }
    if lower.starts_with("sk_") && lower.ends_with("_physicsasset") {
        return Some(RecoveredDependencyRoute::CurrentDonorRebind("PhysicsAsset"));
    }
    None
}

fn composite_alias_candidate(
    consumer: &PackageStoreEntry,
    target_package_name: &str,
    expected_class: &str,
    source_store: &HashMap<u64, PackageStoreEntry>,
    source_packages: &HashMap<u64, PackageEntry>,
) -> Result<PackageEntry> {
    let direct_meshes = consumer
        .imported_package_ids
        .iter()
        .filter_map(|package_id| source_store.get(package_id))
        .filter(|entry| {
            package_leaf_without_extension(&entry.path)
                .get(..3)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SM_"))
        })
        .collect::<Vec<_>>();
    if direct_meshes.len() != 1 {
        bail!(
            "identity recovery requires exactly one bundled primary StaticMesh dependency; found {}",
            direct_meshes.len()
        );
    }
    let main_dependencies = direct_meshes[0]
        .imported_package_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let target_leaf = package_leaf_without_extension(target_package_name);
    let target_parent = target_package_name
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .context("recovered package name has no parent")?;
    let candidates = if expected_class.eq_ignore_ascii_case("MaterialInstanceConstant") {
        main_dependencies
            .iter()
            .filter_map(|package_id| source_packages.get(package_id))
            .filter(|package| {
                mounted_game_package_name(&package.path)
                    .ok()
                    .and_then(|name| name.rsplit_once('/').map(|(parent, _)| parent.to_owned()))
                    .is_some_and(|parent| parent.eq_ignore_ascii_case(target_parent))
            })
            .cloned()
            .collect::<Vec<_>>()
    } else if expected_class.eq_ignore_ascii_case("StaticMesh") {
        source_packages
            .values()
            .filter(|package| {
                differs_by_at_most_one_ascii_edit(
                    &package_leaf_without_extension(&package.path),
                    &target_leaf,
                )
            })
            .filter(|package| {
                source_store
                    .get(&package.package_id)
                    .is_some_and(|candidate| {
                        candidate
                            .imported_package_ids
                            .iter()
                            .any(|dependency| main_dependencies.contains(dependency))
                    })
            })
            .cloned()
            .collect::<Vec<_>>()
    } else {
        bail!("unsupported recovered dependency class {expected_class}");
    };
    if candidates.len() != 1 {
        bail!(
            "recovered {expected_class} dependency requires one structurally related bundled candidate; found {}",
            candidates.len()
        );
    }
    Ok(candidates.into_iter().next().unwrap())
}

fn composite_primary_static_mesh_candidate(
    consumer: &PackageStoreEntry,
    source_store: &HashMap<u64, PackageStoreEntry>,
    source_packages: &HashMap<u64, PackageEntry>,
) -> Result<PackageEntry> {
    let mut candidates = consumer
        .imported_package_ids
        .iter()
        .filter_map(|package_id| source_store.get(package_id))
        .filter(|entry| {
            package_leaf_without_extension(&entry.path)
                .get(..3)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SM_"))
        })
        .filter_map(|entry| source_packages.get(&entry.package_id))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|package| package.package_id);
    candidates.dedup_by_key(|package| package.package_id);
    if candidates.len() != 1 {
        bail!(
            "optional secondary StaticMesh recovery requires exactly one bundled primary StaticMesh; found {}",
            candidates.len()
        );
    }
    Ok(candidates.remove(0))
}

fn authoritative_alias_source_identity(
    source_candidate: &PackageEntry,
    inspection: &ReplacementInspection,
    retoc: &RetocTool,
    work: &Path,
) -> Result<PackageEntry> {
    if let Ok(canonical) = canonical_additive_static_mesh_path(&source_candidate.path)
        && canonical
            .get(.."OblivionRemastered/Content/".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("OblivionRemastered/Content/"))
        && unreal_package_id(&canonical)
            .is_ok_and(|package_id| package_id == source_candidate.package_id)
    {
        return Ok(PackageEntry {
            package_id: source_candidate.package_id,
            path: canonical,
        });
    }
    let container = inspection
        .containers
        .iter()
        .find(|container| {
            container
                .packages
                .iter()
                .any(|package| package.package_id == source_candidate.package_id)
        })
        .context("alias source identity lost its container")?;
    let raw = retoc.package_raw_chunk(
        &container.utoc,
        source_candidate.package_id,
        &work.join(source_candidate.package_id.to_string()),
    )?;
    let source_ids = [source_candidate.package_id]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let names = game_package_names_for_ids(&raw, &source_ids)?
        .remove(&source_candidate.package_id)
        .unwrap_or_default();
    if names.len() != 1 {
        bail!(
            "package-store alias source {} must expose one authoritative mounted identity in its raw NameMap; found {}",
            source_candidate.path,
            names.len()
        );
    }
    Ok(PackageEntry {
        package_id: source_candidate.package_id,
        path: mounted_game_legacy_path(&names[0])?,
    })
}

/// Builds one identity provider container from a staged legacy root and
/// mounts it into the extraction source view. The provider inventory must
/// equal exactly the recovered target IDs it was staged for.
fn build_composite_identity_provider(
    retoc: &RetocTool,
    inspection: &ReplacementInspection,
    source_view: &Path,
    provider_root: &Path,
    legacy_root: &Path,
    name_prefix: &str,
    target_ids: &BTreeSet<u64>,
) -> Result<Option<CompositeIdentityAliasProvider>> {
    if target_ids.is_empty() {
        return Ok(None);
    }
    let provider_hash = sha256_bytes(
        target_ids
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("|")
            .as_bytes(),
    );
    let provider_name = format!("{name_prefix}_{}_P", &provider_hash[..12]);
    fs::create_dir_all(provider_root)?;
    let provider_utoc = provider_root.join(format!("{provider_name}.utoc"));
    let result = retoc.run([
        OsString::from("to-zen"),
        OsString::from("--version"),
        OsString::from("UE5_3"),
        legacy_root.as_os_str().to_owned(),
        provider_utoc.as_os_str().to_owned(),
    ])?;
    RetocTool::assert_success(&result, "identity alias provider rebuild")?;
    let provider_ucas = provider_utoc.with_extension("ucas");
    let provider_pak = provider_utoc.with_extension("pak");
    for path in [&provider_utoc, &provider_ucas, &provider_pak] {
        if !path.is_file() {
            bail!("identity alias provider is incomplete: {}", path.display());
        }
        copy_probe_file(
            path,
            &source_view.join(
                path.file_name()
                    .context("identity alias provider has no filename")?,
            ),
        )?;
    }
    retoc.verify(&provider_utoc, "identity alias provider")?;
    let (_, provider_packages) = retoc.package_entries(&provider_utoc)?;
    if provider_packages
        .iter()
        .map(|package| package.package_id)
        .collect::<BTreeSet<_>>()
        != *target_ids
    {
        bail!("identity alias provider inventory does not match recovered target IDs");
    }
    let first_container = inspection
        .containers
        .first()
        .context("identity recovery has no source container")?;
    let relative_utoc = first_container
        .relative_utoc
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(format!("{provider_name}.utoc"));
    Ok(Some(CompositeIdentityAliasProvider {
        provider_name,
        provider_utoc,
        provider_ucas,
        provider_pak,
        legacy_root: legacy_root.to_path_buf(),
        relative_utoc,
    }))
}

pub fn recover_composite_package_identities(
    inspection: &ReplacementInspection,
    retoc: &RetocTool,
    source_view: &Path,
    work: &Path,
) -> Result<Option<CompositeIdentityRecovery>> {
    let source_packages = inspection
        .packages
        .iter()
        .map(|package| (package.package_id, package.clone()))
        .collect::<HashMap<_, _>>();
    let source_store = inspection
        .containers
        .iter()
        .flat_map(|container| container.package_store.iter().cloned())
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let source_ids = source_packages.keys().copied().collect::<HashSet<_>>();
    let missing_edges = source_store
        .values()
        .flat_map(|consumer| {
            consumer
                .imported_package_ids
                .iter()
                .filter(|dependency| {
                    !source_ids.contains(dependency)
                        && !inspection.target_dependencies.contains_key(dependency)
                })
                .map(|dependency| (consumer.package_id, *dependency))
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    if missing_edges.is_empty() {
        return Ok(None);
    }
    fs::create_dir_all(work)?;
    let alias_legacy = work.join("legacy");
    fs::create_dir_all(&alias_legacy)?;
    // Temporary optional-component identities never ship, so they are staged
    // in their own legacy root and built into a separate rebuild-only
    // provider container instead of the persistent alias provider.
    let temporary_legacy = work.join("temporary-legacy");
    fs::create_dir_all(&temporary_legacy)?;
    let mut recovered_targets =
        HashMap::<u64, (String, String, PackageEntry, PackageIdentityAlias, bool)>::new();
    let mut pending = Vec::<(u64, u64, String, String, PackageEntry, bool)>::new();
    let mut donor_rebinds = Vec::<CompositeDonorRebindPlan>::new();
    for (consumer_id, target_id) in missing_edges {
        let consumer = source_store
            .get(&consumer_id)
            .context("identity recovery lost its consumer package-store row")?;
        // Derivation-first sidecar recognition: an unresolved import whose ID
        // derives exactly from the consumer's own mounted name plus an
        // Unreal-editor sidecar suffix is proven without raw NameMap
        // evidence. Author-renamed sidecars fall through to name recovery.
        let consumer_mounted = inspection
            .target_dependencies
            .get(&consumer_id)
            .and_then(|current| mounted_game_package_name(&current.path).ok())
            .or_else(|| mounted_game_package_name(&consumer.path).ok());
        if let Some(consumer_name) = &consumer_mounted
            && let Some((target_name, expected_class)) =
                derived_sidecar_route(consumer_name, target_id)
        {
            donor_rebinds.push(plan_donor_rebind(
                inspection,
                consumer_id,
                &consumer.path,
                target_id,
                &target_name,
                expected_class,
                "consumer-derived-sidecar-package-id",
            )?);
            continue;
        }
        let container = inspection
            .containers
            .iter()
            .find(|container| {
                container
                    .packages
                    .iter()
                    .any(|package| package.package_id == consumer_id)
            })
            .context("identity recovery lost its consumer container")?;
        let raw = retoc.package_raw_chunk(
            &container.utoc,
            consumer_id,
            &work.join("raw").join(consumer_id.to_string()),
        )?;
        let target_ids = [target_id].into_iter().collect::<BTreeSet<_>>();
        let recovered = game_package_names_for_ids(&raw, &target_ids)?;
        let names = recovered.get(&target_id).cloned().unwrap_or_default();
        if names.len() != 1 {
            bail!(
                "unresolved dependency {target_id} must resolve to one exact mounted package name in consumer raw data; found {}",
                names.len()
            );
        }
        let target_name = names[0].clone();
        let target_leaf = package_leaf_without_extension(&target_name);
        let expected_class = match recovered_dependency_route(&target_leaf) {
            None => {
                bail!("recovered dependency {target_name} has no supported structural alias class")
            }
            Some(RecoveredDependencyRoute::CurrentDonorRebind(expected_class)) => {
                // The stale sidecar is not aliased. Its consumer must be an
                // existing same-identity current-game package whose donor no
                // longer imports the retired dependency; the per-package
                // serialized-role import repair then rebinds the edge to the
                // donor's proven successor (or proves retirement) and the
                // rebuilt container is verified against the donor-derived
                // import set. Recovery only records the routing decision.
                donor_rebinds.push(plan_donor_rebind(
                    inspection,
                    consumer_id,
                    &consumer.path,
                    target_id,
                    &target_name,
                    expected_class,
                    "same-identity-current-donor-import-table",
                )?);
                continue;
            }
            Some(RecoveredDependencyRoute::BundledAlias(expected_class)) => expected_class,
        };
        let (source_candidate, suppress_optional_component) = match composite_alias_candidate(
            consumer,
            &target_name,
            expected_class,
            &source_store,
            &source_packages,
        ) {
            Ok(candidate) => (candidate, false),
            Err(_) if expected_class.eq_ignore_ascii_case("StaticMesh") => (
                composite_primary_static_mesh_candidate(consumer, &source_store, &source_packages)?,
                true,
            ),
            Err(error) => return Err(error),
        };
        if let Some((known_name, known_class, known_source, _, known_suppression)) =
            recovered_targets.get(&target_id)
        {
            if !known_name.eq_ignore_ascii_case(&target_name)
                || !known_class.eq_ignore_ascii_case(expected_class)
                || known_source.package_id != source_candidate.package_id
                || *known_suppression != suppress_optional_component
            {
                bail!("multiple consumers disagree on recovered package identity {target_id}");
            }
        } else {
            let candidate_root = work
                .join("candidates")
                .join(source_candidate.package_id.to_string());
            extract_source_composite_packages_exact(
                retoc,
                source_view,
                &candidate_root,
                &[(source_candidate.clone(), source_candidate.path.clone())],
                "identity alias source extraction",
            )?;
            let source_asset =
                find_extracted_additive_static_mesh(&candidate_root, &source_candidate.path)?;
            let (kind, _) = classify_composite_package_asset(
                &source_asset,
                false,
                &work
                    .join("candidate-classification")
                    .join(source_candidate.package_id.to_string()),
            )?;
            let class_matches = matches!(
                (kind, expected_class),
                (
                    CompositePackageAssetKind::MaterialInstanceConstant,
                    "MaterialInstanceConstant"
                ) | (CompositePackageAssetKind::StaticMesh, "StaticMesh")
            );
            if !class_matches {
                bail!(
                    "structurally related alias candidate {} does not decode as {expected_class}",
                    source_candidate.path
                );
            }
            let (_, identity) = create_package_identity_alias(
                &source_asset,
                &authoritative_alias_source_identity(
                    &source_candidate,
                    inspection,
                    retoc,
                    &work.join("source-identities"),
                )?,
                &target_name,
                target_id,
                expected_class,
                if suppress_optional_component {
                    &temporary_legacy
                } else {
                    &alias_legacy
                },
                &work.join("aliases").join(target_id.to_string()),
            )?;
            recovered_targets.insert(
                target_id,
                (
                    target_name.clone(),
                    expected_class.to_owned(),
                    source_candidate.clone(),
                    identity,
                    suppress_optional_component,
                ),
            );
        }
        pending.push((
            consumer_id,
            target_id,
            target_name,
            expected_class.to_owned(),
            source_candidate,
            suppress_optional_component,
        ));
    }

    let persistent_ids = recovered_targets
        .iter()
        .filter(|(_, tuple)| !tuple.4)
        .map(|(target_id, _)| *target_id)
        .collect::<BTreeSet<_>>();
    let temporary_ids = recovered_targets
        .iter()
        .filter(|(_, tuple)| tuple.4)
        .map(|(target_id, _)| *target_id)
        .collect::<BTreeSet<_>>();
    let provider = build_composite_identity_provider(
        retoc,
        inspection,
        source_view,
        &work.join("provider"),
        &alias_legacy,
        "OBR_IdentityAliases",
        &persistent_ids,
    )?;
    let temporary_provider = build_composite_identity_provider(
        retoc,
        inspection,
        source_view,
        &work.join("temporary-provider"),
        &temporary_legacy,
        "OBR_TemporaryProviders",
        &temporary_ids,
    )?;

    let mut aliases = Vec::new();
    let mut suppressions = Vec::new();
    for (
        consumer_id,
        target_id,
        target_name,
        expected_class,
        source_candidate,
        suppress_optional_component,
    ) in pending
    {
        let consumer_package = source_packages
            .get(&consumer_id)
            .context("identity recovery lost its consumer package")?;
        let consumer_root = work.join("consumers").join(consumer_id.to_string());
        extract_source_composite_packages_exact(
            retoc,
            source_view,
            &consumer_root,
            &[(consumer_package.clone(), consumer_package.path.clone())],
            "resolved identity consumer extraction",
        )?;
        let consumer_asset =
            find_extracted_additive_static_mesh(&consumer_root, &consumer_package.path)?;
        let mut role = prove_blueprint_alias_role(
            &consumer_asset,
            &target_name,
            target_id,
            &expected_class,
            &work.join("roles").join(consumer_id.to_string()),
        )?;
        role.consumer = consumer_package.path.clone();
        let identity = recovered_targets
            .get(&target_id)
            .context("identity recovery lost its alias report")?
            .3
            .clone();
        let target_package = PackageEntry {
            package_id: target_id,
            path: mounted_game_legacy_path(&target_name)?,
        };
        if suppress_optional_component {
            if role.role != "scabbard-static-mesh" {
                bail!("optional StaticMesh fallback did not prove a secondary scabbard role");
            }
            suppressions.push(CompositeOptionalDependencySuppressionPlan {
                consumer_package_id: consumer_id,
                consumer_package_path: consumer_package.path.clone(),
                temporary_source_package: source_candidate,
                target_package,
                expected_class,
                temporary_identity: identity,
                role,
            });
        } else {
            aliases.push(CompositeIdentityAliasPlan {
                consumer_package_id: consumer_id,
                consumer_package_path: consumer_package.path.clone(),
                source_package: source_candidate,
                target_package,
                expected_class,
                identity,
                role,
            });
        }
    }
    aliases.sort_by(|left, right| {
        left.target_package
            .package_id
            .cmp(&right.target_package.package_id)
            .then(left.consumer_package_id.cmp(&right.consumer_package_id))
    });
    suppressions.sort_by(|left, right| {
        left.target_package
            .package_id
            .cmp(&right.target_package.package_id)
            .then(left.consumer_package_id.cmp(&right.consumer_package_id))
    });
    donor_rebinds.sort_by(|left, right| {
        left.target_package_id
            .cmp(&right.target_package_id)
            .then(left.consumer_package_id.cmp(&right.consumer_package_id))
    });
    Ok(Some(CompositeIdentityRecovery {
        provider,
        temporary_provider,
        aliases,
        suppressions,
        donor_rebinds,
    }))
}
pub fn probe_input(mod_input: &Path, game_root: &Path) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-armor-replacement-probe-")
        .tempdir()?;
    let staged = work.path().join("input");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_staged(&staged, game_root, &retoc)?;
    Ok(ReplacementProbeSummary {
        container_count: inspection.containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: "skeletal-mesh-replacement".to_owned(),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets: Vec::new(),
    })
}

pub fn probe_mixed_armor_input(
    mod_input: &Path,
    game_root: &Path,
) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-mixed-armor-probe-")
        .tempdir()?;
    let staged = work.path().join("input");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_mixed_armor_staged(&staged, game_root, &retoc)?;
    Ok(ReplacementProbeSummary {
        container_count: inspection.mesh.containers.len() + inspection.companion_containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: "mixed-armor-expansion-and-form-replacements".to_owned(),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets: Vec::new(),
    })
}

fn copy_probe_file(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(
        destination
            .parent()
            .context("probe copy destination has no parent")?,
    )?;
    fs::copy(source, destination)
        .with_context(|| format!("copying probe input {}", source.display()))?;
    Ok(())
}

fn find_extracted_asset(root: &Path, package_path: &str) -> Result<PathBuf> {
    let expected = canonical_package_path(package_path)?.to_ascii_lowercase();
    let matches = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
        })
        .filter(|path| {
            path.strip_prefix(root)
                .ok()
                .and_then(|relative| canonical_package_path(&relative.to_string_lossy()).ok())
                .is_some_and(|candidate| candidate.to_ascii_lowercase() == expected)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "expected one extracted Texture2D asset for {package_path}; found {}",
            matches.len()
        );
    }
    Ok(matches[0].clone())
}

/// Derives one case-sensitive Retoc filter per current-game donor package.
/// Each filter must keep the current package store's exact spelling; a source
/// container spelling (including any project-root alias) is never a valid
/// donor filter and fails closed here.
pub(crate) fn current_donor_package_filters(
    target_packages: &[PackageEntry],
) -> Result<Vec<String>> {
    target_packages
        .iter()
        .map(|package| {
            Ok(canonical_package_path(&package.path)?
                .trim_end_matches(".uasset")
                .to_owned())
        })
        .collect()
}

/// Extracts every requested current-game donor package in one Retoc
/// invocation instead of re-reading the complete current package store once
/// per donor. The invocation carries one exact current-spelling filter per
/// donor; the run fails closed unless exactly the requested number of assets
/// extracts, and each donor is then individually resolved by its exact
/// current path.
pub(crate) fn extract_current_packages_batched(
    retoc: &RetocTool,
    input: &Path,
    output: &Path,
    target_packages: &[PackageEntry],
    label: &str,
) -> Result<Vec<PathBuf>> {
    if target_packages.is_empty() {
        return Ok(Vec::new());
    }
    fs::create_dir_all(output)?;
    let mut arguments = vec![
        OsString::from("to-legacy"),
        input.as_os_str().to_owned(),
        output.as_os_str().to_owned(),
        OsString::from("--version"),
        OsString::from("UE5_3"),
        OsString::from("--no-shaders"),
        OsString::from("--no-script-objects"),
        OsString::from("--no-parallel"),
    ];
    for filter in current_donor_package_filters(target_packages)? {
        arguments.push(OsString::from("--filter"));
        arguments.push(OsString::from(filter));
    }
    let result = retoc.run(arguments)?;
    let (extracted, failed) = RetocTool::extraction_summary(&result, label)?;
    if failed != 0 || extracted != target_packages.len() {
        bail!(
            "{label} expected exactly {} current donor asset(s); extracted {extracted}, failed {failed}",
            target_packages.len()
        );
    }
    target_packages
        .iter()
        .map(|package| find_extracted_asset(output, &package.path))
        .collect()
}

fn extract_current_texture_package(
    retoc: &RetocTool,
    input: &Path,
    output: &Path,
    target_package: &PackageEntry,
    label: &str,
) -> Result<PathBuf> {
    fs::create_dir_all(output)?;
    // The target package comes directly from the current package store. Keep
    // that store's exact spelling for the case-sensitive Retoc filter.
    let filter = canonical_package_path(&target_package.path)?
        .trim_end_matches(".uasset")
        .to_owned();
    let result = retoc.run([
        OsString::from("to-legacy"),
        input.as_os_str().to_owned(),
        output.as_os_str().to_owned(),
        OsString::from("--version"),
        OsString::from("UE5_3"),
        OsString::from("--no-shaders"),
        OsString::from("--no-script-objects"),
        OsString::from("--no-parallel"),
        OsString::from("--filter"),
        OsString::from(filter),
    ])?;
    let (extracted, failed) = RetocTool::extraction_summary(&result, label)?;
    if failed != 0 || extracted != 1 {
        bail!("{label} expected one Texture2D asset; extracted {extracted}, failed {failed}");
    }
    find_extracted_asset(output, &target_package.path)
}

pub(crate) fn validate_texture_replacement_pair(
    mut source: TextureAssetDiagnostic,
    current: &TextureAssetDiagnostic,
    package_path: &str,
) -> Result<TextureAssetDiagnostic> {
    if !source.class_name.eq_ignore_ascii_case("Texture2D")
        || !current.class_name.eq_ignore_ascii_case("Texture2D")
    {
        bail!("Texture2D class proof failed for {package_path}");
    }
    if !source
        .object_name
        .eq_ignore_ascii_case(&current.object_name)
    {
        bail!(
            "Texture2D object identity changed for {package_path}: source {}, current {}",
            source.object_name,
            current.object_name
        );
    }
    if !source
        .pixel_format
        .eq_ignore_ascii_case(&current.pixel_format)
    {
        source.warnings.push(format!(
            "Pixel format differs from the current target (source {}, current {}); the structurally valid authored source format and payload are preserved without transcoding, and runtime testing is required",
            source.pixel_format,
            current.pixel_format
        ));
    }
    if source.use_separate_bulk_data_files != current.use_separate_bulk_data_files {
        source.warnings.push(format!(
            "Bulk streaming layout differs from the current target (source separate={}, current separate={}); source sidecars are preserved and runtime testing is required",
            source.use_separate_bulk_data_files, current.use_separate_bulk_data_files
        ));
    }
    Ok(source)
}

pub(crate) fn classify_heterogeneous_asset(asset: &Path) -> Result<ProvenHeterogeneousAsset> {
    let texture = inspect_texture_asset(asset);
    let static_mesh = inspect_static_mesh_asset(asset);
    match (texture, static_mesh) {
        (Ok(texture), Err(_)) => Ok(ProvenHeterogeneousAsset::Texture2D(texture)),
        (Err(_), Ok(imports)) => Ok(ProvenHeterogeneousAsset::StaticMesh { imports }),
        (Ok(_), Ok(_)) => bail!(
            "asset matched both Texture2D and StaticMesh structural contracts: {}",
            asset.display()
        ),
        (Err(texture_error), Err(static_mesh_error)) => bail!(
            "asset matched neither supported structural contract: {}; Texture2D: {texture_error:#}; StaticMesh: {static_mesh_error:#}",
            asset.display()
        ),
    }
}

pub(crate) fn find_extracted_additive_static_mesh(
    root: &Path,
    package_path: &str,
) -> Result<PathBuf> {
    let expected = canonical_additive_static_mesh_path(package_path)?.to_ascii_lowercase();
    let matches = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
        })
        .filter(|path| {
            path.strip_prefix(root)
                .ok()
                .and_then(|relative| {
                    canonical_additive_static_mesh_path(&relative.to_string_lossy()).ok()
                })
                .is_some_and(|path| path.to_ascii_lowercase() == expected)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "expected one extracted additive static mesh for {package_path}; found {}",
            matches.len()
        );
    }
    Ok(matches[0].clone())
}

fn create_additive_probe_view(game_root: &Path) -> Result<tempfile::TempDir> {
    let paks = game_root.join(r"OblivionRemastered\Content\Paks");
    let view = tempfile::Builder::new()
        .prefix(".obr-static-mesh-probe-")
        .tempdir_in(game_root)
        .context("creating a temporary dependency view beside the game")?;
    for name in [
        "global.utoc",
        "global.ucas",
        "OblivionRemastered-Windows.utoc",
        "OblivionRemastered-Windows.ucas",
        "OblivionRemastered-Windows.pak",
    ] {
        let source = paks.join(name);
        if !source.is_file() {
            bail!("required game container file is missing: {name}");
        }
        fs::hard_link(&source, view.path().join(name)).with_context(|| {
            format!("creating a temporary hard link for dependency container {name}")
        })?;
    }
    Ok(view)
}

/// Decides whether a composite package that materialized under its exact
/// source spelling may be accepted as the requested effective package.
///
/// `Ok(false)` means both canonical spellings already name the same location
/// (case-insensitively) and nothing needs to move. `Ok(true)` requires
/// project-root-alias evidence: both are `<Project>/Content` paths whose
/// content-relative suffixes agree case-insensitively, so only the named
/// project root differs. The unique package-ID half of the evidence is
/// established by the caller: composite inspection fails closed before any
/// pair reaches extraction unless the source package ID resolves to exactly
/// this current identity. Without the suffix agreement re-proven here there
/// is no evidence the materialized file is the requested package, so
/// anything else fails closed.
pub(crate) fn composite_alias_rebinding_required(
    source_canonical: &str,
    effective_canonical: &str,
) -> Result<bool> {
    if source_canonical.eq_ignore_ascii_case(effective_canonical) {
        return Ok(false);
    }
    fn content_suffix(path: &str) -> Option<&str> {
        path.splitn(3, '/').nth(2)
    }
    match (
        content_suffix(source_canonical),
        content_suffix(effective_canonical),
    ) {
        (Some(source_suffix), Some(effective_suffix))
            if source_suffix.eq_ignore_ascii_case(effective_suffix) =>
        {
            Ok(true)
        }
        _ => bail!(
            "materialized package {source_canonical} changes more than its project root against requested identity {effective_canonical}; refusing alias rebinding"
        ),
    }
}

pub(crate) fn extract_composite_packages_exact(
    retoc: &RetocTool,
    input: &Path,
    output: &Path,
    packages: &[(PackageEntry, String)],
    label: &str,
) -> Result<()> {
    fs::create_dir_all(output)?;
    let initial = extracted_uasset_paths(output)?;
    let expected = packages
        .iter()
        .map(|(_, path)| Ok(canonical_additive_static_mesh_path(path)?.to_ascii_lowercase()))
        .collect::<Result<BTreeSet<_>>>()?;
    let source_directories = packages
        .iter()
        .filter_map(|(source, _)| {
            canonical_additive_static_mesh_path(&source.path)
                .ok()
                .and_then(|path| {
                    path.rsplit_once('/')
                        .map(|(directory, _)| directory.to_owned())
                })
        })
        .collect::<BTreeSet<_>>();
    if packages.len() > 1
        && source_directories.len() == 1
        && packages
            .iter()
            .all(|(source, _)| canonical_additive_static_mesh_path(&source.path).is_ok())
    {
        // Directory filters are a performance optimization only. A source
        // package can share its directory with unrelated stock assets from the
        // dependency view, so isolate the speculative batch and publish it
        // only when its package set is exact. Otherwise discard it and fall
        // back to the per-package filters below.
        let batch = tempfile::Builder::new()
            .prefix("obr-composite-directory-batch-")
            .tempdir()?;
        let directory = source_directories.first().unwrap();
        let result = retoc.run([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            batch.path().as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
            OsString::from("--filter"),
            OsString::from(directory),
        ])?;
        let (extracted, failed) = RetocTool::extraction_summary(&result, label)?;
        if failed == 0 && extracted > 0 {
            let batched = extracted_uasset_paths(batch.path())?;
            if batched == expected {
                if !initial.is_disjoint(&expected) {
                    bail!("{label} would overwrite an already extracted package");
                }
                copy_tree(batch.path(), output)?;
                return Ok(());
            }
        }
    }
    for (source, effective_path) in packages {
        let before = extracted_uasset_paths(output)?;
        let expected_path =
            canonical_additive_static_mesh_path(effective_path)?.to_ascii_lowercase();
        if before.contains(&expected_path) {
            continue;
        }
        let single = tempfile::Builder::new()
            .prefix("obr-composite-package-exact-")
            .tempdir()?;
        let filter = if canonical_additive_static_mesh_path(&source.path).is_ok() {
            source_package_store_filter(source)?
        } else {
            source
                .path
                .replace('\\', "/")
                .rsplit('/')
                .next()
                .context("package-root alias has no filename")?
                .trim_end_matches(".uasset")
                .to_owned()
        };
        let result = retoc.run([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            single.path().as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
            OsString::from("--filter"),
            OsString::from(filter),
        ])?;
        let package_label = format!("{label} {}", source.path);
        let (extracted, failed) = RetocTool::extraction_summary(&result, &package_label)?;
        if failed != 0 || extracted == 0 {
            bail!(
                "{package_label} extracted no package payload; extracted {extracted}, failed {failed}"
            );
        }
        if canonical_additive_static_mesh_path(&source.path).is_err() {
            let source_leaf = source
                .path
                .replace('\\', "/")
                .rsplit('/')
                .next()
                .context("package-root alias has no filename")?
                .to_owned();
            let source_asset = single.path().join(&source_leaf);
            let destination = single
                .path()
                .join(canonical_additive_static_mesh_path(effective_path)?);
            if source_asset.is_file() {
                if destination.exists() {
                    bail!("package-root alias extraction collided with its canonical destination");
                }
                fs::create_dir_all(
                    destination
                        .parent()
                        .context("canonical alias destination has no parent")?,
                )?;
                for extension in ["uasset", "uexp", "ubulk", "uptnl"] {
                    let source_sidecar = source_asset.with_extension(extension);
                    if source_sidecar.is_file() {
                        fs::rename(&source_sidecar, destination.with_extension(extension))?;
                    }
                }
            }
        } else {
            // A named-project-root alias source materializes under its exact
            // source spelling. When the caller proved the pair's identity by
            // unique package ID and the content-relative suffixes agree, the
            // materialized files ARE the requested package and move to its
            // current identity; any other spelling difference fails closed.
            let canonical_source = canonical_additive_static_mesh_path(&source.path)?;
            let canonical_effective = canonical_additive_static_mesh_path(effective_path)?;
            if composite_alias_rebinding_required(&canonical_source, &canonical_effective)? {
                let source_asset =
                    find_extracted_additive_static_mesh(single.path(), &source.path)?;
                let destination = single.path().join(&canonical_effective);
                if destination.exists() {
                    bail!(
                        "{package_label} project-root alias extraction collided with its canonical destination"
                    );
                }
                fs::create_dir_all(
                    destination
                        .parent()
                        .context("canonical alias destination has no parent")?,
                )?;
                for extension in ["uasset", "uexp", "ubulk", "uptnl"] {
                    let source_sidecar = source_asset.with_extension(extension);
                    if source_sidecar.is_file() {
                        fs::rename(&source_sidecar, destination.with_extension(extension))?;
                    }
                }
            }
        }
        let extracted_paths = extracted_uasset_paths(single.path())?;
        if !extracted_paths.contains(&expected_path) {
            bail!(
                "{package_label} did not materialize the exact requested package {expected_path}; Retoc returned {}",
                extracted_paths.into_iter().collect::<Vec<_>>().join(", ")
            );
        }
        let extracted_asset = find_extracted_additive_static_mesh(single.path(), effective_path)?;
        let destination = output.join(canonical_additive_static_mesh_path(effective_path)?);
        fs::create_dir_all(
            destination
                .parent()
                .context("exact composite destination has no parent")?,
        )?;
        for extension in ["uasset", "uexp", "ubulk", "uptnl"] {
            let source_sidecar = extracted_asset.with_extension(extension);
            if source_sidecar.is_file() {
                let destination_sidecar = destination.with_extension(extension);
                if destination_sidecar.exists() {
                    bail!("{package_label} would overwrite an extracted package sidecar");
                }
                fs::copy(&source_sidecar, &destination_sidecar)?;
            }
        }
    }
    let final_paths = extracted_uasset_paths(output)?;
    verify_exact_reconstruction(&initial, &final_paths, &expected, label)
}

/// The extraction above deliberately skips a requested package that a prior
/// call into the same output directory already materialized, so reconstruction
/// is proven by two properties: every requested package is present afterwards,
/// and nothing outside the requested set was newly added.
fn verify_exact_reconstruction(
    initial: &BTreeSet<String>,
    final_paths: &BTreeSet<String>,
    expected: &BTreeSet<String>,
    label: &str,
) -> Result<()> {
    let missing = expected
        .difference(final_paths)
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = final_paths
        .difference(initial)
        .filter(|path| !expected.contains(*path))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() || !unexpected.is_empty() {
        bail!(
            "{label} did not reconstruct the exact composite package set; missing [{}], unexpected [{}]",
            missing.join(", "),
            unexpected.join(", ")
        );
    }
    Ok(())
}
/// Stages the only view a SOURCE-package extraction may read from: every
/// container file in `input` except the current game's stock main store.
///
/// Retoc merges every container in its input directory into one package
/// store. For any package ID the current game also carries, the current
/// store wins that merge: it rebinds the package's path to the current
/// spelling (so an exact source-spelling filter matches nothing) and its
/// chunk is extracted last (so current-game bytes silently overwrite the
/// source bytes). Source extraction must therefore never see the stock main
/// store. The `global` script-object store is kept because zen-to-legacy
/// conversion needs it; unresolved external package imports are preserved as
/// explicit `/Engine/UnknownPackage` markers and repaired downstream against
/// proven current identities.
fn stage_exclusive_source_view(input: &Path) -> Result<tempfile::TempDir> {
    let staged = tempfile::Builder::new()
        .prefix("obr-source-only-extraction-")
        .tempdir()?;
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !matches!(
            extension.to_ascii_lowercase().as_str(),
            "pak" | "ucas" | "utoc"
        ) {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .context("source extraction view contains a non-UTF-8 filename")?;
        if file_name
            .to_ascii_lowercase()
            .starts_with("oblivionremastered-windows.")
        {
            continue;
        }
        fs::copy(&path, staged.path().join(file_name))?;
    }
    Ok(staged)
}

/// Composite SOURCE-package extraction counterpart of
/// [`extract_source_packages_exact`].
///
/// Two extractions of the same packages prove two different properties:
///
/// 1. An extraction from the exclusive source-only view (source containers
///    plus the `global` script-object store, never the current main store) is
///    the byte-authorship truth: nothing in that view can substitute
///    current-game bytes or rebind a path on case skew.
/// 2. An extraction from the caller's layered view (source containers over
///    the current stock store) is the only one that can resolve imported
///    OBJECT names: they live in the imported packages' export maps, so a
///    source-only view degrades current-game imports to
///    `/Engine/UnknownPackage` markers whose object identities no downstream
///    repair could reconstruct.
///
/// Only packages whose exclusive extraction still carries markers consult
/// the layered view, and each name-resolved UAsset is adopted only after
/// proving it carries the exclusive extraction's exact authored export
/// payloads; any divergence means the layered view substituted foreign
/// content and the extraction fails closed. Sidecars always keep the
/// exclusive extraction's bytes. The rebuilt-container roundtrip goes
/// through the same discipline (with the rebuilt containers as the source
/// side); only donor extractions stay off this wrapper, because donors must
/// read the pure current view.
/// Main-lane variant of [`extract_source_composite_packages_exact`] with a
/// per-package layered fallback for packages retoc cannot convert from a
/// source-only view at all (some Blueprint conversions require the imported
/// packages' data and abort otherwise). A fallback package is extracted from
/// the layered view and accepted only with authorship evidence:
///
/// - no current-game donor materializes for its identity → the layered view
///   held a single origin for it, so the bytes are the source's; or
/// - its export payloads differ from the pure-current donor's → the bytes
///   cannot be the current game's; or
/// - its payloads equal the donor's AND the source container's raw zen chunk
///   equals the current store's raw chunk → the mod authored no change, so
///   either origin is the same content.
///
/// A payload-identical fallback whose raw source chunk differs from the
/// current chunk means the layered merge substituted current-game content
/// and the mod's authored bytes would be lost — that fails closed.
pub(crate) fn extract_source_composite_packages_with_fallback(
    retoc: &RetocTool,
    input: &Path,
    current_view: &Path,
    source_utocs: &[PathBuf],
    output: &Path,
    packages: &[(PackageEntry, String)],
    label: &str,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for pair in packages {
        if seen.insert(canonical_additive_static_mesh_path(&pair.1)?.to_ascii_lowercase()) {
            deduped.push(pair.clone());
        }
    }
    let mut fallback = Vec::new();
    for pair in &deduped {
        match extract_source_composite_packages_exact(
            retoc,
            input,
            output,
            std::slice::from_ref(pair),
            label,
        ) {
            Ok(()) => {}
            Err(error) => fallback.push((pair.clone(), error)),
        }
    }
    if fallback.is_empty() {
        return Ok(());
    }
    let fallback_work = tempfile::Builder::new()
        .prefix("obr-composite-layered-fallback-")
        .tempdir()?;
    for (index, ((source, effective_path), exclusive_error)) in fallback.into_iter().enumerate() {
        let package_root = fallback_work.path().join(index.to_string());
        let layered_root = package_root.join("layered");
        extract_composite_packages_exact(
            retoc,
            input,
            &layered_root,
            &[(source.clone(), effective_path.clone())],
            &format!("{label} layered fallback"),
        )
        .with_context(|| {
            format!(
                "{label} {}: source-only conversion failed ({exclusive_error:#}) and the layered fallback did not materialize the package either",
                source.path
            )
        })?;
        let layered_asset = find_extracted_additive_static_mesh(&layered_root, &effective_path)?;
        let donor_root = package_root.join("donor");
        let donor = PackageEntry {
            package_id: source.package_id,
            path: effective_path.clone(),
        };
        let donor_asset = extract_composite_packages_exact(
            retoc,
            current_view,
            &donor_root,
            &[(donor.clone(), donor.path.clone())],
            &format!("{label} layered-fallback donor"),
        )
        .ok()
        .map(|()| find_extracted_additive_static_mesh(&donor_root, &donor.path))
        .transpose()?;
        if let Some(donor_asset) = donor_asset {
            let payloads_identical = verify_identical_export_payloads(
                &layered_asset,
                &donor_asset,
                &package_root.join("payload-proof"),
            )
            .is_ok();
            if payloads_identical {
                let source_raw = source_utocs
                    .iter()
                    .find_map(|utoc| {
                        retoc
                            .package_raw_chunk(
                                utoc,
                                source.package_id,
                                &package_root.join("source-raw"),
                            )
                            .ok()
                    })
                    .with_context(|| {
                        format!(
                            "{label} {}: source container raw chunk is unavailable for authorship evidence",
                            source.path
                        )
                    })?;
                let current_raw = retoc.package_raw_chunk(
                    &current_view.join("OblivionRemastered-Windows.utoc"),
                    source.package_id,
                    &package_root.join("current-raw"),
                )?;
                if source_raw != current_raw {
                    bail!(
                        "{label} {}: layered fallback returned the current game's package content while the source container authored different bytes; refusing the substitution",
                        source.path
                    );
                }
            }
        }
        let destination = output.join(canonical_additive_static_mesh_path(&effective_path)?);
        fs::create_dir_all(
            destination
                .parent()
                .context("layered fallback destination has no parent")?,
        )?;
        for extension in ["uasset", "uexp", "ubulk", "uptnl"] {
            let source_sidecar = layered_asset.with_extension(extension);
            if source_sidecar.is_file() {
                let destination_sidecar = destination.with_extension(extension);
                if destination_sidecar.exists() {
                    bail!("{label} layered fallback would overwrite an extracted package");
                }
                fs::copy(&source_sidecar, &destination_sidecar)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn extract_source_composite_packages_exact(
    retoc: &RetocTool,
    input: &Path,
    output: &Path,
    packages: &[(PackageEntry, String)],
    label: &str,
) -> Result<()> {
    let source_only = stage_exclusive_source_view(input)?;
    extract_composite_packages_exact(retoc, source_only.path(), output, packages, label)?;
    // Only packages whose exclusive extraction actually carries unresolved
    // markers consult the layered view; every other package ships the
    // exclusive extraction untouched. The layered view's SIDECARS are never
    // read at all: for a package the current game also carries, the layered
    // chunk merge can hand back the current game's bulk payload, which is
    // exactly the substitution this extraction exists to prevent.
    let marker = b"/Engine/UnknownPackage";
    let mut pending = Vec::new();
    let mut seen = BTreeSet::new();
    for (source, effective_path) in packages {
        if !seen.insert(canonical_additive_static_mesh_path(effective_path)?.to_ascii_lowercase())
        {
            continue;
        }
        let asset = find_extracted_additive_static_mesh(output, effective_path)?;
        let bytes = fs::read(&asset)?;
        if bytes
            .windows(marker.len())
            .any(|window| window == marker.as_slice())
        {
            pending.push((source.clone(), effective_path.clone()));
        }
    }
    if pending.is_empty() {
        return Ok(());
    }
    let resolution_work = tempfile::Builder::new()
        .prefix("obr-composite-name-resolution-")
        .tempdir()?;
    let resolved_root = resolution_work.path().join("legacy");
    extract_composite_packages_exact(
        retoc,
        input,
        &resolved_root,
        &pending,
        &format!("{label} import-name resolution"),
    )?;
    for (source, effective_path) in &pending {
        let exclusive_asset = find_extracted_additive_static_mesh(output, effective_path)?;
        let resolved_asset = find_extracted_additive_static_mesh(&resolved_root, effective_path)?;
        if fs::read(&exclusive_asset)? == fs::read(&resolved_asset)? {
            continue;
        }
        verify_identical_export_payloads(
            &exclusive_asset,
            &resolved_asset,
            &resolution_work
                .path()
                .join("payload-proof")
                .join(source.package_id.to_string()),
        )
        .with_context(|| {
            format!(
                "{label} {effective_path}: layered import-name resolution must preserve the exclusive source extraction's authored export payloads"
            )
        })?;
        // Adopt the UAsset only (import table and NameMap); every sidecar
        // keeps the exclusive source extraction's bytes.
        fs::copy(&resolved_asset, &exclusive_asset)?;
    }
    Ok(())
}

pub(crate) fn extract_source_static_mesh_packages(
    retoc: &RetocTool,
    input: &Path,
    output: &Path,
    source_packages: &[PackageEntry],
    label: &str,
) -> Result<()> {
    fs::create_dir_all(output)?;
    let source_view = stage_exclusive_source_view(input)?;
    for source_package in source_packages {
        let filter = source_static_mesh_package_filter(source_package)?;
        let result = retoc.run([
            OsString::from("to-legacy"),
            source_view.path().as_os_str().to_owned(),
            output.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
            OsString::from("--filter"),
            OsString::from(filter),
        ])?;
        let package_label = format!("{label} {}", source_package.path);
        let (extracted, failed) = RetocTool::extraction_summary(&result, &package_label)?;
        if failed != 0 || extracted == 0 {
            bail!(
                "{package_label} extracted no package payload; extracted {extracted}, failed {failed}"
            );
        }
    }
    Ok(())
}

pub(crate) fn extract_source_packages_exact(
    retoc: &RetocTool,
    input: &Path,
    output: &Path,
    source_packages: &[PackageEntry],
    label: &str,
) -> Result<()> {
    fs::create_dir_all(output)?;
    let expected = source_packages
        .iter()
        .map(|package| Ok(canonical_additive_static_mesh_path(&package.path)?.to_ascii_lowercase()))
        .collect::<Result<BTreeSet<_>>>()?;
    let source_view = stage_exclusive_source_view(input)?;
    let mut filtered_extraction_complete = true;
    for source_package in source_packages {
        let before = extracted_uasset_paths(output)?;
        let filter = source_package_store_filter(source_package)?;
        let package_label = format!("{label} {}", source_package.path);
        let result = retoc.run([
            OsString::from("to-legacy"),
            source_view.path().as_os_str().to_owned(),

            output.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
            OsString::from("--filter"),
            OsString::from(filter),
        ])?;
        let (extracted, failed) = RetocTool::extraction_summary(&result, &package_label)?;
        if failed != 0 || extracted == 0 {
            filtered_extraction_complete = false;
            break;
        }
        let after = extracted_uasset_paths(output)?;
        let added = after.difference(&before).cloned().collect::<Vec<_>>();
        let expected =
            canonical_additive_static_mesh_path(&source_package.path)?.to_ascii_lowercase();
        if added != [expected.clone()] {
            bail!(
                "{package_label} changed an unexpected UAsset set; expected only {expected}, found {}",
                added.join(", ")
            );
        }
    }
    if filtered_extraction_complete {
        return Ok(());
    }

    // Some valid source containers keep dependency-free package payloads in the
    // PAK member even though their package-store row is in the UTOC. Retoc's
    // package filter can report zero for those rows. Fall back to one bounded
    // full extraction in the same exclusive source view, then prove that the
    // exact expected UAsset set (and no other package) was produced.
    let fallback = tempfile::Builder::new()
        .prefix("obr-source-full-extraction-")
        .tempdir()?;
    let result = retoc.run([
        OsString::from("to-legacy"),
        source_view.path().as_os_str().to_owned(),
        fallback.path().as_os_str().to_owned(),
        OsString::from("--version"),
        OsString::from("UE5_3"),
        OsString::from("--no-shaders"),
        OsString::from("--no-script-objects"),
        OsString::from("--no-parallel"),
    ])?;
    let (extracted, failed) =
        RetocTool::extraction_summary(&result, &format!("{label} source-only fallback"))?;
    if failed != 0 || extracted != source_packages.len() {
        bail!(
            "{label} source-only fallback expected {} packages; extracted {extracted}, failed {failed}",
            source_packages.len()
        );
    }
    let actual = extracted_uasset_paths(fallback.path())?;
    if actual != expected {
        bail!(
            "{label} source-only fallback changed the package set; expected {}, found {}",
            expected.iter().cloned().collect::<Vec<_>>().join(", "),
            actual.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    copy_tree(fallback.path(), output)?;
    if extracted_uasset_paths(output)? != expected {
        bail!("{label} source-only fallback did not reconstruct the exact package set");
    }
    Ok(())
}

fn extracted_uasset_paths(root: &Path) -> Result<BTreeSet<String>> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
        })
        .map(|entry| {
            let relative = entry.path().strip_prefix(root)?;
            Ok(
                canonical_additive_static_mesh_path(&relative.to_string_lossy())?
                    .to_ascii_lowercase(),
            )
        })
        .collect()
}
pub fn probe_additive_static_mesh_input(
    mod_input: &Path,
    game_root: &Path,
) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-additive-static-mesh-probe-")
        .tempdir()?;
    let staged = work.path().join("source");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_additive_static_mesh_staged(&staged, game_root, &retoc)?;
    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let legacy = root.join("legacy");
        fs::create_dir_all(&legacy)?;
        let view = create_additive_probe_view(game_root)?;
        for source in [&container.utoc, &container.ucas, &container.pak] {
            copy_probe_file(source, &view.path().join(source.file_name().unwrap()))?;
        }
        extract_source_static_mesh_packages(
            &retoc,
            view.path(),
            &legacy,
            &container.packages,
            "StaticMesh source extraction",
        )?;
        let extracted_uasset_count = WalkDir::new(&legacy)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_file()
                    && entry
                        .path()
                        .extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
            })
            .count();
        if extracted_uasset_count != container.packages.len() {
            bail!(
                "StaticMesh source extraction expected {} exact assets; found {extracted_uasset_count}",
                container.packages.len()
            );
        }
        for package in &container.packages {
            let asset = find_extracted_additive_static_mesh(&legacy, &package.path)?;
            let imports = inspect_static_mesh_asset(&asset).map_err(|error| {
                anyhow::anyhow!(
                    "{} did not pass structural StaticMesh inspection: {error:#}",
                    package.path
                )
            })?;
            if imports
                .iter()
                .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
            {
                let source_row = container
                    .package_store
                    .iter()
                    .find(|entry| entry.package_id == package.package_id)
                    .context("StaticMesh source package store lost a package row")?;
                repair_static_mesh_imports(
                    &asset,
                    &source_row.imported_package_ids,
                    &inspection.target_dependencies,
                    &root
                        .join("import-repairs")
                        .join(package.package_id.to_string()),
                )?;
                let repaired_imports = inspect_static_mesh_asset(&asset)?;
                if repaired_imports
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
                {
                    bail!("{} retained unresolved imports after repair", package.path);
                }
            }
        }
        repair_legacy_body_setups(&legacy)?;
    }
    Ok(ReplacementProbeSummary {
        container_count: inspection.containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: match inspection.target_package_imports.len() {
            0 => "additive-static-mesh",
            count if count == inspection.packages.len() => "existing-static-mesh-replacement",
            _ => "mixed-additive-and-replacement-static-mesh",
        }
        .to_owned(),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets: Vec::new(),
    })
}

pub fn probe_heterogeneous_replacement_input(
    mod_input: &Path,
    game_root: &Path,
) -> Result<HeterogeneousReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-heterogeneous-replacement-probe-")
        .tempdir()?;
    let staged = work.path().join("source");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_heterogeneous_replacement_staged(&staged, game_root, &retoc)?;
    let current_packages_by_id = inspection.target_dependencies.clone();
    let mut rows = Vec::with_capacity(inspection.packages.len());
    let mut static_mesh_count = 0_usize;
    let mut texture_count = 0_usize;

    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let legacy = root.join("legacy");
        let source_view = create_additive_probe_view(game_root)?;
        let current_view = create_additive_probe_view(game_root)?;
        for source in [&container.utoc, &container.ucas, &container.pak] {
            copy_probe_file(
                source,
                &source_view.path().join(source.file_name().unwrap()),
            )?;
        }
        extract_source_packages_exact(
            &retoc,
            source_view.path(),
            &legacy,
            &container.packages,
            "heterogeneous source extraction",
        )?;

        let mut pending = Vec::with_capacity(container.packages.len());
        for package in &container.packages {
            let asset = find_extracted_additive_static_mesh(&legacy, &package.path)?;
            match classify_heterogeneous_asset(&asset)? {
                ProvenHeterogeneousAsset::StaticMesh { imports } => {
                    if imports
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
                    {
                        let source_row = container
                            .package_store
                            .iter()
                            .find(|entry| entry.package_id == package.package_id)
                            .context("heterogeneous source package store lost a StaticMesh row")?;
                        repair_static_mesh_imports(
                            &asset,
                            &source_row.imported_package_ids,
                            &inspection.target_dependencies,
                            &root
                                .join("import-repairs")
                                .join(package.package_id.to_string()),
                        )?;
                        let repaired = inspect_static_mesh_asset(&asset)?;
                        if repaired
                            .iter()
                            .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
                        {
                            bail!("{} retained unresolved imports after repair", package.path);
                        }
                    }
                    static_mesh_count += 1;
                    pending.push((package, None));
                }
                ProvenHeterogeneousAsset::Texture2D(mut source) => {
                    source.asset = canonical_additive_static_mesh_path(&package.path)?;
                    pending.push((package, Some(Box::new(source))));
                }
            }
        }
        // One batched donor extraction per container reads the current package
        // store once instead of once per Texture2D donor.
        let donor_targets = pending
            .iter()
            .filter(|(_, texture_source)| texture_source.is_some())
            .map(|(package, _)| {
                Ok(current_packages_by_id
                    .get(&package.package_id)
                    .context("heterogeneous current package inventory lost an identity")?
                    .clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let mut donor_assets = extract_current_packages_batched(
            &retoc,
            current_view.path(),
            &root.join("current"),
            &donor_targets,
            "heterogeneous current Texture2D extraction",
        )?
        .into_iter();
        for (package, texture_source) in pending {
            let (asset_kind, mut warnings) = match texture_source {
                None => (HeterogeneousReplacementAssetKind::StaticMesh, Vec::new()),
                Some(source) => {
                    let current_asset = donor_assets
                        .next()
                        .context("heterogeneous donor extraction lost a Texture2D asset")?;
                    let current = inspect_texture_asset(&current_asset)?;
                    let validated =
                        validate_texture_replacement_pair(*source, &current, &package.path)?;
                    texture_count += 1;
                    (
                        HeterogeneousReplacementAssetKind::Texture2D,
                        validated.warnings,
                    )
                }
            };
            let source_store = container
                .package_store
                .iter()
                .find(|entry| entry.package_id == package.package_id)
                .context("heterogeneous source package store lost a classified package")?;
            let current_path = current_packages_by_id
                .get(&package.package_id)
                .context("heterogeneous current package inventory lost a classified package")?
                .path
                .clone();
            if let Some(resolution) = container
                .root_alias_replacements
                .iter()
                .find(|resolution| resolution.package_id == package.package_id)
            {
                warnings.push(format!(
                    "Package is stored at its container mount root with no project/Content path (authored {}); its package ID {} uniquely matches current package {} and the filenames agree, so it is classified as a replacement of that package via root alias",
                    resolution.authored_path, resolution.package_id, resolution.current_path
                ));
            } else if !source_store.path.eq_ignore_ascii_case(&current_path) {
                warnings.push(format!(
                    "Package path uses a project-root alias (source {}, current {}); package ID and content-relative suffix match",
                    source_store.path, current_path
                ));
            }
            if matching_import_set(&source_store.imported_package_ids)
                != matching_import_set(
                    inspection
                        .target_package_imports
                        .get(&package.package_id)
                        .context("heterogeneous current import evidence disappeared")?,
                )
            {
                warnings.push(
                    "Authored source imports differ from the current package; the complete source dependency closure is resolved and the source import set will be preserved"
                        .to_owned(),
                );
            }
            let mut imported_package_ids = source_store.imported_package_ids.clone();
            imported_package_ids.sort_unstable();
            rows.push(HeterogeneousReplacementPackageProbe {
                package_id: package.package_id,
                source_path: package.path.clone(),
                current_path,
                asset_kind,
                imported_package_ids,
                warnings,
            });
        }
        repair_legacy_body_setups(&legacy)?;
    }
    if static_mesh_count == 0 || texture_count == 0 {
        bail!(
            "heterogeneous replacement adapter requires at least one structurally proven StaticMesh and one Texture2D package"
        );
    }
    rows.sort_by(|left, right| {
        left.source_path
            .to_ascii_lowercase()
            .cmp(&right.source_path.to_ascii_lowercase())
            .then(left.package_id.cmp(&right.package_id))
    });
    Ok(HeterogeneousReplacementProbeSummary {
        adapter: HETEROGENEOUS_REPLACEMENT_ADAPTER.to_owned(),
        container_count: inspection.containers.len(),
        package_count: rows.len(),
        static_mesh_count,
        texture_count,
        packages: rows,
    })
}

/// Verifies that every planned current-donor rebind was actually consumed by
/// a successful serialized-role skeletal repair of its consumer: the stale
/// target must appear among the repair's missing source imports and must be
/// absent from the donor-derived rebound import set. Any uncovered plan fails
/// the lane instead of shipping a container that still needs the retired
/// package.
pub(crate) fn verify_donor_rebinds_consumed(
    recovery: Option<&CompositeIdentityRecovery>,
    skeletal_donor_repairs: &HashMap<u64, CompositePackageImportRepair>,
) -> Result<()> {
    let Some(recovery) = recovery else {
        return Ok(());
    };
    for rebind in &recovery.donor_rebinds {
        let repair = skeletal_donor_repairs
            .get(&rebind.consumer_package_id)
            .with_context(|| {
                format!(
                    "recovered stale {} dependency {} was not consumed by a serialized-role donor repair of {}",
                    rebind.expected_class, rebind.target_package_name, rebind.consumer_package_path
                )
            })?;
        if !repair
            .missing_source_imported_package_ids
            .contains(&rebind.target_package_id)
        {
            bail!(
                "donor repair of {} did not account for stale dependency {}",
                rebind.consumer_package_path,
                rebind.target_package_name
            );
        }
        if repair
            .target_imported_package_ids
            .contains(&rebind.target_package_id)
        {
            bail!(
                "donor repair of {} still imports stale dependency {}",
                rebind.consumer_package_path,
                rebind.target_package_name
            );
        }
    }
    Ok(())
}

pub const IDENTITY_ALIAS_RECOVERY_PROBE_API: &str = "zen-package-identity-alias-recovery-probe-v1";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityAliasEdgeSummary {
    pub consumer_package_id: u64,
    pub consumer_package_path: String,
    pub stale_package_id: u64,
    pub authored_package_name: String,
    pub alias_source_package_id: u64,
    pub alias_source_package_path: String,
    pub expected_class: String,
    pub role: String,
    pub role_export_name: String,
}

/// Report-only summary of the composite identity-alias recovery run against a staged
/// mod's containers: which stale package IDs recover to disclosed, role-proven,
/// uniquely selected bundled winners.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityAliasRecoveryProbeSummary {
    pub api: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    pub alias_count: usize,
    pub suppression_count: usize,
    pub aliases: Vec<IdentityAliasEdgeSummary>,
    pub blockers: Vec<String>,
}

/// Runs the same fail-closed identity recovery the update lanes use, in a scratch view,
/// and reports the recovered alias plan without mutating anything the caller keeps.
pub fn probe_identity_alias_recovery(
    mod_input: &Path,
    game_root: &Path,
) -> Result<IdentityAliasRecoveryProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-identity-alias-probe-")
        .tempdir()?;
    let staged = work.path().join("source");
    stage_input(mod_input, &staged)?;
    let container_root = unique_container_parent(&staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_composite_package_staged(&container_root, game_root, &retoc)?;
    let source_view = create_additive_probe_view(game_root)?;
    for container in &inspection.containers {
        for source in [&container.utoc, &container.ucas, &container.pak] {
            fs::copy(
                source,
                source_view.path().join(
                    source
                        .file_name()
                        .context("source container has no filename")?,
                ),
            )?;
        }
    }
    let recovery = recover_composite_package_identities(
        &inspection,
        &retoc,
        source_view.path(),
        &work.path().join("identity-recovery"),
    )?;
    let summary = match recovery {
        None => IdentityAliasRecoveryProbeSummary {
            api: IDENTITY_ALIAS_RECOVERY_PROBE_API.to_owned(),
            status: "none-required".to_owned(),
            provider_name: None,
            alias_count: 0,
            suppression_count: 0,
            aliases: Vec::new(),
            blockers: Vec::new(),
        },
        Some(recovery) => IdentityAliasRecoveryProbeSummary {
            api: IDENTITY_ALIAS_RECOVERY_PROBE_API.to_owned(),
            status: "recovered".to_owned(),
            provider_name: recovery
                .provider
                .as_ref()
                .map(|provider| provider.provider_name.clone()),
            alias_count: recovery.aliases.len(),
            suppression_count: recovery.suppressions.len(),
            aliases: recovery
                .aliases
                .iter()
                .map(|alias| IdentityAliasEdgeSummary {
                    consumer_package_id: alias.consumer_package_id,
                    consumer_package_path: alias.consumer_package_path.clone(),
                    stale_package_id: alias.identity.target_package_id,
                    authored_package_name: alias.identity.target_package_path.clone(),
                    alias_source_package_id: alias.identity.source_package_id,
                    alias_source_package_path: alias.identity.source_package_path.clone(),
                    expected_class: alias.expected_class.clone(),
                    role: alias.role.role.clone(),
                    role_export_name: alias.role.export_name.clone(),
                })
                .collect(),
            blockers: Vec::new(),
        },
    };
    Ok(summary)
}

pub fn probe_composite_package_input(
    mod_input: &Path,
    game_root: &Path,
) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-composite-package-probe-")
        .tempdir()?;
    let staged = work.path().join("source");
    let legacy = work.path().join("legacy");
    stage_input(mod_input, &staged)?;
    let container_root = unique_container_parent(&staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_composite_package_staged(&container_root, game_root, &retoc)?;
    for package in &inspection.packages {
        let effective = composite_effective_package_path(package, &inspection)?;
        canonical_additive_static_mesh_path(&effective).with_context(|| {
            format!(
                "composite identity {} did not resolve source {} to a current or additive content path",
                package.package_id, package.path
            )
        })?;
    }
    let source_view = create_additive_probe_view(game_root)?;
    let current_view = create_additive_probe_view(game_root)?;
    for container in &inspection.containers {
        for source in [&container.utoc, &container.ucas, &container.pak] {
            fs::copy(
                source,
                source_view.path().join(
                    source
                        .file_name()
                        .context("source container has no filename")?,
                ),
            )?;
        }
    }
    let identity_recovery = recover_composite_package_identities(
        &inspection,
        &retoc,
        source_view.path(),
        &work.path().join("identity-recovery"),
    )?;
    for container in &inspection.containers {
        let packages = container
            .packages
            .iter()
            .map(|package| {
                Ok((
                    package.clone(),
                    composite_effective_package_path(package, &inspection)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let source_utocs = inspection
            .containers
            .iter()
            .map(|container| container.utoc.clone())
            .collect::<Vec<_>>();
        extract_source_composite_packages_with_fallback(
            &retoc,
            source_view.path(),
            current_view.path(),
            &source_utocs,
            &legacy,
            &packages,
            "composite source extraction",
        )?;
    }
    let mut available_dependencies = inspection.target_dependencies.clone();
    for package in &inspection.packages {
        available_dependencies
            .entry(package.package_id)
            .or_insert_with(|| package.clone());
    }
    if let Some(recovery) = &identity_recovery {
        for alias in &recovery.aliases {
            available_dependencies
                .entry(alias.target_package.package_id)
                .or_insert_with(|| alias.target_package.clone());
        }
        for suppression in &recovery.suppressions {
            available_dependencies
                .entry(suppression.target_package.package_id)
                .or_insert_with(|| suppression.target_package.clone());
        }
    }
    let source_ids = inspection
        .packages
        .iter()
        .map(|package| package.package_id)
        .collect::<HashSet<_>>();
    let source_store = inspection
        .containers
        .iter()
        .flat_map(|container| container.package_store.iter())
        .map(|entry| (entry.package_id, entry))
        .collect::<HashMap<_, _>>();
    let mut kinds = BTreeMap::<&'static str, usize>::new();
    let mut skeletal_donor_repairs = HashMap::new();
    for package in &inspection.packages {
        let effective_path = composite_effective_package_path(package, &inspection)?;
        let asset = find_extracted_additive_static_mesh(&legacy, &effective_path)?;
        let existing = inspection
            .target_dependencies
            .contains_key(&package.package_id);
        let package_work = work
            .path()
            .join("packages")
            .join(package.package_id.to_string());
        let (kind, unresolved) = classify_composite_package_asset(
            &asset,
            existing,
            &package_work.join("classification"),
        )
        .with_context(|| format!("classifying composite package {}", package.path))?;
        let store = source_store
            .get(&package.package_id)
            .context("composite source package store lost a package")?;
        let mut effective_store = (*store).clone();
        if let Some(recovery) = &identity_recovery {
            let suppressions = recovery
                .suppressions
                .iter()
                .filter(|suppression| suppression.consumer_package_id == package.package_id)
                .collect::<Vec<_>>();
            if suppressions.len() > 1 {
                bail!("one Blueprint package requires multiple optional dependency suppressions");
            }
            if let Some(suppression) = suppressions.first() {
                let replacement = PackageEntry {
                    package_id: suppression.temporary_source_package.package_id,
                    path: suppression.temporary_identity.source_package_path.clone(),
                };
                let result = suppress_optional_blueprint_dependency(
                    &asset,
                    store,
                    &suppression.target_package,
                    &replacement,
                    &suppression.temporary_identity.source_object_name,
                    &suppression.role,
                    &package_work.join("optional-component-suppression"),
                )?;
                effective_store.imported_package_ids = result.target_imported_package_ids;
            }
        }
        let missing_store_dependencies = effective_store
            .imported_package_ids
            .iter()
            .filter(|dependency| !available_dependencies.contains_key(dependency))
            .count();
        match kind {
            CompositePackageAssetKind::SkeletalMesh => {
                *kinds.entry("skeletal-mesh").or_default() += 1;
                if !existing {
                    bail!(
                        "additive SkeletalMesh packages require a separate proven donor contract"
                    );
                }
                if unresolved != 0 {
                    let current = inspection
                        .target_dependencies
                        .get(&package.package_id)
                        .context("existing SkeletalMesh has no current donor identity")?;
                    let donor_root = package_work.join("current");
                    extract_composite_packages_exact(
                        &retoc,
                        current_view.path(),
                        &donor_root,
                        &[(current.clone(), current.path.clone())],
                        "current SkeletalMesh extraction",
                    )?;
                    let donor = find_extracted_additive_static_mesh(&donor_root, &current.path)?;
                    let repair = repair_composite_skeletal_mesh_imports(
                        &asset,
                        &donor,
                        store,
                        &available_dependencies,
                        &package_work.join("repair"),
                    )
                    .with_context(|| {
                        format!("repairing composite SkeletalMesh {}", package.path)
                    })?;
                    skeletal_donor_repairs.insert(package.package_id, repair);
                } else if missing_store_dependencies != 0 {
                    bail!("resolved SkeletalMesh retains unresolved package-store dependencies");
                }
            }
            CompositePackageAssetKind::StaticMesh => {
                *kinds.entry("static-mesh").or_default() += 1;
                let imports = inspect_static_mesh_asset(&asset)?;
                if imports
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
                {
                    repair_static_mesh_imports(
                        &asset,
                        &effective_store.imported_package_ids,
                        &available_dependencies,
                        &package_work.join("repair"),
                    )?;
                } else if missing_store_dependencies != 0 {
                    bail!("resolved StaticMesh retains unresolved package-store dependencies");
                }
            }
            CompositePackageAssetKind::Texture2D => {
                *kinds.entry("texture2d").or_default() += 1;
                inspect_texture_asset(&asset)?;
                if unresolved != 0 {
                    if !existing {
                        bail!("additive Texture2D has unresolved imports");
                    }
                    let current = inspection
                        .target_dependencies
                        .get(&package.package_id)
                        .context("existing Texture2D has no current template")?;
                    let donor_root = package_work.join("current");
                    extract_composite_packages_exact(
                        &retoc,
                        current_view.path(),
                        &donor_root,
                        &[(current.clone(), current.path.clone())],
                        "current Texture2D extraction",
                    )?;
                    let donor = find_extracted_additive_static_mesh(&donor_root, &current.path)?;
                    repair_current_template_imports(
                        &asset,
                        &donor,
                        store,
                        &available_dependencies,
                        &package_work.join("repair"),
                    )?;
                } else if missing_store_dependencies != 0 {
                    bail!("resolved Texture2D retains unresolved package-store dependencies");
                }
            }
            CompositePackageAssetKind::MaterialInstanceConstant => {
                *kinds.entry("material-instance").or_default() += 1;
                if unresolved != 0 {
                    if existing {
                        let current = inspection
                            .target_dependencies
                            .get(&package.package_id)
                            .context("existing material instance has no current template")?;
                        let donor_root = package_work.join("current");
                        extract_composite_packages_exact(
                            &retoc,
                            current_view.path(),
                            &donor_root,
                            &[(current.clone(), current.path.clone())],
                            "current material extraction",
                        )?;
                        let donor =
                            find_extracted_additive_static_mesh(&donor_root, &current.path)?;
                        repair_current_template_imports(
                            &asset,
                            &donor,
                            store,
                            &available_dependencies,
                            &package_work.join("repair"),
                        )?;
                    } else {
                        let targets = store
                            .imported_package_ids
                            .iter()
                            .filter(|dependency| !source_ids.contains(dependency))
                            .filter_map(|dependency| inspection.target_dependencies.get(dependency))
                            .collect::<Vec<_>>();
                        if targets.len() != 1 {
                            bail!(
                                "additive material with one unresolved public export must have exactly one external current dependency; found {}",
                                targets.len()
                            );
                        }
                        let target = targets[0];
                        let donor_root = package_work.join("dependency");
                        extract_composite_packages_exact(
                            &retoc,
                            current_view.path(),
                            &donor_root,
                            &[(target.clone(), target.path.clone())],
                            "current material-parent extraction",
                        )?;
                        let donor = find_extracted_additive_static_mesh(&donor_root, &target.path)?;
                        repair_single_external_import(
                            &asset,
                            &donor,
                            target,
                            store,
                            &available_dependencies,
                            &package_work.join("repair"),
                        )?;
                    }
                } else if missing_store_dependencies != 0 {
                    bail!(
                        "resolved material instance retains unresolved package-store dependencies"
                    );
                }
            }
            CompositePackageAssetKind::ResolvedAuthoredPackage => {
                *kinds.entry("resolved-authored-package").or_default() += 1;
                if missing_store_dependencies != 0 {
                    bail!("authored package retains unresolved package-store dependencies");
                }
                if unresolved != 0 {
                    let targets = unresolved_package_store_dependencies(
                        &asset,
                        &effective_store,
                        &available_dependencies,
                        &package_work.join("unresolved-package-store"),
                    )?;
                    if targets.len() != 1 {
                        bail!(
                            "authored package decoder repair requires exactly one package-store-proven target; found {}",
                            targets.len()
                        );
                    }
                    let target = &targets[0];
                    let donor_root = package_work.join("resolved-dependency");
                    // The proven target is either a current-game package (read
                    // from the pure current view) or a source-bundled package
                    // (read from the exclusive source-only view); a merged
                    // view could silently substitute bytes for shared IDs.
                    if inspection.target_dependencies.contains_key(&target.package_id) {
                        extract_composite_packages_exact(
                            &retoc,
                            current_view.path(),
                            &donor_root,
                            &[(target.clone(), target.path.clone())],
                            "authored package dependency extraction",
                        )?;
                    } else {
                        extract_source_composite_packages_exact(
                            &retoc,
                            source_view.path(),
                            &donor_root,
                            &[(target.clone(), target.path.clone())],
                            "authored package dependency extraction",
                        )?;
                    }
                    let donor = find_extracted_additive_static_mesh(&donor_root, &target.path)?;
                    repair_single_external_import(
                        &asset,
                        &donor,
                        target,
                        &effective_store,
                        &available_dependencies,
                        &package_work.join("repair"),
                    )?;
                }
            }
            CompositePackageAssetKind::CurrentTemplatePackage => {
                *kinds.entry("current-template-package").or_default() += 1;
                let current = inspection
                    .target_dependencies
                    .get(&package.package_id)
                    .context("current-template package has no current identity")?;
                let donor_root = package_work.join("current");
                extract_composite_packages_exact(
                    &retoc,
                    current_view.path(),
                    &donor_root,
                    &[(current.clone(), current.path.clone())],
                    "current template extraction",
                )?;
                let donor = find_extracted_additive_static_mesh(&donor_root, &current.path)?;
                repair_current_template_imports(
                    &asset,
                    &donor,
                    store,
                    &available_dependencies,
                    &package_work.join("repair"),
                )?;
            }
        }
    }
    verify_donor_rebinds_consumed(identity_recovery.as_ref(), &skeletal_donor_repairs)?;
    let donor_rebind_count = identity_recovery
        .as_ref()
        .map(|recovery| recovery.donor_rebinds.len())
        .unwrap_or(0);
    let mut kind_summary = kinds
        .into_iter()
        .map(|(kind, count)| format!("{count} {kind}"))
        .collect::<Vec<_>>()
        .join(", ");
    if donor_rebind_count > 0 {
        kind_summary = format!(
            "{kind_summary}; {donor_rebind_count} stale dependency edge(s) rebound to the current game revision by serialized-role donor repair"
        );
    }
    Ok(ReplacementProbeSummary {
        container_count: inspection.containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: format!("composite-package-rebase ({kind_summary})"),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets: Vec::new(),
    })
}

pub fn probe_texture_input(mod_input: &Path, game_root: &Path) -> Result<ReplacementProbeSummary> {
    let work = tempfile::Builder::new()
        .prefix("obr-texture-replacement-probe-")
        .tempdir()?;
    let staged = work.path().join("source");
    stage_input(mod_input, &staged)?;
    let retoc = RetocTool::materialize()?;
    let inspection = inspect_texture_staged(&staged, game_root, &retoc)?;
    let (_, current_packages) = retoc.package_entries(&inspection.target_utoc)?;
    let current_packages_by_id = current_packages
        .into_iter()
        .map(|package| (package.package_id, package))
        .collect::<HashMap<_, _>>();
    let game_paks = game_root.join(r"OblivionRemastered\Content\Paks");
    let global_utoc = game_paks.join("global.utoc");
    let global_ucas = game_paks.join("global.ucas");
    let mut texture_assets = Vec::new();

    for container in &inspection.containers {
        let root = work.path().join("containers").join(&container.name);
        let input = root.join("input");
        let legacy = root.join("legacy");
        fs::create_dir_all(&input)?;
        for source in [
            &global_utoc,
            &global_ucas,
            &container.utoc,
            &container.ucas,
            &container.pak,
        ] {
            copy_probe_file(source, &input.join(source.file_name().unwrap()))?;
        }
        let result = retoc.run([
            OsString::from("to-legacy"),
            input.as_os_str().to_owned(),
            legacy.as_os_str().to_owned(),
            OsString::from("--version"),
            OsString::from("UE5_3"),
            OsString::from("--no-shaders"),
            OsString::from("--no-script-objects"),
            OsString::from("--no-parallel"),
        ])?;
        let (extracted, failed) =
            RetocTool::extraction_summary(&result, "texture source extraction")?;
        if failed != 0 || extracted != container.packages.len() {
            bail!(
                "texture source extraction expected {} assets; extracted {extracted}, failed {failed}",
                container.packages.len()
            );
        }
        for package in &container.packages {
            let source_asset = find_extracted_asset(&legacy, &package.path)?;
            let mut source = inspect_texture_asset(&source_asset).map_err(|_| {
                anyhow::anyhow!(
                    "{} did not pass structural Texture2D inspection",
                    package.path
                )
            })?;
            source.asset = package.path.clone();

            let current_root = work
                .path()
                .join("current")
                .join(package.package_id.to_string());
            let current_package = current_packages_by_id
                .get(&package.package_id)
                .with_context(|| {
                    format!(
                        "current Texture2D package inventory is missing {}",
                        package.path
                    )
                })?;
            let current_asset = extract_current_texture_package(
                &retoc,
                &game_paks,
                &current_root,
                current_package,
                "current Texture2D extraction",
            )?;
            let current = inspect_texture_asset(&current_asset).map_err(|_| {
                anyhow::anyhow!(
                    "current target {} did not pass structural Texture2D inspection",
                    package.path
                )
            })?;
            if !source
                .object_name
                .eq_ignore_ascii_case(&current.object_name)
            {
                bail!(
                    "Texture2D object identity changed for {}: source {}, current {}",
                    package.path,
                    source.object_name,
                    current.object_name
                );
            }
            if !source
                .pixel_format
                .eq_ignore_ascii_case(&current.pixel_format)
            {
                bail!(
                    "Texture2D pixel format differs from the current target for {}: source {}, current {}",
                    package.path,
                    source.pixel_format,
                    current.pixel_format
                );
            }
            if source.use_separate_bulk_data_files != current.use_separate_bulk_data_files {
                source.warnings.push(format!(
                    "Bulk streaming layout differs from the current target (source separate={}, current separate={}); sidecars will be preserved and runtime testing is required",
                    source.use_separate_bulk_data_files,
                    current.use_separate_bulk_data_files
                ));
            }
            texture_assets.push(source);
        }
    }
    texture_assets.sort_by_key(|asset| asset.asset.to_ascii_lowercase());
    Ok(ReplacementProbeSummary {
        container_count: inspection.containers.len(),
        package_count: inspection.packages.len(),
        asset_kind: "texture2d".to_owned(),
        package_paths: inspection
            .packages
            .iter()
            .map(|package| package.path.clone())
            .collect(),
        texture_assets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_pool_tolerates_exact_cross_container_duplicates_only() {
        let entry = |id: u64, path: &str| PackageEntry {
            package_id: id,
            path: path.to_owned(),
        };
        let store = |id: u64, path: &str, imports: &[u64]| PackageStoreEntry {
            package_id: id,
            path: path.to_owned(),
            imported_package_ids: imports.to_vec(),
        };
        // The same authored package cooked into two shipped containers with one
        // identity, path, and import set is benign equal-mount-order duplication.
        let pooled = pool_unique_composite_packages(
            vec![
                entry(10, "../../../Mod/Content/Forms/BP_Item.uasset"),
                entry(20, "../../../Mod/Content/Forms/WeapItem.uasset"),
                entry(10, "../../../Mod/Content/Forms/BP_Item.uasset"),
            ],
            &[
                store(10, "../../../Mod/Content/Forms/BP_Item.uasset", &[20]),
                store(20, "../../../Mod/Content/Forms/WeapItem.uasset", &[]),
                store(10, "../../../Mod/Content/Forms/BP_Item.uasset", &[20]),
            ],
        )
        .unwrap();
        assert_eq!(pooled.len(), 2);

        // One package ID with two different paths is a real conflict.
        assert!(
            pool_unique_composite_packages(
                vec![
                    entry(10, "../../../Mod/Content/Forms/BP_Item.uasset"),
                    entry(10, "../../../Mod/Content/Forms/Other.uasset"),
                ],
                &[
                    store(10, "../../../Mod/Content/Forms/BP_Item.uasset", &[]),
                    store(10, "../../../Mod/Content/Forms/Other.uasset", &[]),
                ],
            )
            .is_err()
        );

        // One path with two different package IDs is a real conflict.
        assert!(
            pool_unique_composite_packages(
                vec![
                    entry(10, "../../../Mod/Content/Forms/BP_Item.uasset"),
                    entry(11, "../../../Mod/Content/Forms/BP_ITEM.uasset"),
                ],
                &[
                    store(10, "../../../Mod/Content/Forms/BP_Item.uasset", &[]),
                    store(11, "../../../Mod/Content/Forms/BP_ITEM.uasset", &[]),
                ],
            )
            .is_err()
        );

        // Identical identity and path but diverging import sets is a real conflict.
        assert!(
            pool_unique_composite_packages(
                vec![
                    entry(10, "../../../Mod/Content/Forms/BP_Item.uasset"),
                    entry(20, "../../../Mod/Content/Forms/WeapItem.uasset"),
                    entry(10, "../../../Mod/Content/Forms/BP_Item.uasset"),
                ],
                &[
                    store(10, "../../../Mod/Content/Forms/BP_Item.uasset", &[20]),
                    store(20, "../../../Mod/Content/Forms/WeapItem.uasset", &[]),
                    store(10, "../../../Mod/Content/Forms/BP_Item.uasset", &[]),
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn exact_reconstruction_accepts_previously_materialized_requests_only() {
        let set = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<BTreeSet<_>>()
        };
        // Fresh extraction of the requested package.
        verify_exact_reconstruction(&set(&[]), &set(&["a"]), &set(&["a"]), "test").unwrap();
        // A repeated request whose package a prior call already materialized.
        verify_exact_reconstruction(&set(&["a"]), &set(&["a"]), &set(&["a"]), "test").unwrap();
        // A requested package that never materialized fails closed.
        assert!(verify_exact_reconstruction(&set(&[]), &set(&[]), &set(&["a"]), "test").is_err());
        // Anything materialized beyond the requested set fails closed.
        assert!(
            verify_exact_reconstruction(&set(&[]), &set(&["a", "b"]), &set(&["a"]), "test")
                .is_err()
        );
    }

    #[test]
    fn maps_any_valid_project_content_root_to_game_mount() {
        assert_eq!(
            mounted_game_package_name("../../../ExampleProject/Content/Items/SM_Item.uasset")
                .unwrap(),
            "/Game/Items/SM_Item"
        );
        assert!(mounted_game_package_name("A/B/Content/Items/SM_Item.uasset").is_err());
    }

    fn store(package_id: u64, path: &str, imported_package_ids: &[u64]) -> PackageStoreEntry {
        PackageStoreEntry {
            package_id,
            path: path.to_owned(),
            imported_package_ids: imported_package_ids.to_vec(),
        }
    }

    fn diagnostic_container(
        name: &str,
        relative_utoc: &str,
        package_store: Vec<PackageStoreEntry>,
    ) -> DiagnosticContainer {
        DiagnosticContainer {
            name: name.to_owned(),
            relative_utoc: relative_utoc.to_owned(),
            package_store,
        }
    }

    fn texture_diagnostic(
        object_name: &str,
        pixel_format: &str,
        separate_bulk: bool,
    ) -> TextureAssetDiagnostic {
        TextureAssetDiagnostic {
            asset: "Fixture.uasset".to_owned(),
            object_name: object_name.to_owned(),
            class_name: "Texture2D".to_owned(),
            pixel_format: pixel_format.to_owned(),
            use_separate_bulk_data_files: separate_bulk,
            data_resource_count: 1,
            declared_raw_resource_bytes: 16,
            export_serial_bytes: 16,
            uasset_bytes: 16,
            uexp_bytes: Some(16),
            ubulk_bytes: None,
            packed_texture_kind: None,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn derives_retired_sidecar_identities_from_the_consumer_package_name() {
        // Witness (Shivering Isles Clothing Mesh Fixes, Nexus 3738): the
        // bundled dress imports its author-project sidecars, whose package
        // IDs derive exactly from the mesh's own mounted name.
        let dress = "/Game/Art/Clothes/SpecialClass/SEDuchess/SK_SE_Duchess_Dress";
        assert_eq!(
            derived_sidecar_route(dress, 3_956_433_960_298_804_666),
            Some((format!("{dress}_Skeleton"), "Skeleton"))
        );
        assert_eq!(
            derived_sidecar_route(dress, 6_250_700_512_222_885_520),
            Some((format!("{dress}_PhysicsAsset"), "PhysicsAsset"))
        );
        // Witness (CL_Blades, Nexus 3386): the author renamed the meshes but
        // kept project sidecar names (SK_Iron_Boots_B_*), so derivation from
        // the consumer name must NOT match; that class stays on the raw
        // NameMap recovery route.
        let boots = "/Game/Art/Armor/Blades/SK_Blades_Boots";
        assert_eq!(
            derived_sidecar_route(boots, 4_377_219_594_466_101_747),
            None
        );
        assert_eq!(
            derived_sidecar_route(boots, 14_019_482_699_950_780_448),
            None
        );
    }

    #[test]
    fn routes_recovered_dependencies_by_structural_class() {
        assert_eq!(
            recovered_dependency_route("MIC_Hobbe_BattleAxe"),
            Some(RecoveredDependencyRoute::BundledAlias(
                "MaterialInstanceConstant"
            ))
        );
        assert_eq!(
            recovered_dependency_route("SM_FarmWeapShears_Scabbard"),
            Some(RecoveredDependencyRoute::BundledAlias("StaticMesh"))
        );
        // Retired Unreal-editor default sidecars of a skeletal mesh route to
        // the current-donor serialized-role repair.
        assert_eq!(
            recovered_dependency_route("SK_SE_Duchess_Dress_Skeleton"),
            Some(RecoveredDependencyRoute::CurrentDonorRebind("Skeleton"))
        );
        assert_eq!(
            recovered_dependency_route("SK_Iron_Boots_B_PhysicsAsset"),
            Some(RecoveredDependencyRoute::CurrentDonorRebind("PhysicsAsset"))
        );
    }

    #[test]
    fn does_not_route_current_game_naming_or_plain_meshes() {
        // The current game names engine Skeleton/PhysicsAsset packages with
        // SKEL_/PA_ prefixes, and "Skeleton" also appears as an undead
        // creature name; none of those may be treated as retired sidecars.
        assert_eq!(recovered_dependency_route("SKEL_HumanoidSkeleton"), None);
        assert_eq!(recovered_dependency_route("PA_HumanoidFull"), None);
        assert_eq!(recovered_dependency_route("BP_Horse_Skeleton"), None);
        assert_eq!(recovered_dependency_route("T_Iron_Boots_D"), None);
        // A plain skeletal mesh is never a sidecar of another mesh.
        assert_eq!(recovered_dependency_route("SK_Blades_Boots"), None);
        assert_eq!(
            recovered_dependency_route("SK_Chainmail_Cuirass_f_Physics"),
            None
        );
    }

    #[test]
    fn mixed_replacement_diagnostic_reports_exact_identity_and_resolved_dependencies() {
        let source_a = store(
            10,
            "../../../OblivionRemastered/Content/Weapons/A.uasset",
            &[20],
        );
        let source_b = store(
            20,
            "../../../OblivionRemastered/Content/Materials/B.uasset",
            &[30],
        );
        let current = vec![
            source_a.clone(),
            source_b.clone(),
            store(
                30,
                "../../../OblivionRemastered/Content/Materials/C.uasset",
                &[],
            ),
        ];
        let report = build_mixed_replacement_diagnostic_report(
            vec![diagnostic_container(
                "Fixture_P",
                "Content/Paks/~mods/Fixture_P.utoc",
                vec![source_b, source_a],
            )],
            current,
        )
        .unwrap();

        assert_eq!(report.api, MIXED_REPLACEMENT_PACKAGE_DIAGNOSTIC_API);
        assert_eq!(report.status, "complete-report-only");
        assert_eq!(report.mutation_policy, "report-only");
        assert!(!report.automatic_update_enabled);
        assert_eq!(report.container_count, 1);
        assert_eq!(report.source_package_count, 2);
        assert_eq!(report.exact_replacement_count, 2);
        assert_eq!(report.additive_package_count, 0);
        assert_eq!(report.conflict_package_count, 0);
        assert_eq!(report.dependencies.resolved_edge_count, 2);
        assert_eq!(report.dependencies.bundled_edge_count, 1);
        assert_eq!(report.dependencies.current_game_edge_count, 1);
        assert_eq!(report.dependencies.unresolved_edge_count, 0);
        assert!(report.blockers.is_empty());
        assert!(report.packages.iter().all(|package| {
            package.identity_status == MixedReplacementIdentityStatus::ExactReplacement
                && package.container == "Content/Paks/~mods/Fixture_P.utoc"
                && !package.name.is_empty()
        }));
    }

    #[test]
    fn mixed_replacement_diagnostic_retains_additive_conflict_and_unresolved_rows() {
        let source = vec![
            store(
                10,
                "../../../OblivionRemastered/Content/Custom/Additive.uasset",
                &[999],
            ),
            store(
                20,
                "../../../OblivionRemastered/Content/Stock/PathConflict.uasset",
                &[],
            ),
            store(
                30,
                "../../../OblivionRemastered/Content/Custom/IdConflict.uasset",
                &[],
            ),
            store(
                40,
                "../../../OblivionRemastered/Content/Stock/BothConflict.uasset",
                &[],
            ),
        ];
        let current = vec![
            store(
                21,
                "../../../OblivionRemastered/Content/Stock/PathConflict.uasset",
                &[],
            ),
            store(
                30,
                "../../../OblivionRemastered/Content/Stock/IdConflict.uasset",
                &[],
            ),
            store(
                40,
                "../../../OblivionRemastered/Content/Stock/OtherById.uasset",
                &[],
            ),
            store(
                41,
                "../../../OblivionRemastered/Content/Stock/BothConflict.uasset",
                &[],
            ),
        ];
        let report = build_mixed_replacement_diagnostic_report(
            vec![diagnostic_container(
                "Mixed_P",
                "Content/Paks/~mods/Mixed_P.utoc",
                source,
            )],
            current,
        )
        .unwrap();

        assert_eq!(report.status, "blocked");
        assert_eq!(report.exact_replacement_count, 0);
        assert_eq!(report.additive_package_count, 1);
        assert_eq!(report.conflict_package_count, 3);
        assert_eq!(report.path_conflict_count, 2);
        assert_eq!(report.package_id_conflict_count, 2);
        assert_eq!(report.dependencies.unresolved_edge_count, 1);
        assert_eq!(
            report.dependencies.unresolved_edges[0].missing_dependency_package_id,
            999
        );
        assert_eq!(report.blockers.len(), 3);
        assert!(report.packages.iter().any(|package| {
            package.package_id == 10
                && package.identity_status == MixedReplacementIdentityStatus::Additive
        }));
        assert!(report.packages.iter().any(|package| {
            package.package_id == 20
                && package.identity_status == MixedReplacementIdentityStatus::PathConflict
                && package.current_path_match_package_id == Some(21)
        }));
        assert!(report.packages.iter().any(|package| {
            package.package_id == 30
                && package.identity_status == MixedReplacementIdentityStatus::PackageIdConflict
                && package.current_id_match_path.as_deref()
                    == Some("../../../OblivionRemastered/Content/Stock/IdConflict.uasset")
        }));
        assert!(report.packages.iter().any(|package| {
            package.package_id == 40
                && package.identity_status
                    == MixedReplacementIdentityStatus::PathAndPackageIdConflict
        }));
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(
            serialized["dependencies"]["unresolvedEdges"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn mixed_replacement_diagnostic_resolves_bare_root_packages_by_unique_package_id() {
        let source = vec![
            // Stored at the container mount root with no project/Content prefix,
            // but its package ID and filename match exactly one current package.
            store(50, "../../../BP_RootAlias.uasset", &[]),
            // Bare-root file whose name does not match its ID's current package:
            // identity is ambiguous, so it must stay a conflict.
            store(60, "../../../BP_WrongName.uasset", &[]),
            // ID match with an unrecognized directory path is not a root alias.
            store(70, "../../../SomeDir/BP_Nested.uasset", &[]),
        ];
        let current = vec![
            store(
                50,
                "../../../OblivionRemastered/Content/Forms/items/armor/BP_RootAlias.uasset",
                &[],
            ),
            store(
                60,
                "../../../OblivionRemastered/Content/Forms/items/armor/BP_Other.uasset",
                &[],
            ),
            store(
                70,
                "../../../OblivionRemastered/Content/Forms/items/armor/BP_Nested.uasset",
                &[],
            ),
        ];
        let report = build_mixed_replacement_diagnostic_report(
            vec![diagnostic_container(
                "RootAlias_P",
                "Content/Paks/~mods/RootAlias_P.utoc",
                source,
            )],
            current,
        )
        .unwrap();

        assert_eq!(report.exact_replacement_count, 0);
        assert_eq!(report.root_alias_replacement_count, 1);
        assert_eq!(report.additive_package_count, 0);
        assert_eq!(report.conflict_package_count, 2);
        assert_eq!(report.package_id_conflict_count, 2);
        assert!(report.packages.iter().any(|package| {
            package.package_id == 50
                && package.identity_status
                    == MixedReplacementIdentityStatus::ExactReplacementViaRootAlias
                && package.current_id_match_path.as_deref()
                    == Some(
                        "../../../OblivionRemastered/Content/Forms/items/armor/BP_RootAlias.uasset",
                    )
        }));
        assert!(report.packages.iter().any(|package| {
            package.package_id == 60
                && package.identity_status == MixedReplacementIdentityStatus::PackageIdConflict
        }));
        assert!(report.packages.iter().any(|package| {
            package.package_id == 70
                && package.identity_status == MixedReplacementIdentityStatus::PackageIdConflict
        }));
        assert_eq!(
            report.blockers,
            vec!["source-package-identity-conflicts-with-current-game:found-2".to_owned()]
        );
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("../../../BP_RootAlias.uasset")
                && warning.contains(
                    "../../../OblivionRemastered/Content/Forms/items/armor/BP_RootAlias.uasset",
                )
                && warning.contains("mount root")
        }));
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(
            serialized["packages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["packageId"].as_u64() == Some(50))
                .unwrap()["identityStatus"],
            "exact-replacement-via-root-alias"
        );
        assert_eq!(serialized["rootAliasReplacementCount"].as_u64(), Some(1));
    }

    #[test]
    fn diagnostic_container_discovery_tolerates_passive_documentation_only() {
        let retoc = RetocTool::materialize().unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("readme.txt"), b"docs").unwrap();
        // Passive documentation must not abort the diagnostic; with no
        // container triples left the discovery reports that honestly.
        let error = discover_diagnostic_containers(root.path(), &retoc)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no container triples"), "{error}");

        // A functional loose file still fails closed.
        fs::write(root.path().join("loader.lua"), b"script").unwrap();
        let error = discover_diagnostic_containers(root.path(), &retoc)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not Unreal-container-only"), "{error}");
    }

    #[test]
    fn bare_root_alias_leaf_accepts_only_single_traversal_free_leaves() {
        assert_eq!(
            bare_root_alias_leaf("../../../BP_Item.uasset").as_deref(),
            Some("BP_Item.uasset")
        );
        assert_eq!(
            bare_root_alias_leaf("..\\..\\..\\Map_Item.umap").as_deref(),
            Some("Map_Item.umap")
        );
        assert_eq!(
            bare_root_alias_leaf("BP_Item.uasset").as_deref(),
            Some("BP_Item.uasset")
        );
        assert_eq!(bare_root_alias_leaf("../../../Dir/BP_Item.uasset"), None);
        assert_eq!(
            bare_root_alias_leaf("../../../OblivionRemastered/Content/Forms/BP_Item.uasset"),
            None
        );
        assert_eq!(bare_root_alias_leaf("../../../BP_Item.txt"), None);
        assert_eq!(bare_root_alias_leaf("../../../.."), None);
        assert_eq!(bare_root_alias_leaf("../../../"), None);
        assert_eq!(bare_root_alias_leaf("../../../Dir/../BP_Item.uasset"), None);
    }

    #[test]
    fn bare_root_identity_resolves_only_with_unique_id_and_filename_agreement() {
        let current = vec![
            store(
                50,
                "../../../OblivionRemastered/Content/Forms/items/clothes/BP_RootAlias.uasset",
                &[],
            ),
            store(
                60,
                "../../../OblivionRemastered/Content/Forms/items/clothes/BP_Other.uasset",
                &[],
            ),
        ];
        // Full evidence: bare root, unique ID, filenames agree.
        assert_eq!(
            resolve_bare_root_package_identity("../../../BP_RootAlias.uasset", 50, &current)
                .as_deref(),
            Some("../../../OblivionRemastered/Content/Forms/items/clothes/BP_RootAlias.uasset")
        );
        // Filename disagreement is not an identity proof.
        assert_eq!(
            resolve_bare_root_package_identity("../../../BP_RootAlias.uasset", 60, &current),
            None
        );
        // A nested path is not a bare mount-root package.
        assert_eq!(
            resolve_bare_root_package_identity("../../../Dir/BP_RootAlias.uasset", 50, &current),
            None
        );
        // An ID the current game does not carry cannot resolve.
        assert_eq!(
            resolve_bare_root_package_identity("../../../BP_RootAlias.uasset", 70, &current),
            None
        );
        // A duplicated current package ID is ambiguous and disqualifies itself.
        let duplicated = vec![
            store(
                50,
                "../../../OblivionRemastered/Content/A/BP_RootAlias.uasset",
                &[],
            ),
            store(
                50,
                "../../../OblivionRemastered/Content/B/BP_RootAlias.uasset",
                &[],
            ),
        ];
        assert_eq!(
            resolve_bare_root_package_identity("../../../BP_RootAlias.uasset", 50, &duplicated),
            None
        );
    }

    #[test]
    fn composite_roundtrip_requests_use_the_rebuilt_containers_own_spelling() {
        let rebuilt = vec![
            PackageEntry {
                package_id: 42,
                path: "../../../OblivionRemastered/Content/Art/Armor/Blades/SK_Blades_Boots.uasset"
                    .to_owned(),
            },
            PackageEntry {
                package_id: 43,
                path: "../../../OblivionRemastered/Content/Art/Armor/Blades/CL_Belt.uasset"
                    .to_owned(),
            },
        ];
        let requested = vec![PackageEntry {
            package_id: 42,
            // The current game's spelling differs in directory case only; the
            // request must still use the rebuilt container's spelling because
            // Retoc filters are case-sensitive against that index.
            path: "../../../OblivionRemastered/Content/Art/armor/blades/SK_Blades_Boots.uasset"
                .to_owned(),
        }];
        let requests = composite_roundtrip_requests(&rebuilt, &requested).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0.package_id, 42);
        assert_eq!(
            requests[0].1,
            "../../../OblivionRemastered/Content/Art/Armor/Blades/SK_Blades_Boots.uasset"
        );

        // A requested identity missing from the rebuilt inventory fails closed.
        let missing = vec![PackageEntry {
            package_id: 99,
            path: "X.uasset".to_owned(),
        }];
        assert!(composite_roundtrip_requests(&rebuilt, &missing).is_err());

        // A duplicated rebuilt package ID is ambiguous and fails closed.
        let duplicated = vec![rebuilt[0].clone(), rebuilt[0].clone()];
        assert!(composite_roundtrip_requests(&duplicated, &requested).is_err());
    }

    #[test]
    fn composite_alias_rebinding_requires_matching_content_suffix() {
        // Identical spelling (case-insensitively) needs no rebinding.
        assert!(
            !composite_alias_rebinding_required(
                "OblivionRemastered/Content/Art/Clothes/SK_Dress.uasset",
                "oblivionremastered/content/art/clothes/sk_dress.uasset",
            )
            .unwrap()
        );
        // A named project root alias with an agreeing content-relative suffix
        // is proven and must be rebound to the effective identity.
        assert!(
            composite_alias_rebinding_required(
                "obliemperor/Content/Art/Clothes/SpecialClass/SEDuchess/SK_SE_Duchess_Dress.uasset",
                "OblivionRemastered/Content/Art/Clothes/SpecialClass/SEDuchess/SK_SE_Duchess_Dress.uasset",
            )
            .unwrap()
        );
        // Any change beyond the project root fails closed.
        let error = composite_alias_rebinding_required(
            "obliemperor/Content/Art/Clothes/SK_Other.uasset",
            "OblivionRemastered/Content/Art/Clothes/SK_SE_Duchess_Dress.uasset",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("changes more than its project root"), "{error}");
    }

    #[test]
    fn static_mesh_source_and_current_filters_preserve_their_own_path_casing() {
        let source = PackageEntry {
            package_id: 10_014_019_090_142_912_733,
            path: "../../../OblivionRemastered/Content/Art/UI/Icons/Dynamic_Icons/menus/Icons/armor/Elven/T_shield.uasset"
                .to_owned(),
        };
        let current = PackageEntry {
            package_id: 10_014_019_090_142_912_733,
            path: "../../../OblivionRemastered/Content/Art/UI/Icons/Dynamic_Icons/menus/Icons/armor/elven/T_shield.uasset"
                .to_owned(),
        };
        assert_eq!(
            source_static_mesh_package_filter(&source).unwrap(),
            "OblivionRemastered/Content/Art/UI/Icons/Dynamic_Icons/menus/Icons/armor/Elven/T_shield"
        );
        assert_eq!(
            source_static_mesh_package_filter(&current).unwrap(),
            "OblivionRemastered/Content/Art/UI/Icons/Dynamic_Icons/menus/Icons/armor/elven/T_shield"
        );

        let aliased_source = PackageEntry {
            package_id: current.package_id,
            path: "../../../OblivionRemastered/Content/Custom/Aliased/T_shield.uasset".to_owned(),
        };
        assert_eq!(
            source_static_mesh_package_filter(&aliased_source).unwrap(),
            "OblivionRemastered/Content/Custom/Aliased/T_shield"
        );

        let additive = PackageEntry {
            package_id: 42,
            path: "../../../OblivionRemastered/Content/Art/UI/Icons/Dynamic_Icons/menus/Icons/armor/Elven/T_custom.uasset"
                .to_owned(),
        };
        assert_eq!(
            source_static_mesh_package_filter(&additive).unwrap(),
            "OblivionRemastered/Content/Art/UI/Icons/Dynamic_Icons/menus/Icons/armor/Elven/T_custom"
        );
    }

    #[test]
    fn current_donor_filters_keep_current_spelling_and_reject_source_alias_roots() {
        // Donor extraction reads the current game's package store, so every
        // batched Retoc filter must keep that store's exact spelling.
        let donors = [
            PackageEntry {
                package_id: 42,
                path: "../../../OblivionRemastered/Content/Art/armor/example/SM_Example_Helmet.uasset"
                    .to_owned(),
            },
            PackageEntry {
                package_id: 43,
                path: "../../../OblivionRemastered/Content/Art/armor/example/T_Example_Boots_D.uasset"
                    .to_owned(),
            },
        ];
        assert_eq!(
            current_donor_package_filters(&donors).unwrap(),
            vec![
                "OblivionRemastered/Content/Art/armor/example/SM_Example_Helmet".to_owned(),
                "OblivionRemastered/Content/Art/armor/example/T_Example_Boots_D".to_owned(),
            ]
        );

        // A source project-root alias is not a current-store path. Using it as
        // a donor filter could never match the current container, so filter
        // derivation must fail closed instead of extracting nothing.
        let alias_leak = [PackageEntry {
            package_id: 42,
            path: "../../../SomeSourceProject/Content/Art/armor/example/SM_Example_Helmet.uasset"
                .to_owned(),
        }];
        assert!(current_donor_package_filters(&alias_leak).is_err());
    }

    #[test]
    fn heterogeneous_identity_accepts_case_only_paths_and_authored_import_changes() {
        let source = store(
            42,
            "../../../OblivionRemastered/Content/Art/Meshes/Armor/Elven/SM_Shield.uasset",
            &[9, 7, 9],
        );
        let current = store(
            42,
            "../../../OblivionRemastered/Content/Art/Meshes/Armor/elven/SM_Shield.uasset",
            &[7, 9],
        );

        validate_heterogeneous_package_identity(&source, Some(&current), &current).unwrap();
        assert_eq!(
            HETEROGENEOUS_REPLACEMENT_ADAPTER,
            "native-heterogeneous-static-mesh-texture-v1"
        );
    }

    #[test]
    fn heterogeneous_identity_rejects_ambiguous_ids_and_non_root_aliases() {
        let source = store(42, "OblivionRemastered/Content/Test/Asset.uasset", &[7]);
        let wrong_path_identity = store(43, "OblivionRemastered/Content/Test/Asset.uasset", &[7]);
        let by_id = store(42, "OblivionRemastered/Content/Test/Other.uasset", &[7]);
        assert!(
            validate_heterogeneous_package_identity(&source, Some(&wrong_path_identity), &by_id,)
                .unwrap_err()
                .to_string()
                .contains("identity is ambiguous")
        );

        let aliased_source = store(
            42,
            "BlackwoodCompany/Content/Art/Armor/Blackwood/SM_Helmet.uasset",
            &[7],
        );
        let aliased_current = store(
            42,
            "OblivionRemastered/Content/Art/Armor/Blackwood/SM_Helmet.uasset",
            &[8],
        );
        validate_heterogeneous_package_identity(&aliased_source, None, &aliased_current).unwrap();

        let wrong_content = store(
            42,
            "OblivionRemastered/Content/Art/Armor/Blackwood/SM_Other.uasset",
            &[7],
        );
        assert!(
            validate_heterogeneous_package_identity(&aliased_source, None, &wrong_content)
                .unwrap_err()
                .to_string()
                .contains("changes more than the project root")
        );
    }

    #[test]
    fn replacement_scope_allows_passive_docs_but_not_functional_sidecars() {
        assert!(is_passive_documentation_path(Path::new("README.txt")));
        assert!(is_passive_documentation_path(Path::new(
            "docs/screenshot.webp"
        )));
        assert!(!is_passive_documentation_path(Path::new(
            "fomod/ModuleConfig.xml"
        )));
        assert!(!is_passive_documentation_path(Path::new("settings.ini")));
    }

    #[test]
    fn skeletal_replacement_scope_includes_clothing_but_excludes_non_art_packages() {
        assert!(is_skeletal_mesh_candidate(
            "OblivionRemastered/Content/Art/Clothes/Sheogorath/SK_Sheogorath_Robe.uasset"
        ));
        assert!(is_armor_skeletal_mesh(
            "OblivionRemastered/Content/Art/Armor/Blades/SK_Blades_Cuirass_m.uasset"
        ));
        assert!(!is_skeletal_mesh_candidate(
            "OblivionRemastered/Content/Forms/Items/Armor/SK_Fake.uasset"
        ));
    }

    #[test]
    fn heterogeneous_texture_pair_checks_identity_format_and_bulk_layout() {
        let source = texture_diagnostic("T_Shield", "PF_BC7", true);
        let current = texture_diagnostic("t_shield", "pf_bc7", false);
        let validated =
            validate_texture_replacement_pair(source, &current, "T_Shield.uasset").unwrap();
        assert_eq!(validated.warnings.len(), 1);

        let wrong_format = texture_diagnostic("T_Shield", "PF_DXT1", true);
        let validated = validate_texture_replacement_pair(
            texture_diagnostic("T_Shield", "PF_BC7", true),
            &wrong_format,
            "T_Shield.uasset",
        )
        .unwrap();
        assert!(
            validated
                .warnings
                .iter()
                .any(|warning| warning.contains("Pixel format differs"))
        );
    }

    #[test]
    fn accepts_safe_content_paths_without_naming_rules() {
        assert_eq!(
            canonical_additive_static_mesh_path(
                "../../../BackpackQuivers/Content/Art/Equipment/Weapons/Ebony/SM_Ebony_Quiver.uasset"
            )
            .unwrap(),
            "BackpackQuivers/Content/Art/Equipment/Weapons/Ebony/SM_Ebony_Quiver.uasset"
        );
        assert_eq!(
            canonical_additive_static_mesh_path(
                "OddProject/Content/Whatever/AuthorsOwnName.uasset"
            )
            .unwrap(),
            "OddProject/Content/Whatever/AuthorsOwnName.uasset"
        );
        assert_eq!(
            canonical_additive_static_mesh_path(
                "../../../OblivionRemastered/Content/Art/Armor/Orcish/SM_Orcish_Helmet.uasset"
            )
            .unwrap(),
            "OblivionRemastered/Content/Art/Armor/Orcish/SM_Orcish_Helmet.uasset"
        );
        assert!(
            canonical_additive_static_mesh_path("OddProject/Content/Whatever/Mesh.umap").is_err()
        );
        assert!(
            canonical_additive_static_mesh_path("BackpackQuivers/Content/../SM_Traversal.uasset")
                .is_err()
        );
    }
    #[test]
    fn canonicalizes_retoc_paths_case_insensitively() {
        assert_eq!(
            canonical_package_path(
                "../../../OblivionRemastered/Content/Art/armor/Daedric/SK_Test.uasset"
            )
            .unwrap(),
            "OblivionRemastered/Content/Art/armor/Daedric/SK_Test.uasset"
        );
        assert!(is_armor_skeletal_mesh(
            "OblivionRemastered/Content/Art/armor/Daedric/SK_Test.uasset"
        ));
        assert!(!is_armor_skeletal_mesh(
            "OblivionRemastered/Content/Maps/SK_Test.uasset"
        ));
        assert!(is_texture_candidate(
            "OblivionRemastered/Content/Art/armor/Test/T_Test_NNRM.uasset"
        ));
        assert!(!is_texture_candidate(
            "OblivionRemastered/Content/Art/armor/Test/T_Test_NNRM.umap"
        ));
    }

    #[test]
    fn exclusive_source_view_excludes_the_current_game_main_store() {
        let input = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("OblivionRemastered-Windows.utoc", b"stock".as_slice()),
            ("oblivionremastered-windows.UCAS", b"stock".as_slice()),
            ("OblivionRemastered-Windows.pak", b"stock".as_slice()),
            ("global.utoc", b"names".as_slice()),
            ("global.ucas", b"names".as_slice()),
            ("MyMod_p.utoc", b"source-utoc".as_slice()),
            ("MyMod_p.ucas", b"source-ucas".as_slice()),
            ("MyMod_p.pak", b"source-pak".as_slice()),
            ("README.txt", b"documentation".as_slice()),
        ] {
            fs::write(input.path().join(name), bytes).unwrap();
        }
        let staged = stage_exclusive_source_view(input.path()).unwrap();
        let mut names = fs::read_dir(staged.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort_by_key(|name| name.to_ascii_lowercase());
        assert_eq!(
            names,
            [
                "global.ucas",
                "global.utoc",
                "MyMod_p.pak",
                "MyMod_p.ucas",
                "MyMod_p.utoc",
            ]
        );
        assert_eq!(
            fs::read(staged.path().join("MyMod_p.ucas")).unwrap(),
            b"source-ucas"
        );
    }

    fn read_extracted_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
        WalkDir::new(root)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                (relative, fs::read(entry.path()).unwrap())
            })
            .collect()
    }

    fn package_file_set(
        files: &BTreeMap<String, Vec<u8>>,
        package_path: &str,
    ) -> BTreeMap<String, Vec<u8>> {
        let stem = package_path.trim_end_matches(".uasset");
        files
            .iter()
            .filter(|(path, _)| {
                path.strip_prefix(stem).is_some_and(|suffix| {
                    matches!(suffix, ".uasset" | ".uexp" | ".ubulk" | ".uptnl")
                })
            })
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect()
    }

    /// The audit-required fixture: one extraction input that contains BOTH the
    /// source container and the current-game package store, where the two
    /// stores spell a shared package path differently and carry different
    /// bytes. Source extraction must return the source store's exact bytes and
    /// exact path spelling for every package — never the current store's — and
    /// extracting any single package must behave the same as the whole set.
    #[test]
    #[ignore = "requires an installed game and a local heterogeneous container fixture"]
    fn source_extraction_returns_source_bytes_when_both_stores_are_present() {
        let required = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
        };
        let game_root = normalize_install_root(&required("OBR_TEST_GAME"));
        let mod_input = required("OBR_TEST_HETEROGENEOUS_MOD");
        let game_paks = game_root.join(r"OblivionRemastered\Content\Paks");
        let stock_names = [
            "global.utoc",
            "global.ucas",
            "OblivionRemastered-Windows.utoc",
            "OblivionRemastered-Windows.ucas",
            "OblivionRemastered-Windows.pak",
        ];
        let retoc = RetocTool::materialize().unwrap();
        let work = tempfile::Builder::new()
            .prefix("obr-source-byte-fixture-")
            .tempdir()
            .unwrap();
        let staged = work.path().join("source");
        stage_input(&mod_input, &staged).unwrap();
        let containers =
            discover_containers(&staged, &retoc, ReplacementScope::HeterogeneousReplacement)
                .unwrap();
        assert!(!containers.is_empty());
        for container in &containers {
            let root = work.path().join("containers").join(&container.name);
            // Ground truth, independent of the helpers under test: a full
            // unfiltered extraction that can only see the source container
            // (plus the script-object store required for conversion).
            let truth_view = root.join("truth-view");
            fs::create_dir_all(&truth_view).unwrap();
            for name in ["global.utoc", "global.ucas"] {
                fs::copy(game_paks.join(name), truth_view.join(name)).unwrap();
            }
            for source in [&container.utoc, &container.ucas, &container.pak] {
                fs::copy(source, truth_view.join(source.file_name().unwrap())).unwrap();
            }
            let truth_out = root.join("truth");
            fs::create_dir_all(&truth_out).unwrap();
            let result = retoc
                .run([
                    OsString::from("to-legacy"),
                    truth_view.as_os_str().to_owned(),
                    truth_out.as_os_str().to_owned(),
                    OsString::from("--version"),
                    OsString::from("UE5_3"),
                    OsString::from("--no-shaders"),
                    OsString::from("--no-script-objects"),
                    OsString::from("--no-parallel"),
                ])
                .unwrap();
            let (extracted, failed) =
                RetocTool::extraction_summary(&result, "fixture ground truth").unwrap();
            assert_eq!(failed, 0);
            assert_eq!(extracted, container.packages.len());
            let truth = read_extracted_files(&truth_out);
            for package in &container.packages {
                // The ground truth must materialize the exact source spelling.
                assert!(
                    truth.contains_key(&package.path),
                    "ground truth is missing the exact source path {}",
                    package.path
                );
            }

            // The fixture input under test: both stores in one directory.
            let merged = tempfile::Builder::new()
                .prefix(".obr-test-merged-view-")
                .tempdir_in(&game_root)
                .unwrap();
            for name in stock_names {
                fs::hard_link(game_paks.join(name), merged.path().join(name)).unwrap();
            }
            for source in [&container.utoc, &container.ucas, &container.pak] {
                fs::copy(source, merged.path().join(source.file_name().unwrap())).unwrap();
            }

            // 1) Whole-set extraction returns exactly the source bytes.
            let whole = root.join("whole-set");
            extract_source_packages_exact(
                &retoc,
                merged.path(),
                &whole,
                &container.packages,
                "fixture whole-set source extraction",
            )
            .unwrap();
            assert_eq!(read_extracted_files(&whole), truth);

            // 2) Extracting any single package also returns its source bytes.
            for package in &container.packages {
                let single = root
                    .join("single")
                    .join(package.package_id.to_string());
                extract_source_packages_exact(
                    &retoc,
                    merged.path(),
                    &single,
                    std::slice::from_ref(package),
                    &format!("fixture single-package source extraction {}", package.path),
                )
                .unwrap();
                let expected = package_file_set(&truth, &package.path);
                assert!(!expected.is_empty());
                assert_eq!(read_extracted_files(&single), expected);
            }

            // 3) The static-mesh-lane helper (no whole-container fallback)
            //    must extract the same source bytes from the same input.
            let static_mesh_lane = root.join("static-mesh-lane");
            extract_source_static_mesh_packages(
                &retoc,
                merged.path(),
                &static_mesh_lane,
                &container.packages,
                "fixture static-mesh-lane source extraction",
            )
            .unwrap();
            assert_eq!(read_extracted_files(&static_mesh_lane), truth);
        }
    }
}
