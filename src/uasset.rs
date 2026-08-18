use crate::archive::{sha256_bytes, sha256_file};
use crate::retoc::{PackageEntry, PackageStoreEntry, unreal_package_id};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use walkdir::WalkDir;

const UASSETGUI_EXE: &[u8] = include_bytes!("../third_party/uassetgui/UAssetGUI.exe");
pub const UASSETGUI_LICENSE: &str = include_str!("../third_party/uassetgui/LICENSE");
pub const UASSETGUI_NOTICE: &str = include_str!("../third_party/uassetgui/NOTICE.md");

pub fn embedded_fingerprints() -> Vec<(&'static str, usize, String, bool)> {
    vec![(
        "UAssetGUI.exe",
        UASSETGUI_EXE.len(),
        sha256_bytes(UASSETGUI_EXE),
        UASSETGUI_EXE.starts_with(b"MZ"),
    )]
}

const ENGINE_VERSION: &str = "VER_UE5_3";
const MIN_COOKED_PHYSICS_BYTES: usize = 64;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodySetupRepair {
    pub asset: String,
    pub export: String,
    pub old_serial_size: usize,
    pub new_serial_size: usize,
    pub removed_cooked_physics_bytes: usize,
    pub collision_removed: bool,
    pub policy: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SidecarVerification {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePayloadVerification {
    pub asset: String,
    pub export_count: usize,
    pub normalized_json_sha256: String,
    pub source_uasset_sha256: String,
    pub roundtrip_uasset_sha256: String,
    pub metadata_rebased: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadEquivalenceReport {
    pub asset_count: usize,
    pub sidecar_count: usize,
    pub assets: Vec<PackagePayloadVerification>,
    pub sidecars: Vec<SidecarVerification>,
    pub allowed_metadata_changes: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TextureAssetDiagnostic {
    pub asset: String,
    pub object_name: String,
    pub class_name: String,
    pub pixel_format: String,
    pub use_separate_bulk_data_files: bool,
    pub data_resource_count: usize,
    pub declared_raw_resource_bytes: u64,
    pub export_serial_bytes: u64,
    pub uasset_bytes: u64,
    pub uexp_bytes: Option<u64>,
    pub ubulk_bytes: Option<u64>,
    pub packed_texture_kind: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterialImportRepair {
    pub asset: String,
    pub package_id: u64,
    pub material_import_count: usize,
    pub material_slot_names: Vec<String>,
    pub material_object_import_indices: Vec<usize>,
    pub material_targets: Vec<String>,
    pub active_donor_material_imports: Vec<String>,
    pub ignored_inactive_material_dependencies: Vec<String>,
    pub auxiliary_import_count: usize,
    pub auxiliary_import_targets: Vec<String>,
    pub retired_physics_asset_import_count: usize,
    pub retired_physics_asset_object_import_indices: Vec<usize>,
    pub retired_physics_asset_reference_offsets: Vec<usize>,
    pub stale_create_dependencies_removed: usize,
    pub already_retired_physics_asset_import_count: usize,
    pub already_retired_physics_asset_object_import_indices: Vec<usize>,
    pub already_retired_physics_asset_has_no_serialized_property_reference: bool,
    pub split_package_import_count: usize,
    pub skeleton_target: String,
    pub source_imported_package_ids: Vec<u64>,
    pub missing_source_imported_package_ids: Vec<u64>,
    pub target_imported_package_ids: Vec<u64>,
    pub compatibility_profile_id: Option<String>,
    pub compatibility_skeleton_target: Option<String>,
    pub compatibility_material_alias_count: usize,
    pub exports_byte_identical: bool,
    pub uexp_byte_identical: bool,
    pub policy: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompositePackageImportRepair {
    pub asset: String,
    pub package_id: u64,
    pub asset_kind: String,
    pub repaired_import_count: usize,
    pub repaired_targets: Vec<String>,
    pub retired_physics_asset: bool,
    pub stale_create_dependencies_removed: usize,
    pub source_imported_package_ids: Vec<u64>,
    pub missing_source_imported_package_ids: Vec<u64>,
    pub target_imported_package_ids: Vec<u64>,
    pub exports_byte_identical: bool,
    pub uexp_byte_identical: bool,
    pub policy: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageIdentityAlias {
    pub source_package_id: u64,
    pub source_package_path: String,
    pub target_package_id: u64,
    pub target_package_path: String,
    pub source_object_name: String,
    pub target_object_name: String,
    pub asset_class: String,
    pub export_payloads_preserved: bool,
    pub uexp_byte_identical: bool,
    pub provenance: String,
    pub policy: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlueprintAliasRoleEvidence {
    pub consumer: String,
    pub target_package_id: u64,
    pub target_package_path: String,
    pub target_object_name: String,
    pub target_class: String,
    pub role: String,
    pub export_name: String,
    pub export_index: usize,
    pub object_import_index: usize,
    pub serialized_reference_offset: usize,
    pub provenance: String,
    pub policy: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionalBlueprintDependencySuppression {
    pub asset: String,
    pub target_package_id: u64,
    pub target_package_path: String,
    pub target_class: String,
    pub role: String,
    pub export_name: String,
    pub serialized_reference_offset: usize,
    pub removed_dependency_count: usize,
    pub replacement_package_id: u64,
    pub replacement_package_path: String,
    pub target_imported_package_ids: Vec<u64>,
    pub policy: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositePackageAssetKind {
    SkeletalMesh,
    StaticMesh,
    Texture2D,
    MaterialInstanceConstant,
    AnimSequence,
    AnimMontage,
    BlendSpace,
    SoundWave,
    SoundCue,
    ResolvedAuthoredPackage,
    CurrentTemplatePackage,
}

fn package_name_leaf(package_name: &str) -> Result<&str> {
    let normalized = package_name.trim_end_matches('/');
    let leaf = normalized
        .rsplit('/')
        .next()
        .context("package name has no leaf")?;
    if leaf.is_empty()
        || !normalized
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/Game/"))
        || normalized
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        bail!("package name is not a canonical /Game path: {package_name}");
    }
    Ok(leaf)
}

fn legacy_path_for_package_name(package_name: &str) -> Result<PathBuf> {
    let _ = package_name_leaf(package_name)?;
    Ok(PathBuf::from("OblivionRemastered")
        .join("Content")
        .join(package_name.trim_start_matches("/Game/"))
        .with_extension("uasset"))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkeletalCompatibilityProfile {
    pub id: String,
    pub source: String,
    pub body_asset: String,
    pub skeleton_package_id: u64,
    pub skeleton_package_path: String,
    pub skeleton_object_name: String,
    pub material_package_id: u64,
    pub material_package_path: String,
    pub material_object_name: String,
    pub material_aliases: Vec<String>,
    pub policy: String,
}

impl SkeletalCompatibilityProfile {
    fn skeleton_target(&self) -> ImportTarget {
        ImportTarget {
            package_id: self.skeleton_package_id,
            package_path: self.skeleton_package_path.clone(),
            object_name: self.skeleton_object_name.clone(),
            class_name: "Skeleton".to_owned(),
        }
    }

    fn material_target(&self) -> ImportTarget {
        ImportTarget {
            package_id: self.material_package_id,
            package_path: self.material_package_path.clone(),
            object_name: self.material_object_name.clone(),
            class_name: "MaterialInstanceConstant".to_owned(),
        }
    }

    fn alias_targets(&self) -> HashMap<String, ImportTarget> {
        self.material_aliases
            .iter()
            .map(|alias| (normalized_material_name(alias), self.material_target()))
            .collect()
    }
}

pub(crate) struct UAssetGuiTool {
    _temp: TempDir,
    executable: PathBuf,
}

impl UAssetGuiTool {
    pub(crate) fn materialize() -> Result<Self> {
        let temp = tempfile::Builder::new()
            .prefix("obr-uassetgui-")
            .tempdir()?;
        let executable = temp.path().join("UAssetGUI.exe");
        fs::write(&executable, UASSETGUI_EXE)?;
        Ok(Self {
            _temp: temp,
            executable,
        })
    }

    fn run(&self, arguments: &[OsString], label: &str) -> Result<String> {
        let mut command = Command::new(&self.executable);
        command.args(arguments).current_dir(
            self.executable
                .parent()
                .context("embedded UAssetGUI has no parent")?,
        );
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let output = command
            .output()
            .with_context(|| format!("launching embedded UAssetGUI for {label}"))?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.stderr.is_empty() {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        if !output.status.success() {
            bail!("UAssetGUI {label} failed: {text}");
        }
        Ok(text)
    }

    pub(crate) fn to_json(&self, asset: &Path, output: &Path) -> Result<()> {
        if output.exists() {
            fs::remove_file(output)?;
        }
        let arguments = [
            OsString::from("tojson"),
            asset.as_os_str().to_owned(),
            output.as_os_str().to_owned(),
            OsString::from(ENGINE_VERSION),
        ];
        let text = self.run(&arguments, &format!("tojson {}", asset.display()))?;
        if !output.is_file() {
            bail!(
                "UAssetGUI did not produce JSON for {}: {text}",
                asset.display()
            );
        }
        Ok(())
    }

    pub(crate) fn import_json(&self, source: &Path, output: &Path) -> Result<()> {
        if output.exists() {
            fs::remove_file(output)?;
        }
        let arguments = [
            OsString::from("fromjson"),
            source.as_os_str().to_owned(),
            output.as_os_str().to_owned(),
        ];
        let text = self.run(&arguments, &format!("fromjson {}", source.display()))?;
        if !output.is_file() {
            bail!("UAssetGUI did not rebuild {}: {text}", output.display());
        }
        Ok(())
    }
}

fn texture_class_name(document: &Value, export: &Value) -> Result<String> {
    let class_index = export
        .get("ClassIndex")
        .and_then(Value::as_i64)
        .context("texture export has no ClassIndex")?;
    let import_index = class_index
        .checked_neg()
        .and_then(|value| value.checked_sub(1))
        .and_then(|value| usize::try_from(value).ok())
        .context("texture export ClassIndex is not an import reference")?;
    document
        .get("Imports")
        .and_then(Value::as_array)
        .and_then(|imports| imports.get(import_index))
        .and_then(|import| import.get("ObjectName"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context("texture export class import could not be resolved")
}

fn packed_texture_kind(object_name: &str) -> Option<String> {
    let upper = object_name.to_ascii_uppercase();
    ["NNRAO", "NNRM", "NNRS", "NNRE", "NNR"]
        .into_iter()
        .find(|suffix| upper.ends_with(&format!("_{suffix}")))
        .map(str::to_owned)
}

fn inspect_texture_document(document: &Value, asset: &Path) -> Result<TextureAssetDiagnostic> {
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("texture UAsset JSON has no Exports")?;
    if exports.len() != 1 {
        bail!(
            "texture replacement must contain exactly one export; found {} in {}",
            exports.len(),
            asset.display()
        );
    }
    let export = &exports[0];
    let class_name = texture_class_name(document, export)?;
    if !class_name.eq_ignore_ascii_case("Texture2D") {
        bail!(
            "replacement package is {}, not Texture2D: {}",
            class_name,
            asset.display()
        );
    }
    let object_name = export
        .get("ObjectName")
        .and_then(Value::as_str)
        .context("Texture2D export has no ObjectName")?
        .to_owned();
    let expected_name = asset
        .file_stem()
        .and_then(|value| value.to_str())
        .context("texture UAsset filename is not UTF-8")?;
    if !object_name.eq_ignore_ascii_case(expected_name) {
        bail!(
            "Texture2D export name {} does not match package filename {}",
            object_name,
            expected_name
        );
    }

    let mut pixel_formats = document
        .get("NameMap")
        .and_then(Value::as_array)
        .context("Texture2D UAsset JSON has no NameMap")?
        .iter()
        .filter_map(Value::as_str)
        .filter(|name| name.to_ascii_uppercase().starts_with("PF_"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    pixel_formats.sort_by_key(|value| value.to_ascii_lowercase());
    pixel_formats.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    if pixel_formats.len() != 1 {
        bail!(
            "Texture2D package must expose exactly one pixel format; found {} in {}",
            pixel_formats.len(),
            asset.display()
        );
    }

    let data_resources = document
        .get("DataResources")
        .and_then(Value::as_array)
        .context("Texture2D UAsset JSON has no DataResources")?;
    if data_resources.is_empty() {
        bail!(
            "Texture2D package has no DataResources: {}",
            asset.display()
        );
    }
    let declared_raw_resource_bytes = data_resources.iter().try_fold(0_u64, |total, row| {
        let bytes = row
            .get("RawSize")
            .and_then(Value::as_u64)
            .context("Texture2D DataResource has no RawSize")?;
        total
            .checked_add(bytes)
            .context("Texture2D DataResource byte total overflow")
    })?;
    let export_serial_bytes = export
        .get("SerialSize")
        .and_then(Value::as_u64)
        .context("Texture2D export has no SerialSize")?;
    let uexp = asset.with_extension("uexp");
    if !uexp.is_file() {
        bail!(
            "Texture2D package is missing its required UEXP sidecar: {}",
            asset.display()
        );
    }
    let ubulk = asset.with_extension("ubulk");
    let use_separate_bulk_data_files = document
        .get("UseSeparateBulkDataFiles")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let packed_texture_kind = packed_texture_kind(&object_name);
    let mut warnings = Vec::new();
    if packed_texture_kind.is_some() && !pixel_formats[0].eq_ignore_ascii_case("PF_BC7") {
        warnings.push(format!(
            "{} is a packed normal/roughness texture but uses {}; the wiki recommends BC7 with sRGB disabled",
            object_name, pixel_formats[0]
        ));
    }
    if use_separate_bulk_data_files && !ubulk.is_file() {
        warnings.push(
            "Texture metadata declares separate bulk data, but no UBULK sidecar was extracted"
                .to_owned(),
        );
    }

    Ok(TextureAssetDiagnostic {
        asset: asset
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("texture.uasset")
            .to_owned(),
        object_name,
        class_name,
        pixel_format: pixel_formats.remove(0),
        use_separate_bulk_data_files,
        data_resource_count: data_resources.len(),
        declared_raw_resource_bytes,
        export_serial_bytes,
        uasset_bytes: fs::metadata(asset)?.len(),
        uexp_bytes: Some(fs::metadata(&uexp)?.len()),
        ubulk_bytes: ubulk
            .is_file()
            .then(|| fs::metadata(&ubulk).map(|value| value.len()))
            .transpose()?,
        packed_texture_kind,
        warnings,
    })
}

pub fn inspect_texture_asset(asset: &Path) -> Result<TextureAssetDiagnostic> {
    let tool = UAssetGuiTool::materialize()?;
    let work = tempfile::Builder::new()
        .prefix("obr-texture-inspect-")
        .tempdir()?;
    let json = work.path().join("texture.json");
    tool.to_json(asset, &json)?;
    let document: Value = serde_json::from_slice(&fs::read(&json)?)?;
    inspect_texture_document(&document, asset)
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticMeshImportRepair {
    pub asset: String,
    pub repaired_material_import_count: usize,
    pub material_slot_names: Vec<String>,
    pub target_package_ids: Vec<u64>,
    pub target_package_paths: Vec<String>,
    pub exports_byte_identical: bool,
    pub uexp_byte_identical: bool,
}
pub fn inspect_static_mesh_asset(asset: &Path) -> Result<Vec<String>> {
    let tool = UAssetGuiTool::materialize()?;
    let work = tempfile::Builder::new()
        .prefix("obr-static-mesh-inspect-")
        .tempdir()?;
    let json = work.path().join("static-mesh.json");
    tool.to_json(asset, &json)?;
    let document: Value = serde_json::from_slice(&fs::read(&json)?)?;
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("StaticMesh UAsset JSON has no Exports")?;
    let meshes = exports
        .iter()
        .filter(|export| {
            texture_class_name(&document, export)
                .is_ok_and(|class| class.eq_ignore_ascii_case("StaticMesh"))
        })
        .collect::<Vec<_>>();
    if meshes.len() != 1 {
        bail!(
            "additive static-mesh package must contain exactly one StaticMesh export; found {} in {}",
            meshes.len(),
            asset.display()
        );
    }
    let object_name = meshes[0]
        .get("ObjectName")
        .and_then(Value::as_str)
        .context("StaticMesh export has no ObjectName")?;
    let expected = asset
        .file_stem()
        .and_then(|value| value.to_str())
        .context("StaticMesh filename is not UTF-8")?;
    if !object_name.eq_ignore_ascii_case(expected)
        || !object_name.to_ascii_lowercase().starts_with("sm_")
    {
        bail!(
            "StaticMesh export name {object_name} does not match SM_ package filename {expected}"
        );
    }
    let package_imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("StaticMesh UAsset JSON has no Imports")?
        .iter()
        .filter(|import| import.get("ClassName").and_then(Value::as_str) == Some("Package"))
        .filter_map(|import| import.get("ObjectName").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Ok(package_imports)
}

/// Hashes any absolute mounted package name (`/Game/...`, `/Engine/...`)
/// exactly the way the runtime derives FPackageId: CityHash64 over the
/// lowercase UTF-16LE name.
fn mounted_import_package_id(name: &str) -> u64 {
    let lowered = name.to_lowercase();
    let utf16le = lowered
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    cityhasher::hash::<u64>(&utf16le)
}

/// Re-anchors `/Engine/UnknownPackage` markers left by a source-only
/// extraction to the packages the AUTHORED zen package-store row proves the
/// asset imports. The serialized material-slot name is never identity
/// evidence on its own: authoring pipelines clone donor meshes and keep the
/// donor's stale slot names, so a name-first repair can silently rebind an
/// import to an unrelated package. Slot names only disambiguate between
/// already-proven authored targets when several markers remain.
pub fn repair_static_mesh_imports(
    asset: &Path,
    authored_imported_package_ids: &[u64],
    target_dependencies: &HashMap<u64, PackageEntry>,
    work: &Path,
) -> Result<StaticMeshImportRepair> {
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work.join("static-source.json");
    let patched_json = work.join("static-patched.json");
    let rebuilt_asset = work.join(
        asset
            .file_name()
            .context("StaticMesh path has no filename")?,
    );
    let verify_json = work.join("static-verified.json");
    tool.to_json(asset, &source_json)?;
    let mut document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let original_exports = export_data(&document)?;
    let imports_snapshot = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("StaticMesh UAsset JSON has no Imports")?
        .clone();
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("StaticMesh UAsset JSON has no Exports")?;
    let mesh = exports
        .iter()
        .filter(|export| {
            export
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.to_ascii_lowercase().starts_with("sm_"))
        })
        .collect::<Vec<_>>();
    if mesh.len() != 1 {
        bail!(
            "StaticMesh import repair requires exactly one SM_ export; found {}",
            mesh.len()
        );
    }
    let encoded = mesh[0]
        .get("Data")
        .and_then(Value::as_str)
        .or_else(|| mesh[0].get("Extras").and_then(Value::as_str))
        .context("StaticMesh export has no raw payload")?;
    let bytes = BASE64
        .decode(encoded)
        .context("StaticMesh payload is not base64")?;
    let unknown_packages = imports_snapshot
        .iter()
        .enumerate()
        .filter(|(_, import)| {
            import.get("ClassName").and_then(Value::as_str) == Some("Package")
                && import
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case("/Engine/UnknownPackage"))
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if unknown_packages.is_empty() {
        bail!("StaticMesh has no unresolved material imports to repair");
    }
    // Every package this asset may reference is authored in its zen
    // package-store row. The imports that survived to-legacy with a mounted
    // name account for part of that authored set; the remaining authored IDs
    // are exactly the packages the markers stand for.
    let resolved_ids = imports_snapshot
        .iter()
        .filter(|import| import.get("ClassName").and_then(Value::as_str) == Some("Package"))
        .filter_map(|import| import.get("ObjectName").and_then(Value::as_str))
        .filter(|name| {
            name.starts_with('/')
                && !name.eq_ignore_ascii_case("/Engine/UnknownPackage")
                && !name
                    .get(..8)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/Script/"))
        })
        .map(mounted_import_package_id)
        .collect::<BTreeSet<_>>();
    let mut missing_targets = authored_imported_package_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|package_id| !resolved_ids.contains(package_id))
        .collect::<Vec<_>>();
    if missing_targets.len() != unknown_packages.len() {
        bail!(
            "StaticMesh carries {} unresolved package import marker(s) but its authored package-store row leaves {} import(s) unaccounted; the marker-to-package assignment cannot be proven",
            unknown_packages.len(),
            missing_targets.len()
        );
    }
    let mut patches = Vec::<(usize, usize, ImportTarget)>::new();
    for package_index in unknown_packages {
        let outer = -i64::try_from(package_index)? - 1;
        let children = imports_snapshot
            .iter()
            .enumerate()
            .filter(|(_, import)| {
                import.get("OuterIndex").and_then(Value::as_i64) == Some(outer)
                    && import.get("ObjectName").and_then(Value::as_str) == Some("UnknownExport")
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if children.len() != 1 {
            bail!(
                "unresolved StaticMesh package import {package_index} must have exactly one UnknownExport child; found {}",
                children.len()
            );
        }
        let object_index = children[0];
        let target_id = if missing_targets.len() == 1 {
            missing_targets[0]
        } else {
            // Several markers remain: the serialized material-slot name is
            // only a disambiguator BETWEEN authored targets, never identity
            // evidence on its own.
            let reference = -i32::try_from(object_index)? - 1;
            let pattern = reference.to_le_bytes();
            let mut candidates = BTreeSet::new();
            for offset in 0..bytes.len().saturating_sub(11) {
                if bytes[offset..offset + 4] != pattern {
                    continue;
                }
                let Some(name_index) = little_i32(&bytes, offset + 4) else {
                    continue;
                };
                let Some(name_number) = little_i32(&bytes, offset + 8) else {
                    continue;
                };
                if name_number != 0 {
                    continue;
                }
                let Some(name) = usize::try_from(name_index)
                    .ok()
                    .and_then(|index| document.get("NameMap")?.as_array()?.get(index))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                let matched = missing_targets
                    .iter()
                    .copied()
                    .filter(|candidate| {
                        target_dependencies.get(candidate).is_some_and(|entry| {
                            Path::new(&entry.path)
                                .file_stem()
                                .and_then(|value| value.to_str())
                                .is_some_and(|leaf| leaf.eq_ignore_ascii_case(name))
                        })
                    })
                    .collect::<Vec<_>>();
                if matched.len() == 1 {
                    candidates.insert(matched[0]);
                }
            }
            if candidates.len() != 1 {
                bail!(
                    "unresolved StaticMesh object import {object_index} must select exactly one remaining authored package-store target through its serialized slot name; found {}",
                    candidates.len()
                );
            }
            candidates.into_iter().next().unwrap()
        };
        missing_targets.retain(|candidate| *candidate != target_id);
        let target = target_dependencies.get(&target_id).with_context(|| {
            format!("authored StaticMesh import {target_id} has no proven current identity")
        })?;
        let object_name = Path::new(&target.path)
            .file_stem()
            .and_then(|value| value.to_str())
            .context("StaticMesh import target has no filename")?
            .to_owned();
        patches.push((
            package_index,
            object_index,
            ImportTarget {
                package_id: target.package_id,
                package_path: game_package_path(&target.path)?,
                object_name,
                class_name: "MaterialInstanceConstant".to_owned(),
            },
        ));
    }
    let imports = document
        .get_mut("Imports")
        .and_then(Value::as_array_mut)
        .context("StaticMesh UAsset JSON Imports is not an array")?;
    for (package_index, object_index, target) in &patches {
        imports[*package_index]["ObjectName"] = Value::String(target.package_path.clone());
        imports[*object_index]["ObjectName"] = Value::String(target.object_name.clone());
        imports[*object_index]["ClassPackage"] = Value::String("/Script/Engine".to_owned());
        imports[*object_index]["ClassName"] = Value::String(target.class_name.clone());
    }
    let names = document
        .get_mut("NameMap")
        .and_then(Value::as_array_mut)
        .context("StaticMesh UAsset JSON has no NameMap")?;
    for name in patches.iter().flat_map(|(_, _, target)| {
        [
            target.package_path.as_str(),
            target.object_name.as_str(),
            target.class_name.as_str(),
        ]
    }) {
        if !names.iter().any(|value| value.as_str() == Some(name)) {
            names.push(Value::String(name.to_owned()));
        }
    }
    let intended_exports = export_data(&document)?;
    if original_exports != intended_exports {
        bail!("StaticMesh import repair changed raw export data before rebuild");
    }
    fs::write(&patched_json, serde_json::to_vec(&document)?)?;
    tool.import_json(&patched_json, &rebuilt_asset)?;
    let source_uexp = asset.with_extension("uexp");
    let rebuilt_uexp = rebuilt_asset.with_extension("uexp");
    if source_uexp.is_file() != rebuilt_uexp.is_file() {
        bail!("StaticMesh import repair changed UEXP presence");
    }
    let uexp_byte_identical =
        !source_uexp.is_file() || sha256_file(&source_uexp)? == sha256_file(&rebuilt_uexp)?;
    if !uexp_byte_identical {
        bail!("StaticMesh import repair changed raw UEXP payload bytes");
    }
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    if intended_exports != export_data(&verified)? {
        bail!("StaticMesh import repair did not preserve raw exports through UAsset rebuild");
    }
    let verified_imports = verified
        .get("Imports")
        .and_then(Value::as_array)
        .context("verified StaticMesh UAsset has no Imports")?;
    for (package_index, object_index, target) in &patches {
        if verified_imports[*package_index]["ObjectName"].as_str()
            != Some(target.package_path.as_str())
            || verified_imports[*object_index]["ObjectName"].as_str()
                != Some(target.object_name.as_str())
            || verified_imports[*object_index]["ClassName"].as_str()
                != Some(target.class_name.as_str())
        {
            bail!("StaticMesh material import repair did not survive UAsset rebuild");
        }
    }
    fs::copy(&rebuilt_asset, asset)?;
    if rebuilt_uexp.is_file() {
        fs::copy(&rebuilt_uexp, &source_uexp)?;
    }
    Ok(StaticMeshImportRepair {
        asset: asset.to_string_lossy().replace('\\', "/"),
        repaired_material_import_count: patches.len(),
        material_slot_names: patches
            .iter()
            .map(|(_, _, target)| target.object_name.clone())
            .collect(),
        target_package_ids: patches
            .iter()
            .map(|(_, _, target)| target.package_id)
            .collect(),
        target_package_paths: patches
            .iter()
            .map(|(_, _, target)| target.package_path.clone())
            .collect(),
        exports_byte_identical: true,
        uexp_byte_identical,
    })
}
fn contains_ascii(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| window == needle)
}

fn package_relative_path(root: &Path, asset: &Path) -> String {
    asset
        .strip_prefix(root)
        .unwrap_or(asset)
        .to_string_lossy()
        .replace('\\', "/")
}

fn static_mesh_outer(exports: &[Value], imports: &[Value], body: &Value) -> bool {
    let Some(outer_index) = body.get("OuterIndex").and_then(Value::as_i64) else {
        return false;
    };
    if outer_index <= 0 {
        return false;
    }
    let Some(outer) = exports.get((outer_index - 1) as usize) else {
        return false;
    };
    let Some(class_index) = outer.get("ClassIndex").and_then(Value::as_i64) else {
        return false;
    };
    if class_index >= 0 {
        return false;
    }
    imports
        .get((-class_index - 1) as usize)
        .and_then(|import| import.get("ObjectName"))
        .and_then(Value::as_str)
        .is_some_and(|name| name == "StaticMesh")
}

fn cooked_format_anchor(data: &[u8], physx_name_index: u32) -> Vec<usize> {
    let mut pattern = Vec::with_capacity(20);
    pattern.extend_from_slice(&1_u32.to_le_bytes()); // BodySetup is cooked.
    pattern.extend_from_slice(&1_u32.to_le_bytes()); // Cooked collision is present.
    pattern.extend_from_slice(&1_u32.to_le_bytes()); // One physics format follows.
    pattern.extend_from_slice(&physx_name_index.to_le_bytes());
    pattern.extend_from_slice(&0_u32.to_le_bytes()); // FName number.
    data.windows(pattern.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == pattern).then_some(offset))
        .collect()
}

fn repair_document(document: &mut Value, asset: &Path) -> Result<Vec<BodySetupRepair>> {
    let names = document
        .get("NameMap")
        .and_then(Value::as_array)
        .context("UAsset JSON has no NameMap")?;
    let physx_name_index = names
        .iter()
        .position(|name| name.as_str() == Some("PhysXPC"))
        .context("BodySetup package has no PhysXPC name")?;
    let physx_name_index =
        u32::try_from(physx_name_index).context("PhysXPC name index does not fit Unreal FName")?;

    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("UAsset JSON has no Imports")?
        .clone();
    let exports_snapshot = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("UAsset JSON has no Exports")?
        .clone();
    let exports = document
        .get_mut("Exports")
        .and_then(Value::as_array_mut)
        .context("UAsset JSON Exports is not an array")?;

    let mut repairs = Vec::new();
    for (index, export) in exports.iter_mut().enumerate() {
        let export_snapshot = &exports_snapshot[index];
        let object_name = export_snapshot
            .get("ObjectName")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let export_type = export_snapshot
            .get("$type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !object_name.starts_with("BodySetup_")
            || !export_type.contains("RawExport")
            || !static_mesh_outer(&exports_snapshot, &imports, export_snapshot)
        {
            continue;
        }

        let encoded = export_snapshot
            .get("Data")
            .and_then(Value::as_str)
            .context("BodySetup RawExport has no Data")?;
        let mut data = BASE64
            .decode(encoded)
            .context("BodySetup RawExport Data is not base64")?;
        let declared_size = export_snapshot
            .get("SerialSize")
            .and_then(Value::as_u64)
            .context("BodySetup RawExport has no SerialSize")? as usize;
        if declared_size != data.len() {
            bail!(
                "{} {} declares {} bytes but contains {}",
                asset.display(),
                object_name,
                declared_size,
                data.len()
            );
        }

        let anchors = cooked_format_anchor(&data, physx_name_index);
        if anchors.is_empty() {
            continue;
        }
        if anchors.len() != 1 {
            bail!(
                "{} {} has {} possible cooked-physics anchors; refusing an ambiguous repair",
                asset.display(),
                object_name,
                anchors.len()
            );
        }
        let anchor = anchors[0];
        if data.len().saturating_sub(anchor + 12) < MIN_COOKED_PHYSICS_BYTES {
            continue;
        }
        // Shipping 1.512.105.0 consumes the four-byte cooked marker followed by
        // one false collision-presence byte, then ends this BodySetup export.
        // The exact boundary was proven by the game's Serial size mismatch and
        // the subsequent shipping-game load/add test no longer crashing.
        let new_size = anchor + 5;
        data[anchor + 4] = 0;
        data.truncate(new_size);
        export["Data"] = Value::String(BASE64.encode(&data));
        export["SerialSize"] = Value::from(new_size as u64);
        repairs.push(BodySetupRepair {
            asset: asset.to_string_lossy().replace('\\', "/"),
            export: object_name.to_owned(),
            old_serial_size: declared_size,
            new_serial_size: new_size,
            removed_cooked_physics_bytes: declared_size - new_size,
            collision_removed: true,
            policy: "structural-static-mesh-runtime-boundary-v1.512.105.0".to_owned(),
        });
    }
    Ok(repairs)
}

fn export_data(document: &Value) -> Result<Vec<(String, Value, u64)>> {
    document
        .get("Exports")
        .and_then(Value::as_array)
        .context("UAsset JSON has no Exports")?
        .iter()
        .map(|export| {
            Ok((
                export
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .context("export has no ObjectName")?
                    .to_owned(),
                Value::Array(vec![
                    export.get("Data").context("export has no Data")?.clone(),
                    export.get("Extras").cloned().unwrap_or(Value::Null),
                ]),
                export
                    .get("SerialSize")
                    .and_then(Value::as_u64)
                    .context("export has no SerialSize")?,
            ))
        })
        .collect()
}

fn validate_export_payload(export: &Value) -> Result<()> {
    let export_type = export
        .get("$type")
        .and_then(Value::as_str)
        .context("UAsset JSON export has no $type")?;
    let object_name = export
        .get("ObjectName")
        .and_then(Value::as_str)
        .context("UAsset export has no ObjectName")?;
    let serial_size = export
        .get("SerialSize")
        .and_then(Value::as_u64)
        .with_context(|| format!("export {object_name} has no SerialSize"))?;
    if export_type.contains("RawExport") {
        let data = export
            .get("Data")
            .and_then(Value::as_str)
            .with_context(|| format!("RawExport {object_name} has no base64 Data"))?;
        let decoded = BASE64
            .decode(data)
            .with_context(|| format!("RawExport {object_name} Data is not base64"))?;
        if serial_size != decoded.len() as u64 {
            bail!(
                "RawExport {object_name} declares {serial_size} bytes but contains {}",
                decoded.len()
            );
        }
    } else if export_type.contains("NormalExport") {
        export
            .get("Data")
            .and_then(Value::as_array)
            .with_context(|| format!("NormalExport {object_name} has no structured Data array"))?;
        let extras = export
            .get("Extras")
            .and_then(Value::as_str)
            .with_context(|| format!("NormalExport {object_name} has no base64 Extras"))?;
        let decoded = BASE64
            .decode(extras)
            .with_context(|| format!("NormalExport {object_name} Extras is not base64"))?;
        if serial_size < decoded.len() as u64 {
            bail!(
                "NormalExport {object_name} declares {serial_size} bytes but its Extras alone contain {}",
                decoded.len()
            );
        }
    } else {
        bail!("replacement package contains an unsupported export type: {export_type}");
    }
    Ok(())
}

/// Proves two extracted variants of the same package carry the identical
/// authored export payload set (names, raw data, and serial sizes). Import
/// tables and NameMaps may differ — that is exactly the difference between a
/// source-only extraction (markers) and a layered extraction (resolved import
/// names) — but any divergence in export payloads means the variants are not
/// the same authored package and the caller must fail closed.
pub fn verify_identical_export_payloads(left: &Path, right: &Path, work: &Path) -> Result<()> {
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let left_json = work.join("left.json");
    let right_json = work.join("right.json");
    tool.to_json(left, &left_json)?;
    tool.to_json(right, &right_json)?;
    let left_document: Value = serde_json::from_slice(&fs::read(&left_json)?)?;
    let right_document: Value = serde_json::from_slice(&fs::read(&right_json)?)?;
    if validated_export_data(&left_document)? != validated_export_data(&right_document)? {
        bail!(
            "extracted package variants disagree on authored export payloads: {} vs {}",
            left.display(),
            right.display()
        );
    }
    Ok(())
}

fn validated_export_data(document: &Value) -> Result<Vec<(String, Value, u64)>> {
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("UAsset JSON has no Exports")?;
    if exports.is_empty() {
        bail!("UAsset JSON contains no exports");
    }
    for export in exports {
        validate_export_payload(export)?;
    }
    export_data(document)
}

#[derive(Clone, Debug)]
struct ImportTarget {
    package_id: u64,
    package_path: String,
    object_name: String,
    class_name: String,
}

fn resolved_imports(document: &Value, class_name: &str) -> Result<Vec<(String, String)>> {
    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("donor UAsset JSON has no Imports")?;
    imports
        .iter()
        .filter(|import| import.get("ClassName").and_then(Value::as_str) == Some(class_name))
        .map(|object| {
            let outer = object
                .get("OuterIndex")
                .and_then(Value::as_i64)
                .context("resolved donor import has no OuterIndex")?;
            if outer >= 0 {
                bail!("resolved donor import does not point to a package");
            }
            let package = imports
                .get((-outer - 1) as usize)
                .context("resolved donor import package index is out of bounds")?;
            Ok((
                package
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .context("resolved donor package has no ObjectName")?
                    .to_owned(),
                object
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .context("resolved donor object has no ObjectName")?
                    .to_owned(),
            ))
        })
        .collect::<Result<Vec<_>>>()
}

fn resolved_import(document: &Value, class_name: &str) -> Result<(String, String)> {
    let matches = resolved_imports(document, class_name)?;
    if matches.len() != 1 {
        bail!(
            "current stock donor must have exactly one {class_name} import; found {}",
            matches.len()
        );
    }
    Ok(matches[0].clone())
}

fn content_relative_package_path(path: &str) -> Result<String> {
    let normalized = path.replace('\\', "/");
    let mut parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    while parts
        .first()
        .is_some_and(|part| matches!(*part, "." | ".."))
    {
        parts.remove(0);
    }
    if parts.iter().any(|part| matches!(*part, "." | "..")) {
        bail!("package path contains unresolved traversal: {path}");
    }
    let relative = if parts
        .first()
        .is_some_and(|part| part.eq_ignore_ascii_case("Game"))
    {
        &parts[1..]
    } else {
        let content_index = parts
            .iter()
            .position(|part| part.eq_ignore_ascii_case("Content"))
            .with_context(|| format!("package path is outside a mounted Content root: {path}"))?;
        if content_index != 1 {
            bail!("package path has an unsupported mounted Content layout: {path}");
        }
        &parts[content_index + 1..]
    };
    if relative.is_empty() {
        bail!("package path has no asset below its mounted root: {path}");
    }
    let mut relative = relative.join("/");
    for extension in [".uasset", ".umap"] {
        if relative
            .get(relative.len().saturating_sub(extension.len())..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(extension))
        {
            relative.truncate(relative.len() - extension.len());
            break;
        }
    }
    if relative.is_empty() {
        bail!("package path has no package name: {path}");
    }
    Ok(relative)
}

fn package_key(path: &str) -> Result<String> {
    Ok(content_relative_package_path(path)?.to_ascii_lowercase())
}

fn game_package_path(path: &str) -> Result<String> {
    Ok(format!("/Game/{}", content_relative_package_path(path)?))
}

fn target_for_path(
    path: &str,
    object_name: &str,
    class_name: &str,
    target_dependencies: &HashMap<u64, PackageEntry>,
) -> Result<ImportTarget> {
    let key = package_key(path)?;
    let matches = target_dependencies
        .values()
        .filter(|entry| package_key(&entry.path).is_ok_and(|value| value == key))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "expected one current dependency for {path}; found {}",
            matches.len()
        );
    }
    Ok(ImportTarget {
        package_id: matches[0].package_id,
        package_path: path.trim_end_matches(".uasset").to_owned(),
        object_name: object_name.to_owned(),
        class_name: class_name.to_owned(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MaterialSlotEvidence {
    object_import_index: usize,
    slot_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SerializedMaterialArray {
    offset: usize,
    slots: Vec<MaterialSlotEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetiredPhysicsAssetEvidence {
    object_import_index: usize,
    reference_offset: Option<usize>,
    removed_dependency_count: usize,
    already_retired: bool,
}

fn normalized_material_name(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if lower.len() > 4 {
        let suffix = &lower[lower.len() - 4..];
        if suffix.starts_with('_') && suffix[1..].chars().all(|value| value.is_ascii_digit()) {
            return lower[..lower.len() - 4].to_owned();
        }
    }
    lower
}

fn current_material_candidates(
    donor: &Value,
    target_dependencies: &HashMap<u64, PackageEntry>,
) -> Result<(Vec<ImportTarget>, Vec<ImportTarget>)> {
    let active = resolved_imports(donor, "MaterialInstanceConstant")?
        .into_iter()
        .map(|(package, object)| {
            target_for_path(
                &package,
                &object,
                "MaterialInstanceConstant",
                target_dependencies,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    if active.is_empty() {
        bail!("current stock donor has no active MaterialInstanceConstant imports");
    }

    let mut candidates = active.clone();
    candidates.extend(target_dependencies.values().filter_map(|entry| {
        let path = game_package_path(&entry.path).ok()?;
        let object_name = path.rsplit('/').next()?.to_owned();
        object_name
            .to_ascii_lowercase()
            .starts_with("mic_")
            .then(|| ImportTarget {
                package_id: entry.package_id,
                package_path: path,
                object_name,
                class_name: "MaterialInstanceConstant".to_owned(),
            })
    }));
    candidates.sort_by(|left, right| {
        left.package_path
            .to_ascii_lowercase()
            .cmp(&right.package_path.to_ascii_lowercase())
            .then(left.package_id.cmp(&right.package_id))
    });
    candidates.dedup_by(|left, right| {
        left.package_id == right.package_id
            && left.object_name.eq_ignore_ascii_case(&right.object_name)
    });
    Ok((active, candidates))
}

fn little_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    let value = bytes.get(offset..offset + 4)?;
    Some(i32::from_le_bytes(value.try_into().ok()?))
}

fn skeletal_mesh_export_bytes(document: &Value) -> Result<Vec<u8>> {
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("source UAsset JSON has no Exports")?;
    let matches = exports
        .iter()
        .filter(|export| {
            export
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.to_ascii_lowercase().starts_with("sk_"))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "replacement UAsset must contain exactly one SK_ raw export; found {}",
            matches.len()
        );
    }
    let export = matches[0];
    let data = export
        .get("Data")
        .and_then(Value::as_str)
        .or_else(|| export.get("Extras").and_then(Value::as_str))
        .context("replacement skeletal mesh has neither raw Data nor structured-export Extras")?;
    BASE64
        .decode(data)
        .context("replacement skeletal mesh payload is not base64")
}

fn structured_object_property_index(
    document: &Value,
    property_name: &str,
) -> Result<Option<usize>> {
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("source UAsset JSON has no Exports")?;
    let meshes = exports
        .iter()
        .filter(|export| {
            export
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.to_ascii_lowercase().starts_with("sk_"))
        })
        .collect::<Vec<_>>();
    if meshes.len() != 1 {
        bail!(
            "replacement UAsset must contain exactly one SK_ export; found {}",
            meshes.len()
        );
    }
    let Some(properties) = meshes[0].get("Data").and_then(Value::as_array) else {
        return Ok(None);
    };
    let matches = properties
        .iter()
        .filter(|property| {
            property
                .get("Name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(property_name))
                && property
                    .get("$type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind.contains("ObjectPropertyData"))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "structured skeletal mesh must contain exactly one {property_name} object property; found {}",
            matches.len()
        );
    }
    let reference = matches[0]
        .get("Value")
        .and_then(Value::as_i64)
        .with_context(|| format!("structured {property_name} property has no integer reference"))?;
    if reference == 0 {
        return Ok(None);
    }
    let index = reference
        .checked_neg()
        .and_then(|value| value.checked_sub(1))
        .and_then(|value| usize::try_from(value).ok())
        .with_context(|| {
            format!("structured {property_name} property is not an import reference")
        })?;
    Ok(Some(index))
}

fn serialized_material_slots(
    document: &Value,
    pairs: &[(usize, usize)],
    candidates: &[ImportTarget],
    material_aliases: &BTreeSet<String>,
) -> Result<SerializedMaterialArray> {
    const MATERIAL_BYTES: usize = 40;
    const MAX_MATERIALS: i32 = 64;
    let names = document
        .get("NameMap")
        .and_then(Value::as_array)
        .context("source UAsset JSON has no NameMap")?;
    let candidate_names = candidates
        .iter()
        .map(|target| normalized_material_name(&target.object_name))
        .collect::<BTreeSet<_>>();
    let unresolved_objects = pairs
        .iter()
        .map(|(_, object)| *object)
        .collect::<BTreeSet<_>>();
    let bytes = skeletal_mesh_export_bytes(document)?;
    let mut matches = Vec::new();
    for offset in 4..bytes.len().saturating_sub(MATERIAL_BYTES) {
        let Some(count) = little_i32(&bytes, offset - 4) else {
            continue;
        };
        if !(1..=MAX_MATERIALS).contains(&count) {
            continue;
        }
        let Some(end) = offset.checked_add(count as usize * MATERIAL_BYTES) else {
            continue;
        };
        if end > bytes.len() {
            continue;
        }
        let mut slots = Vec::new();
        for slot in 0..count as usize {
            let entry = offset + slot * MATERIAL_BYTES;
            let Some(reference) = little_i32(&bytes, entry) else {
                slots.clear();
                break;
            };
            let Some(object_import_index) = reference.checked_neg().and_then(|v| v.checked_sub(1))
            else {
                slots.clear();
                break;
            };
            let object_import_index = object_import_index as usize;
            let Some(name_index) = little_i32(&bytes, entry + 4) else {
                slots.clear();
                break;
            };
            let Some(name_number) = little_i32(&bytes, entry + 8) else {
                slots.clear();
                break;
            };
            let Some(slot_name) = usize::try_from(name_index)
                .ok()
                .and_then(|index| names.get(index))
                .and_then(Value::as_str)
            else {
                slots.clear();
                break;
            };
            if !unresolved_objects.contains(&object_import_index)
                || !(0..=16).contains(&name_number)
            {
                slots.clear();
                break;
            }
            slots.push(MaterialSlotEvidence {
                object_import_index,
                slot_name: slot_name.to_owned(),
            });
        }
        let every_object_has_a_named_target = slots.iter().all(|slot| {
            slots.iter().any(|candidate| {
                candidate.object_import_index == slot.object_import_index
                    && (candidate_names.contains(&normalized_material_name(&candidate.slot_name))
                        || material_aliases
                            .contains(&normalized_material_name(&candidate.slot_name)))
            })
        });
        if !slots.is_empty() && every_object_has_a_named_target {
            matches.push(SerializedMaterialArray { offset, slots });
        }
    }
    matches.sort_by(|left, right| {
        left.slots
            .iter()
            .map(|slot| (slot.object_import_index, slot.slot_name.as_str()))
            .cmp(
                right
                    .slots
                    .iter()
                    .map(|slot| (slot.object_import_index, slot.slot_name.as_str())),
            )
            .then(left.offset.cmp(&right.offset))
    });
    matches.dedup();
    if matches.len() != 1 {
        bail!(
            "replacement skeletal mesh must contain exactly one proven serialized material array; found {}",
            matches.len()
        );
    }
    Ok(matches.remove(0))
}

fn select_material_slot_targets(
    slots: &[MaterialSlotEvidence],
    candidates: &[ImportTarget],
    alias_targets: &HashMap<String, ImportTarget>,
) -> Result<Vec<ImportTarget>> {
    let mut targets_by_object = HashMap::new();
    for object in slots
        .iter()
        .map(|slot| slot.object_import_index)
        .collect::<BTreeSet<_>>()
    {
        let names = slots
            .iter()
            .filter(|slot| slot.object_import_index == object)
            .map(|slot| normalized_material_name(&slot.slot_name))
            .collect::<BTreeSet<_>>();
        let mut matches = candidates
            .iter()
            .filter(|target| names.contains(&normalized_material_name(&target.object_name)))
            .cloned()
            .collect::<Vec<_>>();
        if matches.is_empty() {
            for name in &names {
                if let Some(target) = alias_targets.get(name) {
                    matches.push(target.clone());
                }
            }
        }
        matches.sort_by_key(|target| target.package_id);
        matches.dedup_by_key(|target| target.package_id);
        if matches.len() != 1 {
            bail!(
                "serialized material import {object} must resolve through its slot names to exactly one current MIC dependency; found {}",
                matches.len()
            );
        }
        targets_by_object.insert(object, matches.remove(0));
    }
    slots
        .iter()
        .map(|slot| {
            targets_by_object
                .get(&slot.object_import_index)
                .cloned()
                .with_context(|| {
                    format!(
                        "serialized material slot {} has no object-identity target",
                        slot.slot_name
                    )
                })
        })
        .collect()
}

fn serialized_skeleton_import_index(
    document: &Value,
    pairs: &[(usize, usize)],
    material_objects: &BTreeSet<usize>,
) -> Result<usize> {
    if let Some(index) = structured_object_property_index(document, "Skeleton")? {
        let unresolved = pairs
            .iter()
            .map(|(_, object)| *object)
            .filter(|object| !material_objects.contains(object))
            .collect::<BTreeSet<_>>();
        if !unresolved.contains(&index) {
            bail!(
                "structured skeletal mesh Skeleton property does not reference an unresolved source import"
            );
        }
        return Ok(index);
    }
    let bytes = skeletal_mesh_export_bytes(document)?;
    let unresolved = pairs
        .iter()
        .map(|(_, object)| *object)
        .filter(|object| !material_objects.contains(object))
        .collect::<BTreeSet<_>>();
    let mut matches = BTreeSet::new();
    for offset in 0..bytes.len().min(64).saturating_sub(3) {
        let Some(reference) = little_i32(&bytes, offset) else {
            continue;
        };
        let Some(index) = reference.checked_neg().and_then(|v| v.checked_sub(1)) else {
            continue;
        };
        let index = index as usize;
        if unresolved.contains(&index) {
            matches.insert(index);
        }
    }
    if matches.len() != 1 {
        bail!(
            "replacement skeletal mesh must expose exactly one unresolved skeleton reference in its serialized header; found {}",
            matches.len()
        );
    }
    Ok(*matches.first().unwrap())
}

fn unversioned_nonzero_property_indices(bytes: &[u8]) -> Result<(usize, BTreeSet<usize>)> {
    const MAX_FRAGMENTS: usize = 64;
    let mut cursor = 0_usize;
    let mut schema_index = 0_usize;
    let mut zero_mask_count = 0_usize;
    let mut properties = Vec::<(usize, Option<usize>)>::new();
    for _ in 0..MAX_FRAGMENTS {
        let packed = u16::from_le_bytes(
            bytes
                .get(cursor..cursor + 2)
                .context("skeletal mesh has a truncated unversioned property header")?
                .try_into()
                .unwrap(),
        );
        cursor += 2;
        let skip = usize::from(packed & 0x007f);
        let has_zeroes = packed & 0x0080 != 0;
        let is_last = packed & 0x0100 != 0;
        let value_count = usize::from(packed >> 9);
        schema_index = schema_index
            .checked_add(skip)
            .context("unversioned property index overflow")?;
        for value in 0..value_count {
            let zero_index = has_zeroes.then(|| zero_mask_count + value);
            properties.push((schema_index + value, zero_index));
        }
        schema_index = schema_index
            .checked_add(value_count)
            .context("unversioned property index overflow")?;
        if has_zeroes {
            zero_mask_count += value_count;
        }
        if is_last {
            let zero_mask_bytes = match zero_mask_count {
                0 => 0,
                1..=8 => 1,
                9..=16 => 2,
                count => count.div_ceil(32) * 4,
            };
            let mask = bytes
                .get(cursor..cursor + zero_mask_bytes)
                .context("skeletal mesh has a truncated unversioned zero mask")?;
            let nonzero = properties
                .into_iter()
                .filter_map(|(index, zero_index)| {
                    let is_zero = zero_index.is_some_and(|bit| {
                        mask.get(bit / 8)
                            .is_some_and(|byte| byte & (1 << (bit % 8)) != 0)
                    });
                    (!is_zero).then_some(index)
                })
                .collect();
            return Ok((cursor + zero_mask_bytes, nonzero));
        }
    }
    bail!("skeletal mesh unversioned property header did not terminate")
}

fn retire_obsolete_physics_asset(
    document: &mut Value,
    donor: &Value,
    pairs: &[(usize, usize)],
    material_array: &SerializedMaterialArray,
    material_objects: &BTreeSet<usize>,
    skeleton_object_index: usize,
    orphan_object_import_count: usize,
) -> Result<Vec<RetiredPhysicsAssetEvidence>> {
    // This is deliberately narrow: a PhysicsAsset is retired only when the serialized evidence and the current donor agree.
    const SKELETAL_MESH_PHYSICS_ASSET_SCHEMA_INDEX: usize = 16;
    let auxiliary_objects = pairs
        .iter()
        .map(|(_, object)| *object)
        .filter(|object| *object != skeleton_object_index && !material_objects.contains(object))
        .collect::<Vec<_>>();
    if auxiliary_objects.is_empty() {
        return Ok(Vec::new());
    }
    if auxiliary_objects.len() != 1 {
        bail!(
            "replacement skeletal mesh has {} unresolved auxiliary imports; refusing to guess which one is PhysicsAsset",
            auxiliary_objects.len()
        );
    }
    if !resolved_imports(donor, "PhysicsAsset")?.is_empty() {
        bail!(
            "current stock donor still has an active PhysicsAsset import; donor-backed PhysicsAsset migration is not proven"
        );
    }

    let expected_reference = -i64::try_from(auxiliary_objects[0])? - 1;
    let structured_physics = structured_object_property_index(document, "PhysicsAsset")?;
    if structured_physics.is_some() {
        if structured_physics != Some(auxiliary_objects[0]) {
            bail!(
                "structured PhysicsAsset property does not reference the only unresolved auxiliary import"
            );
        }
        let export = document
            .get_mut("Exports")
            .and_then(Value::as_array_mut)
            .context("source UAsset JSON has no mutable Exports")?
            .iter_mut()
            .find(|export| {
                export
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.to_ascii_lowercase().starts_with("sk_"))
            })
            .context("source UAsset JSON has no mutable SK_ export")?;
        let properties = export
            .get_mut("Data")
            .and_then(Value::as_array_mut)
            .context("structured skeletal mesh Data is not an array")?;
        let physics = properties
            .iter_mut()
            .find(|property| {
                property
                    .get("Name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case("PhysicsAsset"))
            })
            .context("structured skeletal mesh has no PhysicsAsset property")?;
        if physics.get("Value").and_then(Value::as_i64) != Some(expected_reference) {
            bail!("structured PhysicsAsset property changed during migration");
        }
        physics["Value"] = Value::from(0);
        let dependencies = export
            .get_mut("CreateBeforeSerializationDependencies")
            .and_then(Value::as_array_mut)
            .context("skeletal mesh export has no CreateBeforeSerializationDependencies")?;
        let dependency_count = dependencies
            .iter()
            .filter(|value| value.as_i64() == Some(expected_reference))
            .count();
        dependencies.retain(|value| value.as_i64() != Some(expected_reference));
        return Ok(vec![RetiredPhysicsAssetEvidence {
            object_import_index: auxiliary_objects[0],
            reference_offset: None,
            removed_dependency_count: dependency_count,
            already_retired: false,
        }]);
    }

    let mut bytes = skeletal_mesh_export_bytes(document)?;
    let (header_size, nonzero_properties) = unversioned_nonzero_property_indices(&bytes)?;
    if !nonzero_properties.contains(&SKELETAL_MESH_PHYSICS_ASSET_SCHEMA_INDEX) {
        bail!(
            "unresolved auxiliary import is not backed by serialized USkeletalMesh PhysicsAsset property slot 16"
        );
    }
    let object_import_index = auxiliary_objects[0];
    let reference = -i32::try_from(object_import_index)? - 1;
    let serialized_property_end = material_array.offset.min(bytes.len());
    let reference_offsets = (header_size..serialized_property_end.saturating_sub(3))
        .filter(|offset| little_i32(&bytes, *offset) == Some(reference))
        .collect::<Vec<_>>();

    let export = document
        .get_mut("Exports")
        .and_then(Value::as_array_mut)
        .context("source UAsset JSON has no mutable Exports")?
        .iter_mut()
        .filter(|export| {
            export
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.to_ascii_lowercase().starts_with("sk_"))
        })
        .collect::<Vec<_>>();
    if export.len() != 1 {
        bail!("replacement UAsset must contain exactly one mutable SK_ raw export");
    }
    let export = export.into_iter().next().unwrap();
    let dependency = i64::from(reference);
    let dependencies = export
        .get_mut("CreateBeforeSerializationDependencies")
        .and_then(Value::as_array_mut)
        .context("skeletal mesh export has no CreateBeforeSerializationDependencies")?;
    let dependency_count = dependencies
        .iter()
        .filter(|value| value.as_i64() == Some(dependency))
        .count();
    if reference_offsets.is_empty() && dependency_count == 0 && orphan_object_import_count == 1 {
        return Ok(vec![RetiredPhysicsAssetEvidence {
            object_import_index,
            reference_offset: None,
            removed_dependency_count: 0,
            already_retired: true,
        }]);
    }
    if reference_offsets.len() != 1 {
        bail!(
            "serialized PhysicsAsset import {} must occur exactly once in the property region before the material array, or be a proven inactive tombstone; found {} property references",
            object_import_index,
            reference_offsets.len()
        );
    }
    if dependency_count == 0 {
        bail!(
            "serialized PhysicsAsset import {} must have at least one matching create-before-serialization dependency",
            object_import_index
        );
    }
    let reference_offset = reference_offsets[0];
    dependencies.retain(|value| value.as_i64() != Some(dependency));
    bytes[reference_offset..reference_offset + 4].copy_from_slice(&0_i32.to_le_bytes());
    export["Data"] = Value::String(BASE64.encode(&bytes));
    Ok(vec![RetiredPhysicsAssetEvidence {
        object_import_index,
        reference_offset: Some(reference_offset),
        removed_dependency_count: dependency_count,
        already_retired: false,
    }])
}

fn ignored_material_dependencies(
    candidate_dependency_ids: &[u64],
    selected: &[ImportTarget],
    target_dependencies: &HashMap<u64, PackageEntry>,
) -> Vec<String> {
    let selected_ids = selected
        .iter()
        .map(|target| target.package_id)
        .collect::<BTreeSet<_>>();
    let mut ignored = candidate_dependency_ids
        .iter()
        .filter(|package_id| !selected_ids.contains(package_id))
        .filter_map(|package_id| target_dependencies.get(package_id))
        .filter(|entry| {
            entry
                .path
                .replace('\\', "/")
                .rsplit('/')
                .next()
                .is_some_and(|leaf| leaf.to_ascii_lowercase().starts_with("mic_"))
        })
        .filter_map(|entry| game_package_path(&entry.path).ok())
        .collect::<Vec<_>>();
    ignored.sort_by_key(|path| path.to_ascii_lowercase());
    ignored.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    ignored
}

fn unresolved_import_pairs(document: &Value) -> Result<Vec<(usize, usize)>> {
    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("source UAsset JSON has no Imports")?;
    let mut pairs = Vec::new();
    for (package_index, package) in imports.iter().enumerate() {
        if package.get("ClassName").and_then(Value::as_str) != Some("Package")
            || !package
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("/Engine/UnknownPackage"))
        {
            continue;
        }
        let outer = -i64::try_from(package_index)? - 1;
        let children = imports
            .iter()
            .enumerate()
            .filter(|(_, import)| import.get("OuterIndex").and_then(Value::as_i64) == Some(outer))
            .collect::<Vec<_>>();
        if children.is_empty() {
            continue;
        }
        if children.iter().any(|(_, import)| {
            import.get("ObjectName").and_then(Value::as_str) != Some("UnknownExport")
        }) {
            bail!(
                "unresolved package import {package_index} does not contain only unresolved object children"
            );
        }
        pairs.extend(
            children
                .into_iter()
                .map(|(object_index, _)| (package_index, object_index)),
        );
    }
    Ok(pairs)
}

pub fn unresolved_package_store_dependencies(
    asset: &Path,
    source_store: &PackageStoreEntry,
    available_dependencies: &HashMap<u64, PackageEntry>,
    work: &Path,
) -> Result<Vec<PackageEntry>> {
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let json_path = work.join("source.json");
    tool.to_json(asset, &json_path)?;
    let document: Value = serde_json::from_slice(&fs::read(&json_path)?)?;
    let pairs = unresolved_import_pairs(&document)?;
    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("authored package has no Imports")?;
    let resolved_ids = imports
        .iter()
        .filter(|import| import.get("ClassName").and_then(Value::as_str) == Some("Package"))
        .filter_map(|import| import.get("ObjectName").and_then(Value::as_str))
        .filter(|name| {
            name.get(..6)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/Game/"))
        })
        .map(unreal_package_id)
        .collect::<Result<HashSet<_>>>()?;
    let missing = source_store
        .imported_package_ids
        .iter()
        .filter(|package_id| !resolved_ids.contains(package_id))
        .map(|package_id| {
            available_dependencies
                .get(package_id)
                .cloned()
                .with_context(|| {
                    format!("authored package store references unavailable package {package_id}")
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let unresolved_package_count = pairs
        .iter()
        .map(|(package_index, _)| *package_index)
        .collect::<BTreeSet<_>>()
        .len();
    let one_target_proves_all_placeholders = missing.len() == 1 && unresolved_package_count > 0;
    if !one_target_proves_all_placeholders && unresolved_package_count != missing.len() {
        bail!(
            "decoder exposes {unresolved_package_count} unresolved package import(s), but package-store comparison identifies {} missing resolved package identity/identities",
            missing.len()
        );
    }
    Ok(missing)
}

fn serialized_resolved_material_slots(document: &Value) -> Result<SerializedMaterialArray> {
    const MATERIAL_BYTES: usize = 40;
    const MAX_MATERIALS: i32 = 64;
    let names = document
        .get("NameMap")
        .and_then(Value::as_array)
        .context("source UAsset JSON has no NameMap")?;
    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("source UAsset JSON has no Imports")?;
    let bytes = skeletal_mesh_export_bytes(document)?;
    let mut matches = Vec::new();
    for offset in 4..bytes.len().saturating_sub(MATERIAL_BYTES) {
        let Some(count) = little_i32(&bytes, offset - 4) else {
            continue;
        };
        if !(1..=MAX_MATERIALS).contains(&count) {
            continue;
        }
        let Some(end) = offset.checked_add(count as usize * MATERIAL_BYTES) else {
            continue;
        };
        if end > bytes.len() {
            continue;
        }
        let mut slots = Vec::new();
        for slot in 0..count as usize {
            let entry = offset + slot * MATERIAL_BYTES;
            let Some(reference) = little_i32(&bytes, entry) else {
                slots.clear();
                break;
            };
            let Some(name_index) = little_i32(&bytes, entry + 4) else {
                slots.clear();
                break;
            };
            let Some(name_number) = little_i32(&bytes, entry + 8) else {
                slots.clear();
                break;
            };
            let Some(slot_name) = usize::try_from(name_index)
                .ok()
                .and_then(|index| names.get(index))
                .and_then(Value::as_str)
            else {
                slots.clear();
                break;
            };
            if !(0..=16).contains(&name_number) {
                slots.clear();
                break;
            }
            if reference == 0 {
                continue;
            }
            let Some(object_index) = reference
                .checked_neg()
                .and_then(|value| value.checked_sub(1))
            else {
                slots.clear();
                break;
            };
            let Ok(object_index) = usize::try_from(object_index) else {
                slots.clear();
                break;
            };
            let Some(import) = imports.get(object_index) else {
                slots.clear();
                break;
            };
            if import.get("ClassName").and_then(Value::as_str) != Some("MaterialInstanceConstant") {
                slots.clear();
                break;
            }
            slots.push(MaterialSlotEvidence {
                object_import_index: object_index,
                slot_name: slot_name.to_owned(),
            });
        }
        if !slots.is_empty() {
            matches.push(SerializedMaterialArray { offset, slots });
        }
    }
    matches.sort_by(|left, right| {
        left.slots
            .iter()
            .map(|slot| (slot.object_import_index, slot.slot_name.as_str()))
            .cmp(
                right
                    .slots
                    .iter()
                    .map(|slot| (slot.object_import_index, slot.slot_name.as_str())),
            )
            .then(left.offset.cmp(&right.offset))
    });
    matches.dedup();
    if matches.len() != 1 {
        bail!(
            "replacement skeletal mesh must contain exactly one proven resolved material array; found {}",
            matches.len()
        );
    }
    Ok(matches.remove(0))
}

fn prove_serialized_object_property(
    document: &Value,
    property_name: &str,
    schema_index: usize,
    object_import_index: usize,
    serialized_property_end: usize,
) -> Result<()> {
    if let Some(index) = structured_object_property_index(document, property_name)? {
        if index != object_import_index {
            bail!(
                "structured {property_name} property does not reference the proven unresolved import"
            );
        }
        return Ok(());
    }
    let bytes = skeletal_mesh_export_bytes(document)?;
    let (header_size, nonzero_properties) = unversioned_nonzero_property_indices(&bytes)?;
    if !nonzero_properties.contains(&schema_index) {
        bail!(
            "unresolved import is not backed by serialized {property_name} property slot {schema_index}"
        );
    }
    let reference = -i32::try_from(object_import_index)? - 1;
    let offsets = (header_size..serialized_property_end.min(bytes.len()).saturating_sub(3))
        .filter(|offset| little_i32(&bytes, *offset) == Some(reference))
        .collect::<Vec<_>>();
    if offsets.len() != 1 {
        bail!(
            "serialized {property_name} import {object_import_index} must occur exactly once in its property region; found {}",
            offsets.len()
        );
    }
    Ok(())
}

fn add_import_names(document: &mut Value, targets: &[ImportTarget]) -> Result<()> {
    let names = document
        .get_mut("NameMap")
        .and_then(Value::as_array_mut)
        .context("source UAsset JSON has no NameMap")?;
    for name in targets.iter().flat_map(|target| {
        [
            target.package_path.as_str(),
            target.object_name.as_str(),
            target.class_name.as_str(),
        ]
    }) {
        if !names.iter().any(|value| value.as_str() == Some(name)) {
            names.push(Value::String(name.to_owned()));
        }
    }
    Ok(())
}

fn replacement_dependency_sets(
    source_store: &PackageStoreEntry,
    available_dependencies: &HashMap<u64, PackageEntry>,
    repaired_targets: &[ImportTarget],
) -> (Vec<u64>, Vec<u64>) {
    let missing = source_store
        .imported_package_ids
        .iter()
        .filter(|package_id| !available_dependencies.contains_key(package_id))
        .copied()
        .collect::<Vec<_>>();
    let mut target = source_store
        .imported_package_ids
        .iter()
        .filter(|package_id| available_dependencies.contains_key(package_id))
        .copied()
        .collect::<BTreeSet<_>>();
    target.extend(repaired_targets.iter().map(|value| value.package_id));
    (missing, target.into_iter().collect())
}

pub fn repair_composite_skeletal_mesh_imports(
    asset: &Path,
    donor_asset: &Path,
    source_store: &PackageStoreEntry,
    available_dependencies: &HashMap<u64, PackageEntry>,
    work: &Path,
) -> Result<CompositePackageImportRepair> {
    const SKELETAL_MESH_PHYSICS_ASSET_SCHEMA_INDEX: usize = 16;
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work.join("source.json");
    let donor_json = work.join("donor.json");
    let patched_json = work.join("patched.json");
    let verify_json = work.join("verify.json");
    let rebuilt_asset = work.join(
        asset
            .file_name()
            .context("replacement UAsset has no filename")?,
    );
    tool.to_json(asset, &source_json)?;
    tool.to_json(donor_asset, &donor_json)?;
    let mut document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let donor: Value = serde_json::from_slice(&fs::read(&donor_json)?)?;
    let original_exports = validated_export_data(&document)?;
    let pairs = unresolved_import_pairs(&document)?;
    if pairs.len() != 2 {
        bail!(
            "composite skeletal-mesh repair requires exactly two unresolved object imports (skeleton and physics); found {}",
            pairs.len()
        );
    }
    let material_array = serialized_resolved_material_slots(&document)?;
    let material_objects = material_array
        .slots
        .iter()
        .map(|slot| slot.object_import_index)
        .collect::<BTreeSet<_>>();
    let skeleton_object_index =
        serialized_skeleton_import_index(&document, &pairs, &material_objects)?;
    let auxiliary = pairs
        .iter()
        .map(|(_, object)| *object)
        .filter(|object| *object != skeleton_object_index)
        .collect::<Vec<_>>();
    if auxiliary.len() != 1 {
        bail!("composite skeletal mesh does not expose exactly one physics candidate");
    }
    let (skeleton_package, skeleton_object) = resolved_import(&donor, "Skeleton")?;
    let skeleton = target_for_path(
        &skeleton_package,
        &skeleton_object,
        "Skeleton",
        available_dependencies,
    )?;
    let donor_physics = resolved_imports(&donor, "PhysicsAsset")?;
    if donor_physics.len() > 1 {
        bail!("current stock donor has more than one PhysicsAsset import");
    }
    let active_physics = donor_physics
        .first()
        .map(|(package, object)| {
            prove_serialized_object_property(
                &document,
                "PhysicsAsset",
                SKELETAL_MESH_PHYSICS_ASSET_SCHEMA_INDEX,
                auxiliary[0],
                material_array.offset,
            )?;
            target_for_path(package, object, "PhysicsAsset", available_dependencies)
        })
        .transpose()?;
    let retired = if active_physics.is_none() {
        retire_obsolete_physics_asset(
            &mut document,
            &donor,
            &pairs,
            &material_array,
            &material_objects,
            skeleton_object_index,
            0,
        )?
    } else {
        Vec::new()
    };
    let mut patches = pairs
        .iter()
        .map(|(package, object)| {
            let target = if *object == skeleton_object_index {
                skeleton.clone()
            } else {
                active_physics.clone().unwrap_or_else(|| skeleton.clone())
            };
            ((*package, *object), target)
        })
        .collect::<Vec<_>>();
    patches.sort_by_key(|((package, object), _)| (*package, *object));
    {
        let imports = document
            .get_mut("Imports")
            .and_then(Value::as_array_mut)
            .context("source UAsset JSON Imports is not an array")?;
        for ((package_index, object_index), target) in &patches {
            imports[*package_index]["ObjectName"] = Value::String(target.package_path.clone());
            imports[*object_index]["ObjectName"] = Value::String(target.object_name.clone());
            imports[*object_index]["ClassPackage"] = Value::String("/Script/Engine".to_owned());
            imports[*object_index]["ClassName"] = Value::String(target.class_name.clone());
        }
    }
    let targets = patches
        .iter()
        .map(|(_, target)| target.clone())
        .collect::<Vec<_>>();
    add_import_names(&mut document, &targets)?;
    let intended_exports = validated_export_data(&document)?;
    let exports_byte_identical = original_exports == intended_exports;
    fs::write(&patched_json, serde_json::to_vec(&document)?)?;
    tool.import_json(&patched_json, &rebuilt_asset)?;
    let source_uexp = asset.with_extension("uexp");
    let rebuilt_uexp = rebuilt_asset.with_extension("uexp");
    if source_uexp.is_file() != rebuilt_uexp.is_file() {
        bail!("composite skeletal repair changed UEXP presence");
    }
    let uexp_byte_identical =
        !source_uexp.is_file() || sha256_file(&source_uexp)? == sha256_file(&rebuilt_uexp)?;
    if retired.is_empty() && !uexp_byte_identical {
        bail!("reference-only skeletal repair changed authored UEXP bytes");
    }
    if retired.iter().any(|evidence| !evidence.already_retired) && uexp_byte_identical {
        bail!("retired PhysicsAsset repair did not change its serialized reference");
    }
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    if validated_export_data(&verified)? != intended_exports {
        bail!("composite skeletal repair did not preserve its approved export migration");
    }
    if !unresolved_import_pairs(&verified)?.is_empty() {
        bail!("composite skeletal repair retained unresolved imports");
    }
    fs::copy(&rebuilt_asset, asset)?;
    if rebuilt_uexp.is_file() {
        fs::copy(&rebuilt_uexp, &source_uexp)?;
    }
    let (missing, target_imported_package_ids) =
        replacement_dependency_sets(source_store, available_dependencies, &targets);
    let stale_create_dependencies_removed = retired
        .iter()
        .map(|evidence| evidence.removed_dependency_count)
        .sum();
    let mut repaired_targets = targets
        .iter()
        .map(|target| target.package_path.clone())
        .collect::<Vec<_>>();
    repaired_targets.sort_by_key(|path| path.to_ascii_lowercase());
    repaired_targets.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    Ok(CompositePackageImportRepair {
        asset: asset.to_string_lossy().replace('\\', "/"),
        package_id: source_store.package_id,
        asset_kind: "skeletal-mesh".to_owned(),
        repaired_import_count: patches.len(),
        repaired_targets,
        retired_physics_asset: retired.iter().any(|evidence| !evidence.already_retired),
        stale_create_dependencies_removed,
        source_imported_package_ids: source_store.imported_package_ids.clone(),
        missing_source_imported_package_ids: missing,
        target_imported_package_ids,
        exports_byte_identical,
        uexp_byte_identical,
        policy: "serialized-role-current-template-import-rebase-v1".to_owned(),
    })
}

fn export_class_name(document: &Value, export: &Value) -> Result<String> {
    let class_index = export
        .get("ClassIndex")
        .and_then(Value::as_i64)
        .context("UAsset export has no ClassIndex")?;
    let import_index = class_index
        .checked_neg()
        .and_then(|value| value.checked_sub(1))
        .and_then(|value| usize::try_from(value).ok())
        .context("UAsset export ClassIndex is not an import reference")?;
    document
        .get("Imports")
        .and_then(Value::as_array)
        .and_then(|imports| imports.get(import_index))
        .and_then(|import| import.get("ObjectName"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context("UAsset export class import has no ObjectName")
}

fn rewrite_root_identity(
    document: &mut Value,
    source_package_name: &str,
    target_package_name: &str,
    source_object_name: &str,
    target_object_name: &str,
) -> Result<()> {
    let folder = document
        .get_mut("FolderName")
        .context("UAsset JSON has no FolderName")?;
    if !folder
        .as_str()
        .is_some_and(|value| value.eq_ignore_ascii_case(source_package_name))
    {
        bail!("package FolderName does not match its source identity");
    }
    *folder = Value::String(target_package_name.to_owned());

    let names = document
        .get_mut("NameMap")
        .and_then(Value::as_array_mut)
        .context("UAsset JSON has no NameMap")?;
    let mut package_name_count = 0;
    let mut object_name_count = 0;
    for name in names {
        if name
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(source_package_name))
        {
            *name = Value::String(target_package_name.to_owned());
            package_name_count += 1;
        } else if name
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(source_object_name))
        {
            *name = Value::String(target_object_name.to_owned());
            object_name_count += 1;
        }
    }
    if package_name_count != 1 || object_name_count != 1 {
        bail!(
            "package identity alias requires one root package name and one root object name in the NameMap; found {package_name_count}/{object_name_count}"
        );
    }

    let exports = document
        .get_mut("Exports")
        .and_then(Value::as_array_mut)
        .context("UAsset JSON has no Exports")?;
    let roots = exports
        .iter_mut()
        .filter(|export| export.get("OuterIndex").and_then(Value::as_i64) == Some(0))
        .filter(|export| {
            export
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(source_object_name))
        })
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        bail!(
            "package identity alias requires exactly one matching top-level public export; found {}",
            roots.len()
        );
    }
    roots.into_iter().next().unwrap()["ObjectName"] = Value::String(target_object_name.to_owned());
    Ok(())
}

pub fn create_package_identity_alias(
    source_asset: &Path,
    source_package: &PackageEntry,
    target_package_name: &str,
    target_package_id: u64,
    expected_class: &str,
    output_root: &Path,
    work: &Path,
) -> Result<(PathBuf, PackageIdentityAlias)> {
    let calculated_target = unreal_package_id(target_package_name)?;
    if calculated_target != target_package_id {
        bail!(
            "recovered package name {target_package_name} hashes to {calculated_target}, not unresolved package ID {target_package_id}"
        );
    }
    let source_package_name = game_package_path(&source_package.path)?;
    if unreal_package_id(&source_package_name)? != source_package.package_id {
        bail!("source package path and package ID disagree");
    }
    if source_package.package_id == target_package_id
        || source_package_name.eq_ignore_ascii_case(target_package_name)
    {
        bail!("identity alias target must differ from its source package");
    }
    let source_object_name = package_name_leaf(&source_package_name)?.to_owned();
    let target_object_name = package_name_leaf(target_package_name)?.to_owned();
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work.join("source.json");
    let patched_json = work.join("patched.json");
    let verify_json = work.join("verify.json");
    tool.to_json(source_asset, &source_json)?;
    let original: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let original_exports = validated_export_data(&original)?;
    let source_root = original
        .get("Exports")
        .and_then(Value::as_array)
        .context("source package has no Exports")?
        .iter()
        .filter(|export| export.get("OuterIndex").and_then(Value::as_i64) == Some(0))
        .filter(|export| {
            export
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(&source_object_name))
        })
        .collect::<Vec<_>>();
    if source_root.len() != 1 {
        bail!("source alias candidate has no unique top-level public export");
    }
    let asset_class = export_class_name(&original, source_root[0])?;
    if !asset_class.eq_ignore_ascii_case(expected_class) {
        bail!("identity alias candidate class is {asset_class}, expected {expected_class}");
    }

    let mut patched = original.clone();
    rewrite_root_identity(
        &mut patched,
        &source_package_name,
        target_package_name,
        &source_object_name,
        &target_object_name,
    )?;
    let mut normalized = patched.clone();
    rewrite_root_identity(
        &mut normalized,
        target_package_name,
        &source_package_name,
        &target_object_name,
        &source_object_name,
    )?;
    if normalized != original {
        bail!("identity alias changed package metadata outside the approved root identity fields");
    }
    fs::write(&patched_json, serde_json::to_vec(&patched)?)?;

    let rebuilt_root = work.join("rebuilt");
    let rebuilt_asset = rebuilt_root.join(legacy_path_for_package_name(target_package_name)?);
    fs::create_dir_all(
        rebuilt_asset
            .parent()
            .context("identity alias output has no parent")?,
    )?;
    tool.import_json(&patched_json, &rebuilt_asset)?;
    let source_uexp = source_asset.with_extension("uexp");
    let rebuilt_uexp = rebuilt_asset.with_extension("uexp");
    if source_uexp.is_file() != rebuilt_uexp.is_file() {
        bail!("identity alias changed UEXP presence");
    }
    let uexp_byte_identical =
        !source_uexp.is_file() || sha256_file(&source_uexp)? == sha256_file(&rebuilt_uexp)?;
    if !uexp_byte_identical {
        bail!("identity alias changed authored UEXP bytes");
    }
    for extension in ["ubulk", "uptnl"] {
        let source_sidecar = source_asset.with_extension(extension);
        if source_sidecar.is_file() {
            fs::copy(&source_sidecar, rebuilt_asset.with_extension(extension))?;
        }
    }
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let mut verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    rewrite_root_identity(
        &mut verified,
        target_package_name,
        &source_package_name,
        &target_object_name,
        &source_object_name,
    )?;
    if validated_export_data(&verified)? != original_exports {
        bail!("identity alias did not preserve normalized export payloads");
    }

    let relative = legacy_path_for_package_name(target_package_name)?;
    let destination = output_root.join(&relative);
    if destination.exists() {
        bail!(
            "identity alias destination already exists: {}",
            destination.display()
        );
    }
    fs::create_dir_all(
        destination
            .parent()
            .context("identity alias destination has no parent")?,
    )?;
    for extension in ["uasset", "uexp", "ubulk", "uptnl"] {
        let source = rebuilt_asset.with_extension(extension);
        if source.is_file() {
            fs::copy(&source, destination.with_extension(extension))?;
        }
    }
    Ok((
        destination,
        PackageIdentityAlias {
            source_package_id: source_package.package_id,
            source_package_path: source_package_name,
            target_package_id,
            target_package_path: target_package_name.to_owned(),
            source_object_name,
            target_object_name,
            asset_class,
            export_payloads_preserved: true,
            uexp_byte_identical,
            provenance: "deterministically_inferred".to_owned(),
            policy: "package-root-public-export-identity-alias-v1".to_owned(),
        },
    ))
}

pub fn prove_blueprint_alias_role(
    consumer_asset: &Path,
    target_package_name: &str,
    target_package_id: u64,
    expected_class: &str,
    work: &Path,
) -> Result<BlueprintAliasRoleEvidence> {
    if unreal_package_id(target_package_name)? != target_package_id {
        bail!("Blueprint role target path and package ID disagree");
    }
    let target_object_name = package_name_leaf(target_package_name)?.to_owned();
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let json_path = work.join("consumer.json");
    tool.to_json(consumer_asset, &json_path)?;
    let document: Value = serde_json::from_slice(&fs::read(&json_path)?)?;
    validated_export_data(&document)?;
    let unresolved_pairs = unresolved_import_pairs(&document)?;
    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("Blueprint consumer has no Imports")?;
    let package_indices = imports
        .iter()
        .enumerate()
        .filter(|(_, import)| import.get("ClassName").and_then(Value::as_str) == Some("Package"))
        .filter(|(_, import)| {
            import
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(target_package_name))
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if package_indices.len() > 1 {
        bail!(
            "Blueprint consumer imports the recovered package identity more than once; found {}",
            package_indices.len()
        );
    }
    let object_indices = if package_indices.len() == 1 {
        let package_outer = -i64::try_from(package_indices[0])? - 1;
        imports
            .iter()
            .enumerate()
            .filter(|(_, import)| {
                import.get("OuterIndex").and_then(Value::as_i64) == Some(package_outer)
            })
            .filter(|(_, import)| {
                import
                    .get("ClassName")
                    .and_then(Value::as_str)
                    .is_some_and(|class| class.eq_ignore_ascii_case(expected_class))
            })
            .filter(|(_, import)| {
                import
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case(&target_object_name))
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
    } else {
        unresolved_pairs
            .iter()
            .map(|(_, object)| *object)
            .collect::<Vec<_>>()
    };
    let (role, required_export_name) =
        if expected_class.eq_ignore_ascii_case("MaterialInstanceConstant") {
            ("blood-splatter-material", "bloodsplatter")
        } else if expected_class.eq_ignore_ascii_case("StaticMesh") {
            ("scabbard-static-mesh", "scabbard")
        } else {
            bail!("Blueprint identity aliases do not support role proof for {expected_class}");
        };
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("Blueprint consumer has no Exports")?;
    let mut matches = Vec::new();
    for object_index in object_indices {
        let reference = (-i32::try_from(object_index)? - 1).to_le_bytes();
        let mut object_matches = Vec::new();
        let mut all_reference_count = 0_usize;
        for (export_index, export) in exports.iter().enumerate() {
            let Some(encoded) = export.get("Data").and_then(Value::as_str) else {
                continue;
            };
            let bytes = BASE64.decode(encoded)?;
            for offset in 0..bytes.len().saturating_sub(3) {
                if bytes[offset..offset + 4] != reference {
                    continue;
                }
                all_reference_count += 1;
                let export_name = export
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if export_name
                    .to_ascii_lowercase()
                    .contains(required_export_name)
                {
                    object_matches.push((export_index, export_name.to_owned(), offset));
                }
            }
        }
        if all_reference_count == 1 && object_matches.len() == 1 {
            let (export_index, export_name, offset) = object_matches.remove(0);
            matches.push((object_index, export_index, export_name, offset));
        }
    }
    if matches.len() != 1 {
        bail!(
            "recovered {expected_class} import must map to exactly one serialized Blueprint role reference; found {}",
            matches.len()
        );
    }
    let (object_import_index, export_index, export_name, serialized_reference_offset) =
        matches.remove(0);
    Ok(BlueprintAliasRoleEvidence {
        consumer: consumer_asset.display().to_string(),
        target_package_id,
        target_package_path: target_package_name.to_owned(),
        target_object_name,
        target_class: expected_class.to_owned(),
        role: role.to_owned(),
        export_name,
        export_index,
        object_import_index,
        serialized_reference_offset,
        provenance: "serialized-consumer-reference".to_owned(),
        policy: "blueprint-serialized-alias-role-proof-v1".to_owned(),
    })
}

/// Retires one optional secondary Blueprint component dependency after its serialized role was
/// proven. The dead import pair is rebound to an already-bundled dependency so the rebuilt package
/// store no longer requires the absent package; the component property itself is explicitly null.
pub fn suppress_optional_blueprint_dependency(
    consumer_asset: &Path,
    source_store: &PackageStoreEntry,
    target_package: &PackageEntry,
    replacement_package: &PackageEntry,
    replacement_object_name: &str,
    evidence: &BlueprintAliasRoleEvidence,
    work: &Path,
) -> Result<OptionalBlueprintDependencySuppression> {
    if evidence.role != "scabbard-static-mesh"
        || evidence.target_class != "StaticMesh"
        || evidence.target_package_id != target_package.package_id
    {
        bail!("optional Blueprint suppression requires a proven secondary StaticMesh role");
    }
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work.join("source.json");
    let patched_json = work.join("patched.json");
    let verify_json = work.join("verify.json");
    let rebuilt_asset = work.join(
        consumer_asset
            .file_name()
            .context("Blueprint consumer has no filename")?,
    );
    tool.to_json(consumer_asset, &source_json)?;
    let mut document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    validated_export_data(&document)?;
    let original_unresolved_pairs = unresolved_import_pairs(&document)?;
    let original_resolved_package_ids = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("Blueprint consumer has no Imports")?
        .iter()
        .filter(|import| import.get("ClassName").and_then(Value::as_str) == Some("Package"))
        .filter_map(|import| import.get("ObjectName").and_then(Value::as_str))
        .filter(|name| {
            name.get(..6)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/Game/"))
        })
        .map(unreal_package_id)
        .collect::<Result<BTreeSet<_>>>()?;

    let target_path = game_package_path(&target_package.path)?;
    let replacement_path = game_package_path(&replacement_package.path)?;
    let calculated_replacement_id = unreal_package_id(&replacement_path)?;
    if calculated_replacement_id != replacement_package.package_id {
        bail!(
            "optional Blueprint replacement path hashes to {calculated_replacement_id}, not replacement package ID {}",
            replacement_package.package_id
        );
    }
    let (package_index, object_index) = {
        let imports = document
            .get("Imports")
            .and_then(Value::as_array)
            .context("Blueprint consumer has no Imports")?;
        let packages = imports
            .iter()
            .enumerate()
            .filter(|(_, import)| {
                import.get("ClassName").and_then(Value::as_str) == Some("Package")
            })
            .filter(|(_, import)| {
                import
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case(&target_path))
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if packages.len() == 1 {
            let outer = -i64::try_from(packages[0])? - 1;
            let objects = imports
                .iter()
                .enumerate()
                .filter(|(_, import)| {
                    import.get("OuterIndex").and_then(Value::as_i64) == Some(outer)
                })
                .filter(|(_, import)| {
                    import
                        .get("ClassName")
                        .and_then(Value::as_str)
                        .is_some_and(|name| name.eq_ignore_ascii_case("StaticMesh"))
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if objects != [evidence.object_import_index] {
                bail!("optional Blueprint resolved target object identity changed");
            }
            (packages[0], objects[0])
        } else if packages.is_empty() {
            let pairs = original_unresolved_pairs
                .iter()
                .filter(|(_, object)| *object == evidence.object_import_index)
                .copied()
                .collect::<Vec<_>>();
            if pairs.len() != 1 {
                bail!("optional Blueprint unresolved role has no unique import pair");
            }
            pairs[0]
        } else {
            bail!("optional Blueprint target package occurs more than once");
        }
    };
    let reference = -i32::try_from(object_index)? - 1;
    let reference_bytes = reference.to_le_bytes();
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("Blueprint consumer has no Exports")?;
    let total_references = exports
        .iter()
        .filter_map(|export| export.get("Data").and_then(Value::as_str))
        .map(|encoded| BASE64.decode(encoded))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(|bytes| {
            bytes
                .windows(4)
                .filter(|window| *window == reference_bytes)
                .count()
        })
        .sum::<usize>();
    if total_references != 1 {
        bail!("optional Blueprint import must have exactly one serialized reference");
    }

    let export = document
        .get_mut("Exports")
        .and_then(Value::as_array_mut)
        .and_then(|exports| exports.get_mut(evidence.export_index))
        .context("optional Blueprint role export index is unavailable")?;
    if export.get("ObjectName").and_then(Value::as_str) != Some(evidence.export_name.as_str()) {
        bail!("optional Blueprint role export identity changed");
    }
    let mut bytes = BASE64.decode(
        export
            .get("Data")
            .and_then(Value::as_str)
            .context("optional Blueprint role export has no raw Data")?,
    )?;
    let offset = evidence.serialized_reference_offset;
    if bytes.get(offset..offset + 4) != Some(reference_bytes.as_slice()) {
        bail!("optional Blueprint serialized role reference moved");
    }
    bytes[offset..offset + 4].copy_from_slice(&0_i32.to_le_bytes());
    export["Data"] = Value::String(BASE64.encode(&bytes));
    let mut removed_dependency_count = 0_usize;
    for key in [
        "CreateBeforeSerializationDependencies",
        "SerializationBeforeCreateDependencies",
        "CreateBeforeCreateDependencies",
        "SerializationBeforeSerializationDependencies",
    ] {
        if let Some(dependencies) = export.get_mut(key).and_then(Value::as_array_mut) {
            let before = dependencies.len();
            dependencies.retain(|value| value.as_i64() != Some(i64::from(reference)));
            removed_dependency_count += before - dependencies.len();
        }
    }
    if removed_dependency_count == 0 {
        bail!("optional Blueprint serialized role has no matching dependency edge");
    }
    {
        let imports = document
            .get_mut("Imports")
            .and_then(Value::as_array_mut)
            .context("Blueprint consumer Imports is not mutable")?;
        imports[package_index]["ObjectName"] = Value::String(replacement_path.clone());
        imports[object_index]["ObjectName"] = Value::String(replacement_object_name.to_owned());
        imports[object_index]["ClassPackage"] = Value::String("/Script/Engine".to_owned());
        imports[object_index]["ClassName"] = Value::String("StaticMesh".to_owned());
    }
    let replacement_target = ImportTarget {
        package_id: replacement_package.package_id,
        package_path: replacement_path.clone(),
        object_name: replacement_object_name.to_owned(),
        class_name: "StaticMesh".to_owned(),
    };
    add_import_names(&mut document, std::slice::from_ref(&replacement_target))?;
    let intended_exports = validated_export_data(&document)?;
    fs::write(&patched_json, serde_json::to_vec(&document)?)?;
    tool.import_json(&patched_json, &rebuilt_asset)?;
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    let expected_unresolved_pairs = original_unresolved_pairs
        .into_iter()
        .filter(|pair| *pair != (package_index, object_index))
        .collect::<Vec<_>>();
    if validated_export_data(&verified)? != intended_exports
        || unresolved_import_pairs(&verified)? != expected_unresolved_pairs
    {
        bail!("optional Blueprint suppression did not survive UAsset rebuild");
    }
    if verified
        .get("Imports")
        .and_then(Value::as_array)
        .is_some_and(|imports| {
            imports.iter().any(|import| {
                import
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case(&target_path))
            })
        })
    {
        bail!("optional Blueprint suppression retained the absent package identity");
    }
    let verified_resolved_package_ids = verified
        .get("Imports")
        .and_then(Value::as_array)
        .context("rebuilt Blueprint consumer has no Imports")?
        .iter()
        .filter(|import| import.get("ClassName").and_then(Value::as_str) == Some("Package"))
        .filter_map(|import| import.get("ObjectName").and_then(Value::as_str))
        .filter(|name| {
            name.get(..6)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/Game/"))
        })
        .map(unreal_package_id)
        .collect::<Result<BTreeSet<_>>>()?;
    let mut intended_resolved_package_ids = original_resolved_package_ids;
    intended_resolved_package_ids.remove(&target_package.package_id);
    intended_resolved_package_ids.insert(replacement_package.package_id);
    if verified_resolved_package_ids != intended_resolved_package_ids {
        bail!("optional Blueprint suppression changed unrelated resolved package imports");
    }
    let mut target_imported_package_ids = source_store
        .imported_package_ids
        .iter()
        .copied()
        .filter(|package_id| *package_id != target_package.package_id)
        .collect::<BTreeSet<_>>();
    target_imported_package_ids.insert(replacement_package.package_id);
    for extension in ["uasset", "uexp", "ubulk", "uptnl"] {
        let rebuilt = rebuilt_asset.with_extension(extension);
        let destination = consumer_asset.with_extension(extension);
        if rebuilt.is_file() {
            fs::copy(rebuilt, destination)?;
        } else if destination.is_file() {
            bail!("optional Blueprint suppression dropped an authored sidecar");
        }
    }
    Ok(OptionalBlueprintDependencySuppression {
        asset: consumer_asset.to_string_lossy().replace('\\', "/"),
        target_package_id: target_package.package_id,
        target_package_path: target_path,
        target_class: "StaticMesh".to_owned(),
        role: evidence.role.clone(),
        export_name: evidence.export_name.clone(),
        serialized_reference_offset: offset,
        removed_dependency_count,
        replacement_package_id: replacement_package.package_id,
        replacement_package_path: replacement_path,
        target_imported_package_ids: target_imported_package_ids.into_iter().collect(),
        policy: "optional-secondary-blueprint-component-suppression-v1".to_owned(),
    })
}

pub fn classify_composite_package_asset(
    asset: &Path,
    allow_current_template: bool,
    work: &Path,
) -> Result<(CompositePackageAssetKind, usize)> {
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let json_path = work.join("classify.json");
    tool.to_json(asset, &json_path)?;
    let document: Value = serde_json::from_slice(&fs::read(&json_path)?)?;
    let exports = document
        .get("Exports")
        .and_then(Value::as_array)
        .context("composite package has no Exports")?;
    validated_export_data(&document)?;
    let classes = exports
        .iter()
        .filter(|export| {
            export
                .get("ClassIndex")
                .and_then(Value::as_i64)
                .is_some_and(|index| index < 0)
        })
        .map(|export| export_class_name(&document, export))
        .collect::<Result<HashSet<_>>>()?;
    let main = [
        ("SkeletalMesh", CompositePackageAssetKind::SkeletalMesh),
        ("StaticMesh", CompositePackageAssetKind::StaticMesh),
        ("Texture2D", CompositePackageAssetKind::Texture2D),
        (
            "MaterialInstanceConstant",
            CompositePackageAssetKind::MaterialInstanceConstant,
        ),
        ("AnimSequence", CompositePackageAssetKind::AnimSequence),
        ("AnimMontage", CompositePackageAssetKind::AnimMontage),
        ("BlendSpace", CompositePackageAssetKind::BlendSpace),
        ("BlendSpace1D", CompositePackageAssetKind::BlendSpace),
        ("SoundWave", CompositePackageAssetKind::SoundWave),
        ("SoundCue", CompositePackageAssetKind::SoundCue),
    ]
    .into_iter()
    .filter(|(class, _)| {
        classes
            .iter()
            .any(|value| value.eq_ignore_ascii_case(class))
    })
    .map(|(_, kind)| kind)
    .collect::<Vec<_>>();
    let unresolved = unresolved_import_pairs(&document)?.len();
    if main.len() == 1 {
        return Ok((main[0], unresolved));
    }
    if main.len() > 1 {
        bail!("composite package contains multiple primary supported asset classes");
    }
    let root_classes = exports
        .iter()
        .filter(|export| export.get("OuterIndex").and_then(Value::as_i64) == Some(0))
        .filter(|export| {
            export
                .get("ClassIndex")
                .and_then(Value::as_i64)
                .is_some_and(|index| index < 0)
        })
        .map(|export| export_class_name(&document, export))
        .collect::<Result<Vec<_>>>()?;
    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("composite package has no Imports")?;
    let altar_tes_root = exports
        .iter()
        .filter(|export| export.get("OuterIndex").and_then(Value::as_i64) == Some(0))
        .filter_map(|export| export.get("ClassIndex").and_then(Value::as_i64))
        .filter(|index| *index < 0)
        .filter_map(|index| imports.get(usize::try_from(-index - 1).ok()?))
        .filter(|class| {
            class
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|name| {
                    name.get(..3)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("TES"))
                })
        })
        .filter(|class| {
            class
                .get("OuterIndex")
                .and_then(Value::as_i64)
                .filter(|outer| *outer < 0)
                .and_then(|outer| imports.get(usize::try_from(-outer - 1).ok()?))
                .and_then(|package| package.get("ObjectName"))
                .and_then(Value::as_str)
                .is_some_and(|package| package.eq_ignore_ascii_case("/Script/Altar"))
        })
        .count()
        == 1;
    let blueprint_generated_root = root_classes.len() == 1
        && root_classes[0]
            .to_ascii_lowercase()
            .ends_with("blueprintgeneratedclass");
    if root_classes.len() == 1 && (blueprint_generated_root || (unresolved == 0 && altar_tes_root))
    {
        return Ok((
            CompositePackageAssetKind::ResolvedAuthoredPackage,
            unresolved,
        ));
    }
    if allow_current_template {
        return Ok((
            CompositePackageAssetKind::CurrentTemplatePackage,
            unresolved,
        ));
    }
    bail!(
        "additive composite package has no independently supported primary export class; current-template repair is available only to existing package identities"
    )
}

fn resolved_import_semantics(document: &Value) -> Result<BTreeSet<String>> {
    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("UAsset JSON has no Imports")?;
    imports
        .iter()
        .filter(|import| import.get("ClassName").and_then(Value::as_str) != Some("Package"))
        .filter(|import| import.get("ObjectName").and_then(Value::as_str) != Some("UnknownExport"))
        .map(|import| {
            let outer = import
                .get("OuterIndex")
                .and_then(Value::as_i64)
                .context("resolved import has no OuterIndex")?;
            if outer >= 0 {
                bail!("resolved object import does not reference a package import");
            }
            let package = imports
                .get(usize::try_from(-outer - 1)?)
                .context("resolved import package index is out of bounds")?;
            let package_name = package
                .get("ObjectName")
                .and_then(Value::as_str)
                .context("resolved import package has no ObjectName")?;
            if package_name.eq_ignore_ascii_case("/Engine/UnknownPackage") {
                bail!("resolved object import unexpectedly references an unknown package");
            }
            Ok(format!(
                "{}|{}|{}|{}",
                import
                    .get("ClassPackage")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                import
                    .get("ClassName")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                import
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                package_name.to_ascii_lowercase()
            ))
        })
        .collect()
}

fn export_topology(document: &Value) -> Result<Vec<Value>> {
    document
        .get("Exports")
        .and_then(Value::as_array)
        .context("UAsset JSON has no Exports")?
        .iter()
        .map(|export| {
            Ok(serde_json::json!({
                "type": export.get("$type").and_then(Value::as_str),
                "objectName": export.get("ObjectName").and_then(Value::as_str),
                "classIndex": export.get("ClassIndex").and_then(Value::as_i64),
                "superIndex": export.get("SuperIndex").and_then(Value::as_i64),
                "templateIndex": export.get("TemplateIndex").and_then(Value::as_i64),
                "outerIndex": export.get("OuterIndex").and_then(Value::as_i64),
            }))
        })
        .collect()
}

fn merge_name_map_from_donor(document: &mut Value, donor: &Value) -> Result<()> {
    let donor_names = donor
        .get("NameMap")
        .and_then(Value::as_array)
        .context("current template has no NameMap")?;
    let names = document
        .get_mut("NameMap")
        .and_then(Value::as_array_mut)
        .context("source package has no NameMap")?;
    for name in donor_names {
        if !names.iter().any(|value| value == name) {
            names.push(name.clone());
        }
    }
    Ok(())
}

pub fn repair_current_template_imports(
    asset: &Path,
    donor_asset: &Path,
    source_store: &PackageStoreEntry,
    available_dependencies: &HashMap<u64, PackageEntry>,
    work: &Path,
) -> Result<CompositePackageImportRepair> {
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work.join("source.json");
    let donor_json = work.join("donor.json");
    let patched_json = work.join("patched.json");
    let verify_json = work.join("verify.json");
    let rebuilt_asset = work.join(
        asset
            .file_name()
            .context("source package has no filename")?,
    );
    tool.to_json(asset, &source_json)?;
    tool.to_json(donor_asset, &donor_json)?;
    let mut document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let donor: Value = serde_json::from_slice(&fs::read(&donor_json)?)?;
    let original_exports = validated_export_data(&document)?;
    validated_export_data(&donor)?;
    let source_folder = document.get("FolderName").and_then(Value::as_str);
    let donor_folder = donor.get("FolderName").and_then(Value::as_str);
    if !matches!((source_folder, donor_folder), (Some(source), Some(current)) if source.eq_ignore_ascii_case(current))
    {
        bail!("source and current-template package paths do not match");
    }
    for field in ["IsUnversioned", "IsCooked", "FilterEditorOnly"] {
        if document.get(field) != donor.get(field) {
            bail!("source and current template disagree on {field}");
        }
    }
    if export_topology(&document)? != export_topology(&donor)? {
        bail!("source and current template export topology does not match");
    }
    let source_imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("source package has no Imports")?;
    let donor_imports = donor
        .get("Imports")
        .and_then(Value::as_array)
        .context("current template has no Imports")?;
    if source_imports.len() != donor_imports.len() {
        bail!("source and current template import table lengths do not match");
    }
    let pairs = unresolved_import_pairs(&document)?;
    if !unresolved_import_pairs(&donor)?.is_empty() {
        bail!("current template contains unresolved imports");
    }
    let source_semantics = resolved_import_semantics(&document)?;
    let donor_semantics = resolved_import_semantics(&donor)?;
    if !source_semantics.is_subset(&donor_semantics) {
        bail!("source contains authored resolved imports absent from the current template");
    }
    let donor_only = donor_semantics.difference(&source_semantics).count();
    if donor_only != pairs.len() {
        bail!(
            "current template contributes {donor_only} semantic imports but the source exposes {} unresolved imports",
            pairs.len()
        );
    }
    if pairs.is_empty() && source_imports != donor_imports {
        bail!("current-template import tables differ without unresolved source evidence");
    }
    if !pairs.is_empty() {
        document["Imports"] = donor["Imports"].clone();
        merge_name_map_from_donor(&mut document, &donor)?;
    }
    let intended_exports = validated_export_data(&document)?;
    let exports_byte_identical = original_exports == intended_exports;
    if !exports_byte_identical {
        bail!("current-template import repair changed authored export data");
    }
    fs::write(&patched_json, serde_json::to_vec(&document)?)?;
    tool.import_json(&patched_json, &rebuilt_asset)?;
    let source_uexp = asset.with_extension("uexp");
    let rebuilt_uexp = rebuilt_asset.with_extension("uexp");
    if source_uexp.is_file() != rebuilt_uexp.is_file() {
        bail!("current-template repair changed UEXP presence");
    }
    let uexp_byte_identical =
        !source_uexp.is_file() || sha256_file(&source_uexp)? == sha256_file(&rebuilt_uexp)?;
    if !uexp_byte_identical {
        bail!("current-template import repair changed authored UEXP bytes");
    }
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    if validated_export_data(&verified)? != intended_exports
        || !unresolved_import_pairs(&verified)?.is_empty()
    {
        bail!("current-template import repair did not survive UAsset rebuild");
    }
    fs::copy(&rebuilt_asset, asset)?;
    if rebuilt_uexp.is_file() {
        fs::copy(&rebuilt_uexp, &source_uexp)?;
    }
    let (missing, target_imported_package_ids) =
        replacement_dependency_sets(source_store, available_dependencies, &[]);
    if !missing.is_empty() {
        bail!("current-template repair retained unresolved package IDs");
    }
    Ok(CompositePackageImportRepair {
        asset: asset.to_string_lossy().replace('\\', "/"),
        package_id: source_store.package_id,
        asset_kind: "current-template-package".to_owned(),
        repaired_import_count: pairs.len(),
        repaired_targets: donor_semantics
            .difference(&source_semantics)
            .cloned()
            .collect(),
        retired_physics_asset: false,
        stale_create_dependencies_removed: 0,
        source_imported_package_ids: source_store.imported_package_ids.clone(),
        missing_source_imported_package_ids: missing,
        target_imported_package_ids,
        exports_byte_identical,
        uexp_byte_identical,
        policy: "identity-and-export-topology-current-template-import-rebase-v1".to_owned(),
    })
}

pub fn repair_single_external_import(
    asset: &Path,
    dependency_asset: &Path,
    dependency: &PackageEntry,
    source_store: &PackageStoreEntry,
    available_dependencies: &HashMap<u64, PackageEntry>,
    work: &Path,
) -> Result<CompositePackageImportRepair> {
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work.join("source.json");
    let dependency_json = work.join("dependency.json");
    let patched_json = work.join("patched.json");
    let verify_json = work.join("verify.json");
    let rebuilt_asset = work.join(
        asset
            .file_name()
            .context("source package has no filename")?,
    );
    tool.to_json(asset, &source_json)?;
    tool.to_json(dependency_asset, &dependency_json)?;
    let mut document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let dependency_document: Value = serde_json::from_slice(&fs::read(&dependency_json)?)?;
    let original_exports = validated_export_data(&document)?;
    let pairs = unresolved_import_pairs(&document)?;
    let package_indices = pairs
        .iter()
        .map(|(package_index, _)| *package_index)
        .collect::<BTreeSet<_>>();
    if package_indices.is_empty() || pairs.is_empty() {
        bail!("single external package repair requires unresolved package imports");
    }
    let dependency_exports = dependency_document
        .get("Exports")
        .and_then(Value::as_array)
        .context("current dependency has no Exports")?;
    let dependency_package_name = game_package_path(&dependency.path)?;
    let expected_object_name = package_name_leaf(&dependency_package_name)?;
    let public_roots = dependency_exports
        .iter()
        .filter(|export| export.get("OuterIndex").and_then(Value::as_i64) == Some(0))
        .filter(|export| {
            export
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(expected_object_name))
        })
        .collect::<Vec<_>>();
    if public_roots.len() != 1 {
        bail!(
            "single external import target must expose one package-named top-level public export; found {}",
            public_roots.len()
        );
    }
    let object_name = public_roots[0]
        .get("ObjectName")
        .and_then(Value::as_str)
        .context("current dependency export has no ObjectName")?;
    let class_name = export_class_name(&dependency_document, public_roots[0])?;
    let target = ImportTarget {
        package_id: dependency.package_id,
        package_path: dependency_package_name,
        object_name: object_name.to_owned(),
        class_name,
    };
    {
        let imports = document
            .get_mut("Imports")
            .and_then(Value::as_array_mut)
            .context("source package Imports is not an array")?;
        for package_index in &package_indices {
            imports[*package_index]["ObjectName"] = Value::String(target.package_path.clone());
        }
        for (_, object_index) in &pairs {
            imports[*object_index]["ObjectName"] = Value::String(target.object_name.clone());
            imports[*object_index]["ClassPackage"] = Value::String("/Script/Engine".to_owned());
            imports[*object_index]["ClassName"] = Value::String(target.class_name.clone());
        }
    }
    add_import_names(&mut document, std::slice::from_ref(&target))?;
    let intended_exports = validated_export_data(&document)?;
    let exports_byte_identical = original_exports == intended_exports;
    if !exports_byte_identical {
        bail!("single external import repair changed authored export data");
    }
    fs::write(&patched_json, serde_json::to_vec(&document)?)?;
    tool.import_json(&patched_json, &rebuilt_asset)?;
    let source_uexp = asset.with_extension("uexp");
    let rebuilt_uexp = rebuilt_asset.with_extension("uexp");
    if source_uexp.is_file() != rebuilt_uexp.is_file() {
        bail!("single external import repair changed UEXP presence");
    }
    let uexp_byte_identical =
        !source_uexp.is_file() || sha256_file(&source_uexp)? == sha256_file(&rebuilt_uexp)?;
    if !uexp_byte_identical {
        bail!("single external import repair changed authored UEXP bytes");
    }
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    if validated_export_data(&verified)? != intended_exports
        || !unresolved_import_pairs(&verified)?.is_empty()
    {
        bail!("single external import repair did not survive UAsset rebuild");
    }
    fs::copy(&rebuilt_asset, asset)?;
    if rebuilt_uexp.is_file() {
        fs::copy(&rebuilt_uexp, &source_uexp)?;
    }
    let (missing, target_imported_package_ids) = replacement_dependency_sets(
        source_store,
        available_dependencies,
        std::slice::from_ref(&target),
    );
    Ok(CompositePackageImportRepair {
        asset: asset.to_string_lossy().replace('\\', "/"),
        package_id: source_store.package_id,
        asset_kind: "single-external-import".to_owned(),
        repaired_import_count: pairs.len(),
        repaired_targets: vec![target.package_path],
        retired_physics_asset: false,
        stale_create_dependencies_removed: 0,
        source_imported_package_ids: source_store.imported_package_ids.clone(),
        missing_source_imported_package_ids: missing,
        target_imported_package_ids,
        exports_byte_identical,
        uexp_byte_identical,
        policy: "single-resolved-dependency-public-export-rebase-v2".to_owned(),
    })
}

pub fn derive_skeletal_compatibility_profile(
    source: &str,
    body_asset_path: &str,
    body_asset: &Path,
    donor_asset: &Path,
    target_dependencies: &HashMap<u64, PackageEntry>,
    work: &Path,
) -> Result<SkeletalCompatibilityProfile> {
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work.join("body-source.json");
    let donor_json = work.join("body-donor.json");
    tool.to_json(body_asset, &source_json)?;
    tool.to_json(donor_asset, &donor_json)?;
    let document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let donor: Value = serde_json::from_slice(&fs::read(&donor_json)?)?;

    let (source_skeleton_package, source_skeleton_object) = resolved_import(&document, "Skeleton")?;
    let (donor_skeleton_package, donor_skeleton_object) = resolved_import(&donor, "Skeleton")?;
    if source_skeleton_package.eq_ignore_ascii_case(&donor_skeleton_package)
        && source_skeleton_object.eq_ignore_ascii_case(&donor_skeleton_object)
    {
        bail!(
            "attached body mesh uses the stock donor skeleton and does not prove a custom armor compatibility profile"
        );
    }
    let skeleton = target_for_path(
        &source_skeleton_package,
        &source_skeleton_object,
        "Skeleton",
        target_dependencies,
    )?;

    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("body compatibility UAsset JSON has no Imports")?;
    let pairs = imports
        .iter()
        .enumerate()
        .filter(|(_, import)| {
            import.get("ClassName").and_then(Value::as_str) == Some("Package")
                && import
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case("/Engine/UnknownPackage"))
        })
        .flat_map(|(package_index, _)| {
            let expected_outer = -(package_index as i64) - 1;
            imports
                .iter()
                .enumerate()
                .filter(move |(_, import)| {
                    import.get("OuterIndex").and_then(Value::as_i64) == Some(expected_outer)
                        && import.get("ObjectName").and_then(Value::as_str) == Some("UnknownExport")
                })
                .map(move |(object_index, _)| (package_index, object_index))
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        bail!("attached body mesh has no unresolved material imports to profile");
    }
    let (_, candidates) = current_material_candidates(&donor, target_dependencies)?;
    let aliases = BTreeSet::new();
    let material_array = serialized_material_slots(&document, &pairs, &candidates, &aliases)?;
    let material_targets =
        select_material_slot_targets(&material_array.slots, &candidates, &HashMap::new())?;
    let unique_materials = material_targets
        .iter()
        .map(|target| target.package_id)
        .collect::<BTreeSet<_>>();
    if unique_materials.len() != 1 {
        bail!(
            "attached body mesh must resolve every active body slot to one current body material; found {}",
            unique_materials.len()
        );
    }
    let material = material_targets
        .first()
        .context("attached body mesh has no active material target")?;

    Ok(SkeletalCompatibilityProfile {
        id: "attached-female-body-profile-v1".to_owned(),
        source: source.to_owned(),
        body_asset: body_asset_path.to_owned(),
        skeleton_package_id: skeleton.package_id,
        skeleton_package_path: skeleton.package_path,
        skeleton_object_name: skeleton.object_name,
        material_package_id: material.package_id,
        material_package_path: material.package_path.clone(),
        material_object_name: material.object_name.clone(),
        material_aliases: vec!["material".to_owned()],
        policy: "explicit-attached-body-custom-skeleton-and-current-body-material-v1".to_owned(),
    })
}

pub fn repair_skeletal_mesh_imports(
    asset: &Path,
    donor_asset: &Path,
    source_store: &PackageStoreEntry,
    target_store_imports: &[u64],
    target_dependencies: &HashMap<u64, PackageEntry>,
    compatibility_profile: Option<&SkeletalCompatibilityProfile>,
    work: &Path,
) -> Result<MaterialImportRepair> {
    fs::create_dir_all(work)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work.join("source.json");
    let donor_json = work.join("donor.json");
    let patched_json = work.join("patched.json");
    let verify_json = work.join("verify.json");
    let rebuilt_asset = work.join(
        asset
            .file_name()
            .context("replacement UAsset path has no filename")?,
    );
    tool.to_json(asset, &source_json)?;
    tool.to_json(donor_asset, &donor_json)?;
    let mut document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let donor: Value = serde_json::from_slice(&fs::read(&donor_json)?)?;
    let original_exports = export_data(&document)?;

    let skeleton = if let Some(profile) = compatibility_profile {
        profile.skeleton_target()
    } else {
        let (skeleton_package, skeleton_object) = resolved_import(&donor, "Skeleton")?;
        target_for_path(
            &skeleton_package,
            &skeleton_object,
            "Skeleton",
            target_dependencies,
        )?
    };

    let imports = document
        .get("Imports")
        .and_then(Value::as_array)
        .context("source UAsset JSON has no Imports")?;
    let package_indices = imports
        .iter()
        .enumerate()
        .filter(|(_, import)| {
            import.get("ClassName").and_then(Value::as_str) == Some("Package")
                && import
                    .get("ObjectName")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case("/Engine/UnknownPackage"))
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if package_indices.len() < 2 {
        bail!(
            "{} has only {} unresolved package imports; a skeletal replacement requires at least material and skeleton packages",
            asset.display(),
            package_indices.len()
        );
    }
    for package_index in &package_indices {
        let expected_outer = -(*package_index as i64) - 1;
        let child_count = imports
            .iter()
            .filter(|import| {
                import.get("OuterIndex").and_then(Value::as_i64) == Some(expected_outer)
            })
            .count();
        let unresolved_child_count = imports
            .iter()
            .filter(|import| {
                import.get("OuterIndex").and_then(Value::as_i64) == Some(expected_outer)
                    && import.get("ObjectName").and_then(Value::as_str) == Some("UnknownExport")
            })
            .count();
        if child_count != unresolved_child_count {
            bail!(
                "{} unresolved package import {} has {} child imports but only {} are unresolved object imports",
                asset.display(),
                package_index,
                child_count,
                unresolved_child_count
            );
        }
    }
    let pairs = package_indices
        .iter()
        .flat_map(|package_index| {
            let expected_outer = -(*package_index as i64) - 1;
            let objects = imports
                .iter()
                .enumerate()
                .filter(|(_, import)| {
                    import.get("OuterIndex").and_then(Value::as_i64) == Some(expected_outer)
                        && import.get("ObjectName").and_then(Value::as_str) == Some("UnknownExport")
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            objects
                .into_iter()
                .map(|object| Ok((*package_index, object)))
                .collect::<Vec<_>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let orphan_object_import_count = pairs
        .len()
        .saturating_sub(source_store.imported_package_ids.len());
    if pairs.len() < source_store.imported_package_ids.len() || orphan_object_import_count > 1 {
        bail!(
            "{} has {} unresolved object imports but its store declares {} imported packages; only one structurally proven retired-PhysicsAsset object tombstone may be inactive",
            asset.display(),
            pairs.len(),
            source_store.imported_package_ids.len()
        );
    }

    let mut candidate_material_dependency_ids = source_store.imported_package_ids.clone();
    candidate_material_dependency_ids.extend_from_slice(target_store_imports);
    candidate_material_dependency_ids.sort_unstable();
    candidate_material_dependency_ids.dedup();
    let (active_donor_materials, mut material_candidates) =
        current_material_candidates(&donor, target_dependencies)?;
    let alias_targets = compatibility_profile
        .map(SkeletalCompatibilityProfile::alias_targets)
        .unwrap_or_default();
    if let Some(profile) = compatibility_profile {
        material_candidates.push(profile.material_target());
        material_candidates.sort_by_key(|target| target.package_id);
        material_candidates.dedup_by_key(|target| target.package_id);
    }
    let alias_names = alias_targets.keys().cloned().collect::<BTreeSet<_>>();
    let material_array =
        serialized_material_slots(&document, &pairs, &material_candidates, &alias_names)?;
    let material_targets =
        select_material_slot_targets(&material_array.slots, &material_candidates, &alias_targets)?;
    let material_objects = material_array
        .slots
        .iter()
        .map(|slot| slot.object_import_index)
        .collect::<BTreeSet<_>>();
    let skeleton_object_index =
        serialized_skeleton_import_index(&document, &pairs, &material_objects)?;
    if material_objects.contains(&skeleton_object_index) {
        bail!("serialized skeleton reference overlaps a material object import");
    }
    let auxiliary_objects = pairs
        .iter()
        .map(|(_, object)| *object)
        .filter(|object| *object != skeleton_object_index && !material_objects.contains(object))
        .collect::<Vec<_>>();
    let donor_physics = resolved_imports(&donor, "PhysicsAsset")?;
    if donor_physics.len() > 1 {
        bail!(
            "current stock donor has {} PhysicsAsset imports; exactly zero or one is required",
            donor_physics.len()
        );
    }
    let active_physics_asset = if let Some((package, object)) = donor_physics.first() {
        if auxiliary_objects.len() != 1 {
            bail!(
                "current donor has a PhysicsAsset but the source exposes {} unresolved auxiliary imports",
                auxiliary_objects.len()
            );
        }
        let structured = structured_object_property_index(&document, "PhysicsAsset")?;
        if structured != Some(auxiliary_objects[0]) {
            bail!(
                "donor-backed PhysicsAsset migration is allowed only when a typed source PhysicsAsset property proves the auxiliary import role"
            );
        }
        Some((
            auxiliary_objects[0],
            target_for_path(package, object, "PhysicsAsset", target_dependencies)?,
        ))
    } else {
        None
    };
    let retired_physics_assets = if active_physics_asset.is_none() {
        retire_obsolete_physics_asset(
            &mut document,
            &donor,
            &pairs,
            &material_array,
            &material_objects,
            skeleton_object_index,
            orphan_object_import_count,
        )?
    } else {
        Vec::new()
    };
    let newly_retired_physics_assets = retired_physics_assets
        .iter()
        .filter(|evidence| !evidence.already_retired)
        .collect::<Vec<_>>();
    let already_retired_physics_assets = retired_physics_assets
        .iter()
        .filter(|evidence| evidence.already_retired)
        .collect::<Vec<_>>();
    let retired_physics_objects = retired_physics_assets
        .iter()
        .map(|evidence| evidence.object_import_index)
        .collect::<BTreeSet<_>>();

    let mut material_target_by_object = HashMap::<usize, ImportTarget>::new();
    for (slot, target) in material_array.slots.iter().zip(&material_targets) {
        if let Some(existing) = material_target_by_object.get(&slot.object_import_index)
            && existing.package_id != target.package_id
        {
            bail!(
                "one unresolved object import is used by incompatible material slots {} and {}",
                existing.object_name,
                slot.slot_name
            );
        }
        material_target_by_object.insert(slot.object_import_index, target.clone());
    }
    let mut live_targets_by_package = HashMap::<usize, Vec<ImportTarget>>::new();
    for (package_index, object_index) in &pairs {
        let live_target = if *object_index == skeleton_object_index {
            Some(skeleton.clone())
        } else {
            material_target_by_object.get(object_index).cloned()
        };
        let Some(live_target) = live_target else {
            continue;
        };
        let targets = live_targets_by_package.entry(*package_index).or_default();
        if !targets.iter().any(|existing| {
            existing
                .package_path
                .eq_ignore_ascii_case(&live_target.package_path)
        }) {
            targets.push(live_target);
        }
    }
    for targets in live_targets_by_package.values_mut() {
        targets.sort_by_key(|target| target.package_path.to_ascii_lowercase());
    }
    let mut patches = pairs
        .iter()
        .map(|pair| -> Result<_> {
        let target = if pair.1 == skeleton_object_index {
            skeleton.clone()
        } else if let Some(material) = material_target_by_object.get(&pair.1) {
            material.clone()
        } else if active_physics_asset
            .as_ref()
            .is_some_and(|(object, _)| *object == pair.1)
        {
            active_physics_asset.as_ref().unwrap().1.clone()
        } else if retired_physics_objects.contains(&pair.1) {
                live_targets_by_package
                    .get(&pair.0)
                    .and_then(|targets| targets.first().cloned())
                    .unwrap_or_else(|| skeleton.clone())
            } else {
                bail!(
                    "unresolved auxiliary import {} has no proven material, skeleton, or retired PhysicsAsset role",
                    pair.1
                );
            };
            Ok((*pair, target))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut patch_groups = BTreeMap::<usize, BTreeMap<String, Vec<usize>>>::new();
    for (patch_index, ((package_index, _), target)) in patches.iter().enumerate() {
        patch_groups
            .entry(*package_index)
            .or_default()
            .entry(target.package_path.to_ascii_lowercase())
            .or_default()
            .push(patch_index);
    }
    let imports = document
        .get_mut("Imports")
        .and_then(Value::as_array_mut)
        .context("source UAsset JSON Imports is not an array")?;
    let mut split_package_import_count = 0_usize;
    for (package_index, target_groups) in patch_groups {
        for patch_indices in target_groups.values().skip(1) {
            let cloned_package = imports
                .get(package_index)
                .context("unresolved package import index is outside Imports")?
                .clone();
            let new_package_index = imports.len();
            imports.push(cloned_package);
            split_package_import_count += 1;
            for patch_index in patch_indices {
                let object_index = patches[*patch_index].0.1;
                patches[*patch_index].0.0 = new_package_index;
                imports[object_index]["OuterIndex"] =
                    Value::Number((-i64::try_from(new_package_index)? - 1).into());
            }
        }
    }
    let auxiliary_import_targets = patches
        .iter()
        .filter(|((_, object), _)| {
            *object != skeleton_object_index
                && !material_objects.contains(object)
                && !retired_physics_objects.contains(object)
        })
        .map(|(_, target)| target.package_path.clone())
        .collect::<Vec<_>>();
    let ignored_inactive_materials = ignored_material_dependencies(
        &candidate_material_dependency_ids,
        &material_targets,
        target_dependencies,
    );

    for ((package_index, object_index), target) in &patches {
        imports[*package_index]["ObjectName"] = Value::String(target.package_path.clone());
        imports[*object_index]["ObjectName"] = Value::String(target.object_name.clone());
        imports[*object_index]["ClassPackage"] = Value::String("/Script/Engine".to_owned());
        imports[*object_index]["ClassName"] = Value::String(target.class_name.clone());
    }
    let names = document
        .get_mut("NameMap")
        .and_then(Value::as_array_mut)
        .context("source UAsset JSON has no NameMap")?;
    for name in patches.iter().flat_map(|(_, target)| {
        [
            target.package_path.as_str(),
            target.object_name.as_str(),
            target.class_name.as_str(),
        ]
    }) {
        if !names.iter().any(|value| value.as_str() == Some(name)) {
            names.push(Value::String(name.to_owned()));
        }
    }

    let intended_exports = export_data(&document)?;
    let exports_byte_identical = original_exports == intended_exports;

    fs::write(&patched_json, serde_json::to_vec(&document)?)?;
    tool.import_json(&patched_json, &rebuilt_asset)?;
    let rebuilt_uexp = rebuilt_asset.with_extension("uexp");
    let source_uexp = asset.with_extension("uexp");
    if source_uexp.is_file() != rebuilt_uexp.is_file() {
        bail!(
            "material import repair changed UEXP presence for {}",
            asset.display()
        );
    }
    let uexp_byte_identical =
        !source_uexp.is_file() || sha256_file(&source_uexp)? == sha256_file(&rebuilt_uexp)?;
    if newly_retired_physics_assets.is_empty() && !uexp_byte_identical {
        bail!(
            "reference-only repair changed raw UEXP payload bytes for {}",
            asset.display()
        );
    }
    if !newly_retired_physics_assets.is_empty() && uexp_byte_identical {
        bail!(
            "retired PhysicsAsset repair did not change the expected raw UEXP bytes for {}",
            asset.display()
        );
    }
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    if intended_exports != export_data(&verified)? {
        bail!(
            "UAsset roundtrip did not preserve the approved raw export migration in {}",
            asset.display()
        );
    }
    let verified_imports = verified
        .get("Imports")
        .and_then(Value::as_array)
        .context("verified UAsset JSON has no Imports")?;
    for ((package_index, object_index), target) in &patches {
        if verified_imports[*package_index]["ObjectName"].as_str()
            != Some(target.package_path.as_str())
            || verified_imports[*object_index]["ObjectName"].as_str()
                != Some(target.object_name.as_str())
            || verified_imports[*object_index]["ClassName"].as_str()
                != Some(target.class_name.as_str())
        {
            bail!(
                "material import repair did not survive UAsset rebuild for {}",
                asset.display()
            );
        }
    }
    let verified_skeletal_export = verified
        .get("Exports")
        .and_then(Value::as_array)
        .context("verified UAsset JSON has no Exports")?
        .iter()
        .find(|export| {
            export
                .get("ObjectName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.to_ascii_lowercase().starts_with("sk_"))
        })
        .context("verified UAsset JSON has no skeletal mesh export")?;
    let verified_create_dependencies = verified_skeletal_export
        .get("CreateBeforeSerializationDependencies")
        .and_then(Value::as_array)
        .context("verified skeletal mesh export has no create dependencies")?;
    for evidence in &retired_physics_assets {
        let stale = -i64::try_from(evidence.object_import_index)? - 1;
        if verified_create_dependencies
            .iter()
            .any(|value| value.as_i64() == Some(stale))
        {
            bail!(
                "retired PhysicsAsset create dependency survived UAsset rebuild for {}",
                asset.display()
            );
        }
    }

    fs::copy(&rebuilt_asset, asset)?;
    if rebuilt_uexp.is_file() {
        fs::copy(&rebuilt_uexp, &source_uexp)?;
    }
    let mut target_imported_package_ids = patches
        .iter()
        .map(|(_, target)| target.package_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    target_imported_package_ids.sort_unstable();
    let missing_source_imported_package_ids = source_store
        .imported_package_ids
        .iter()
        .filter(|package_id| !target_dependencies.contains_key(package_id))
        .copied()
        .collect();
    Ok(MaterialImportRepair {
        asset: asset.to_string_lossy().replace('\\', "/"),
        package_id: source_store.package_id,
        material_import_count: material_targets.len(),
        material_slot_names: material_array
            .slots
            .iter()
            .map(|slot| slot.slot_name.clone())
            .collect(),
        material_object_import_indices: material_array
            .slots
            .iter()
            .map(|slot| slot.object_import_index)
            .collect(),
        material_targets: material_targets
            .iter()
            .map(|target| target.package_path.clone())
            .collect(),
        active_donor_material_imports: active_donor_materials
            .iter()
            .map(|target| target.package_path.clone())
            .collect(),
        ignored_inactive_material_dependencies: ignored_inactive_materials,
        auxiliary_import_count: auxiliary_import_targets.len(),
        auxiliary_import_targets,
        retired_physics_asset_import_count: newly_retired_physics_assets.len(),
        retired_physics_asset_object_import_indices: newly_retired_physics_assets
            .iter()
            .map(|evidence| evidence.object_import_index)
            .collect(),
        retired_physics_asset_reference_offsets: newly_retired_physics_assets
            .iter()
            .filter_map(|evidence| evidence.reference_offset)
            .collect(),
        stale_create_dependencies_removed: newly_retired_physics_assets
            .iter()
            .map(|evidence| evidence.removed_dependency_count)
            .sum(),
        already_retired_physics_asset_import_count: already_retired_physics_assets.len(),
        already_retired_physics_asset_object_import_indices: already_retired_physics_assets
            .iter()
            .map(|evidence| evidence.object_import_index)
            .collect(),
        already_retired_physics_asset_has_no_serialized_property_reference:
            already_retired_physics_assets
                .iter()
                .all(|evidence| evidence.reference_offset.is_none()),
        split_package_import_count,
        skeleton_target: skeleton.package_path,
        source_imported_package_ids: source_store.imported_package_ids.clone(),
        missing_source_imported_package_ids,
        target_imported_package_ids,
        compatibility_profile_id: compatibility_profile.map(|profile| profile.id.clone()),
        compatibility_skeleton_target: compatibility_profile
            .map(|profile| profile.skeleton_package_path.clone()),
        compatibility_material_alias_count: material_array
            .slots
            .iter()
            .filter(|slot| alias_names.contains(&normalized_material_name(&slot.slot_name)))
            .count(),
        exports_byte_identical,
        uexp_byte_identical,
        policy: "serialized-slots-current-skeleton-retired-physics-idempotent-v5".to_owned(),
    })
}

fn repair_asset(
    tool: &UAssetGuiTool,
    legacy_root: &Path,
    asset: &Path,
    work: &Path,
) -> Result<Vec<BodySetupRepair>> {
    let stem = asset
        .file_stem()
        .and_then(|value| value.to_str())
        .context("UAsset filename is not UTF-8")?;
    let source_json = work.join(format!("{stem}.source.json"));
    let patched_json = work.join(format!("{stem}.patched.json"));
    let rebuilt_asset = work.join(asset.file_name().context("UAsset path has no filename")?);
    tool.to_json(asset, &source_json)?;
    let mut document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let original_exports = export_data(&document)?;
    let mut repairs = repair_document(&mut document, asset)?;
    if repairs.is_empty() {
        return Ok(repairs);
    }
    for repair in &mut repairs {
        repair.asset = package_relative_path(legacy_root, asset);
    }
    fs::write(&patched_json, serde_json::to_vec(&document)?)?;
    tool.import_json(&patched_json, &rebuilt_asset)?;

    let rebuilt_uexp = rebuilt_asset.with_extension("uexp");
    let source_uexp = asset.with_extension("uexp");
    if source_uexp.is_file() && !rebuilt_uexp.is_file() {
        bail!(
            "UAssetGUI rebuilt {} without its required UEXP",
            asset.display()
        );
    }

    let verify_json = work.join(format!("{stem}.verify.json"));
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    let expected_exports = export_data(&document)?;
    let verified_exports = export_data(&verified)?;
    if expected_exports != verified_exports {
        bail!(
            "UAssetGUI verification changed export data for {}",
            asset.display()
        );
    }
    for ((old_name, old_data, _), (new_name, new_data, _)) in
        original_exports.iter().zip(&verified_exports)
    {
        if !old_name.starts_with("BodySetup_") && (old_name != new_name || old_data != new_data) {
            bail!(
                "BodySetup repair changed downstream export {} in {}",
                old_name,
                asset.display()
            );
        }
    }

    fs::copy(&rebuilt_asset, asset)?;
    if rebuilt_uexp.is_file() {
        fs::copy(&rebuilt_uexp, source_uexp)?;
    }
    Ok(repairs)
}

pub fn repair_legacy_body_setups(legacy_root: &Path) -> Result<Vec<BodySetupRepair>> {
    let candidates = WalkDir::new(legacy_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("uasset"))
        })
        .filter_map(|path| {
            let bytes = fs::read(&path).ok()?;
            (contains_ascii(&bytes, b"BodySetup") && contains_ascii(&bytes, b"PhysXPC"))
                .then_some(path)
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let tool = UAssetGuiTool::materialize()?;
    let work = tempfile::Builder::new()
        .prefix("obr-bodysetup-repair-")
        .tempdir()?;
    let mut repairs = Vec::new();
    for (index, asset) in candidates.iter().enumerate() {
        let asset_work = work.path().join(index.to_string());
        fs::create_dir_all(&asset_work)?;
        repairs.extend(repair_asset(&tool, legacy_root, asset, &asset_work)?);
    }
    Ok(repairs)
}

const REBASED_EXPORT_FIELDS: &[&str] = &[
    "SerializationBeforeSerializationDependencies",
    "CreateBeforeSerializationDependencies",
    "SerializationBeforeCreateDependencies",
    "CreateBeforeCreateDependencies",
];

fn normalize_rebased_metadata(document: &mut Value) -> Result<usize> {
    let exports = document
        .get_mut("Exports")
        .and_then(Value::as_array_mut)
        .context("UAsset JSON has no Exports array")?;
    if exports.is_empty() {
        bail!("UAsset JSON contains no exports");
    }
    for export in exports.iter_mut() {
        validate_export_payload(export)?;
        let object = export
            .as_object_mut()
            .context("UAsset JSON export is not an object")?;
        for field in REBASED_EXPORT_FIELDS {
            object.remove(*field);
        }
    }
    let export_count = exports.len();

    let imports = document
        .get_mut("Imports")
        .and_then(Value::as_array_mut)
        .context("UAsset JSON has no Imports array")?;
    for import in imports {
        import
            .as_object_mut()
            .context("UAsset JSON import is not an object")?
            .remove("OuterIndex");
    }
    Ok(export_count)
}

fn file_map(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut files = BTreeMap::new();
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "legacy payload contains a filesystem link: {}",
                entry.path().display()
            );
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if files.insert(relative.clone(), entry.into_path()).is_some() {
            bail!("duplicate legacy payload path: {relative}");
        }
    }
    Ok(files)
}

pub fn verify_rebased_payloads(
    source_root: &Path,
    roundtrip_root: &Path,
    work_root: &Path,
) -> Result<PayloadEquivalenceReport> {
    let source_files = file_map(source_root)?;
    let roundtrip_files = file_map(roundtrip_root)?;
    let source_paths = source_files.keys().cloned().collect::<Vec<_>>();
    let roundtrip_paths = roundtrip_files.keys().cloned().collect::<Vec<_>>();
    if source_paths != roundtrip_paths {
        bail!(
            "Retoc roundtrip changed the extracted file set. Source:\n{}\nRoundtrip:\n{}",
            source_paths.join("\n"),
            roundtrip_paths.join("\n")
        );
    }

    fs::create_dir_all(work_root)?;
    let tool = UAssetGuiTool::materialize()?;
    let mut assets = Vec::new();
    let mut sidecars = Vec::new();
    for (index, relative) in source_paths.iter().enumerate() {
        let source = &source_files[relative];
        let roundtrip = &roundtrip_files[relative];
        let is_uasset = source
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("uasset"));
        if !is_uasset {
            let source_hash = sha256_file(source)?;
            let roundtrip_hash = sha256_file(roundtrip)?;
            if source_hash != roundtrip_hash {
                bail!("Retoc roundtrip changed payload sidecar {relative}");
            }
            sidecars.push(SidecarVerification {
                path: relative.clone(),
                sha256: source_hash,
            });
            continue;
        }

        let asset_work = work_root.join(index.to_string());
        fs::create_dir_all(&asset_work)?;
        let source_json = asset_work.join("source.json");
        let roundtrip_json = asset_work.join("roundtrip.json");
        tool.to_json(source, &source_json)?;
        tool.to_json(roundtrip, &roundtrip_json)?;
        let mut source_document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
        let mut roundtrip_document: Value = serde_json::from_slice(&fs::read(&roundtrip_json)?)?;
        let source_export_count = normalize_rebased_metadata(&mut source_document)?;
        let roundtrip_export_count = normalize_rebased_metadata(&mut roundtrip_document)?;
        if source_export_count != roundtrip_export_count || source_document != roundtrip_document {
            bail!(
                "Retoc roundtrip changed package content outside the allowed linkage metadata: {relative}"
            );
        }
        let source_hash = sha256_file(source)?;
        let roundtrip_hash = sha256_file(roundtrip)?;
        assets.push(PackagePayloadVerification {
            asset: relative.clone(),
            export_count: source_export_count,
            normalized_json_sha256: sha256_bytes(&serde_json::to_vec(&source_document)?),
            metadata_rebased: source_hash != roundtrip_hash,
            source_uasset_sha256: source_hash,
            roundtrip_uasset_sha256: roundtrip_hash,
        });
    }
    if assets.is_empty() {
        bail!("Retoc extraction produced no UAsset packages");
    }
    Ok(PayloadEquivalenceReport {
        asset_count: assets.len(),
        sidecar_count: sidecars.len(),
        assets,
        sidecars,
        allowed_metadata_changes: REBASED_EXPORT_FIELDS
            .iter()
            .copied()
            .chain(std::iter::once("Imports[].OuterIndex"))
            .collect(),
    })
}

pub fn verify_rebased_asset_metadata(
    source: &Path,
    roundtrip: &Path,
    work_root: &Path,
) -> Result<bool> {
    fs::create_dir_all(work_root)?;
    let tool = UAssetGuiTool::materialize()?;
    let source_json = work_root.join("source.json");
    let roundtrip_json = work_root.join("roundtrip.json");
    tool.to_json(source, &source_json)?;
    tool.to_json(roundtrip, &roundtrip_json)?;
    let mut source_document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let mut roundtrip_document: Value = serde_json::from_slice(&fs::read(&roundtrip_json)?)?;
    let source_export_count = normalize_rebased_metadata(&mut source_document)?;
    let roundtrip_export_count = normalize_rebased_metadata(&mut roundtrip_document)?;
    if source_export_count != roundtrip_export_count || source_document != roundtrip_document {
        bail!(
            "Retoc roundtrip changed Texture2D content outside the allowed linkage metadata: {}",
            source.display()
        );
    }
    Ok(sha256_file(source)? != sha256_file(roundtrip)?)
}

pub fn verify_preserved_export_payloads(
    source_root: &Path,
    roundtrip_root: &Path,
    work_root: &Path,
) -> Result<PayloadEquivalenceReport> {
    let source_files = file_map(source_root)?;
    let roundtrip_files = file_map(roundtrip_root)?;
    let source_paths = source_files.keys().cloned().collect::<Vec<_>>();
    let roundtrip_paths = roundtrip_files.keys().cloned().collect::<Vec<_>>();
    if source_paths != roundtrip_paths {
        bail!(
            "Retoc roundtrip changed the extracted file set. Source:\n{}\nRoundtrip:\n{}",
            source_paths.join("\n"),
            roundtrip_paths.join("\n")
        );
    }

    fs::create_dir_all(work_root)?;
    let tool = UAssetGuiTool::materialize()?;
    let mut assets = Vec::new();
    let mut sidecars = Vec::new();
    for (index, relative) in source_paths.iter().enumerate() {
        let source = &source_files[relative];
        let roundtrip = &roundtrip_files[relative];
        let is_uasset = source
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("uasset"));
        if !is_uasset {
            let source_hash = sha256_file(source)?;
            let roundtrip_hash = sha256_file(roundtrip)?;
            if source_hash != roundtrip_hash {
                bail!("material migration changed payload sidecar {relative}");
            }
            sidecars.push(SidecarVerification {
                path: relative.clone(),
                sha256: source_hash,
            });
            continue;
        }

        let asset_work = work_root.join(index.to_string());
        fs::create_dir_all(&asset_work)?;
        let source_json = asset_work.join("source.json");
        let roundtrip_json = asset_work.join("roundtrip.json");
        tool.to_json(source, &source_json)?;
        tool.to_json(roundtrip, &roundtrip_json)?;
        let source_document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
        let roundtrip_document: Value = serde_json::from_slice(&fs::read(&roundtrip_json)?)?;
        let source_exports = validated_export_data(&source_document)?;
        let roundtrip_exports = validated_export_data(&roundtrip_document)?;
        if source_exports != roundtrip_exports {
            bail!(
                "material migration changed export ObjectName, Data, Extras, or SerialSize: {relative}"
            );
        }
        let source_hash = sha256_file(source)?;
        let roundtrip_hash = sha256_file(roundtrip)?;
        assets.push(PackagePayloadVerification {
            asset: relative.clone(),
            export_count: source_exports.len(),
            normalized_json_sha256: sha256_bytes(&serde_json::to_vec(&source_exports)?),
            metadata_rebased: source_hash != roundtrip_hash,
            source_uasset_sha256: source_hash,
            roundtrip_uasset_sha256: roundtrip_hash,
        });
    }
    if assets.is_empty() {
        bail!("Retoc extraction produced no UAsset packages");
    }
    Ok(PayloadEquivalenceReport {
        asset_count: assets.len(),
        sidecar_count: sidecars.len(),
        assets,
        sidecars,
        allowed_metadata_changes: vec![
            "NameMap",
            "Imports",
            "package dependency metadata outside export ObjectName/Data/Extras/SerialSize",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_valid_project_content_roots_to_game_packages() {
        assert_eq!(
            game_package_path("../../../ExampleProject/Content/Items/SM_Item.uasset").unwrap(),
            "/Game/Items/SM_Item"
        );
        assert_eq!(
            game_package_path("OblivionRemastered\\Content\\Items\\BP_Item.umap").unwrap(),
            "/Game/Items/BP_Item"
        );
    }

    #[test]
    fn rejects_ambiguous_or_traversing_content_roots() {
        assert!(game_package_path("Content/Items/SM_Item.uasset").is_err());
        assert!(game_package_path("Project/Content/Items/../Secrets/SM_Item.uasset").is_err());
        assert!(game_package_path("A/B/Content/Items/SM_Item.uasset").is_err());
    }

    fn fixture(path: &Path, duplicate_anchor: bool, payload_bytes: usize) -> Value {
        let mut data = vec![0xAA; 11];
        let mut anchor = Vec::new();
        anchor.extend_from_slice(&1_u32.to_le_bytes());
        anchor.extend_from_slice(&1_u32.to_le_bytes());
        anchor.extend_from_slice(&1_u32.to_le_bytes());
        anchor.extend_from_slice(&1_u32.to_le_bytes());
        anchor.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&anchor);
        data.extend(std::iter::repeat_n(0xCC, payload_bytes));
        if duplicate_anchor {
            data.extend_from_slice(&anchor);
            data.extend(std::iter::repeat_n(0xDD, payload_bytes));
        }
        let _ = path;
        json!({
            "NameMap": ["BlockAll", "PhysXPC"],
            "Imports": [{"ObjectName": "StaticMesh"}],
            "Exports": [
                {
                    "$type": "UAssetAPI.ExportTypes.RawExport, UAssetAPI",
                    "ObjectName": "BodySetup_0",
                    "OuterIndex": 2,
                    "ClassIndex": -1,
                    "SerialSize": data.len(),
                    "Data": BASE64.encode(&data)
                },
                {
                    "$type": "UAssetAPI.ExportTypes.RawExport, UAssetAPI",
                    "ObjectName": "SM_Test",
                    "OuterIndex": 0,
                    "ClassIndex": -1,
                    "SerialSize": 4,
                    "Data": BASE64.encode([1, 2, 3, 4])
                }
            ]
        })
    }

    fn donor_with_materials(materials: &[(&str, &str)]) -> Value {
        let mut imports = Vec::new();
        for (package_path, object_name) in materials {
            let package_index = imports.len();
            imports.push(json!({
                "ClassName": "Package",
                "ObjectName": package_path,
                "OuterIndex": 0
            }));
            imports.push(json!({
                "ClassName": "MaterialInstanceConstant",
                "ClassPackage": "/Script/Engine",
                "ObjectName": object_name,
                "OuterIndex": -(package_index as i64) - 1
            }));
        }
        json!({ "Imports": imports })
    }

    fn material_dependency(package_id: u64, path: &str) -> PackageEntry {
        PackageEntry {
            package_id,
            path: format!("../../../OblivionRemastered/Content/{path}.uasset"),
        }
    }

    fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn source_with_two_material_slots(
        names: &[&str],
        first_import: i32,
        second_import: i32,
        skeleton_import: i32,
    ) -> Value {
        let mut data = vec![0_u8; 400];
        data[..8].copy_from_slice(&[0x00, 0x02, 0x05, 0x02, 0x09, 0x02, 0x09, 0x05]);
        write_i32(&mut data, 8, skeleton_import);
        write_i32(&mut data, 147, -11);
        write_i32(&mut data, 241, 2);
        write_i32(&mut data, 245, first_import);
        write_i32(&mut data, 249, 0);
        write_i32(&mut data, 253, 0);
        write_i32(&mut data, 285, second_import);
        write_i32(&mut data, 289, 1);
        write_i32(&mut data, 293, 0);
        json!({
            "NameMap": names,
            "Exports": [{
                "$type": "UAssetAPI.ExportTypes.RawExport, UAssetAPI",
                "ObjectName": "SK_Test",
                "SerialSize": data.len(),
                "Data": BASE64.encode(data),
                "CreateBeforeSerializationDependencies": [-11]
            }]
        })
    }

    #[test]
    fn maps_only_serialized_material_slots_by_exact_slot_name() {
        let source = source_with_two_material_slots(
            &["MIC_Ebony_Greaves", "MIC_Elven_Cuirass"],
            -4,
            -5,
            -13,
        );
        let donor = donor_with_materials(&[(
            "/Game/Art/Armor/Ebony/MIC_Ebony_Greaves",
            "MIC_Ebony_Greaves",
        )]);
        let dependencies = HashMap::from([
            (
                11,
                material_dependency(11, "Art/Armor/Ebony/MIC_Ebony_Greaves"),
            ),
            (
                12,
                material_dependency(12, "Art/armor/elven/MIC_Elven_Cuirass"),
            ),
        ]);

        let pairs = vec![(5, 3), (6, 4), (7, 10), (8, 12)];
        let (active, candidates) = current_material_candidates(&donor, &dependencies).unwrap();
        let material_array =
            serialized_material_slots(&source, &pairs, &candidates, &BTreeSet::new()).unwrap();
        let selected =
            select_material_slot_targets(&material_array.slots, &candidates, &HashMap::new())
                .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(material_array.offset, 245);
        assert_eq!(material_array.slots.len(), 2);
        assert_eq!(material_array.slots[0].object_import_index, 3);
        assert_eq!(material_array.slots[1].object_import_index, 4);
        assert_eq!(
            selected
                .iter()
                .map(|target| target.package_id)
                .collect::<Vec<_>>(),
            vec![11, 12]
        );
        assert_eq!(
            serialized_skeleton_import_index(&source, &pairs, &BTreeSet::from([3, 4])).unwrap(),
            12
        );
    }

    #[test]
    fn supports_duplicate_serialized_slots_sharing_one_material_import() {
        let source = source_with_two_material_slots(
            &["MIC_Ebony_Cuirass", "MIC_Ebony_Cuirass_001"],
            -4,
            -4,
            -11,
        );
        let donor = donor_with_materials(&[(
            "/Game/Art/Armor/Ebony/MIC_Ebony_Cuirass",
            "MIC_Ebony_Cuirass",
        )]);
        let dependencies = HashMap::from([(
            21,
            material_dependency(21, "Art/Armor/Ebony/MIC_Ebony_Cuirass"),
        )]);
        let pairs = vec![(5, 3), (6, 8), (7, 10)];
        let (_, candidates) = current_material_candidates(&donor, &dependencies).unwrap();
        let material_array =
            serialized_material_slots(&source, &pairs, &candidates, &BTreeSet::new()).unwrap();
        let selected =
            select_material_slot_targets(&material_array.slots, &candidates, &HashMap::new())
                .unwrap();

        assert_eq!(material_array.slots.len(), 2);
        assert_eq!(material_array.slots[0].object_import_index, 3);
        assert_eq!(material_array.slots[1].object_import_index, 3);
        assert_eq!(
            selected
                .iter()
                .map(|target| target.package_id)
                .collect::<Vec<_>>(),
            vec![21, 21]
        );
    }

    #[test]
    fn maps_generic_body_slots_only_through_an_explicit_profile_alias() {
        let source = source_with_two_material_slots(&["material", "material"], -4, -5, -11);
        let donor = donor_with_materials(&[(
            "/Game/Art/Character/Imperial/MIC_Imperial_Body_F",
            "MIC_Imperial_Body_F",
        )]);
        let dependencies = HashMap::from([(
            31,
            material_dependency(31, "Art/Character/Imperial/MIC_Imperial_Body_F"),
        )]);
        let pairs = vec![(5, 3), (6, 4), (7, 10)];
        let (_, candidates) = current_material_candidates(&donor, &dependencies).unwrap();
        let alias_target = candidates[0].clone();
        let aliases = BTreeSet::from(["material".to_owned()]);
        let alias_targets = HashMap::from([("material".to_owned(), alias_target)]);
        let material_array =
            serialized_material_slots(&source, &pairs, &candidates, &aliases).unwrap();
        let selected =
            select_material_slot_targets(&material_array.slots, &candidates, &alias_targets)
                .unwrap();

        assert_eq!(material_array.slots.len(), 2);
        assert_eq!(
            selected
                .iter()
                .map(|target| target.package_id)
                .collect::<Vec<_>>(),
            vec![31, 31]
        );
        assert!(serialized_material_slots(&source, &pairs, &candidates, &BTreeSet::new()).is_err());
    }

    #[test]
    fn exact_named_material_wins_when_an_object_also_has_a_generic_alias_slot() {
        let source =
            source_with_two_material_slots(&["MIC_Daedric_Cuirass", "material"], -4, -4, -11);
        let donor = donor_with_materials(&[(
            "/Game/Art/Armor/Daedric/MIC_Daedric_Cuirass",
            "MIC_Daedric_Cuirass",
        )]);
        let dependencies = HashMap::from([(
            41,
            material_dependency(41, "Art/Armor/Daedric/MIC_Daedric_Cuirass"),
        )]);
        let pairs = vec![(5, 3), (6, 10)];
        let (_, candidates) = current_material_candidates(&donor, &dependencies).unwrap();
        let body_target = ImportTarget {
            package_id: 42,
            package_path: "/Game/Art/Character/Imperial/MIC_Imperial_Body_F".to_owned(),
            object_name: "MIC_Imperial_Body_F".to_owned(),
            class_name: "MaterialInstanceConstant".to_owned(),
        };
        let aliases = BTreeSet::from(["material".to_owned()]);
        let alias_targets = HashMap::from([("material".to_owned(), body_target)]);
        let material_array =
            serialized_material_slots(&source, &pairs, &candidates, &aliases).unwrap();
        let selected =
            select_material_slot_targets(&material_array.slots, &candidates, &alias_targets)
                .unwrap();

        assert_eq!(
            selected
                .iter()
                .map(|target| target.package_id)
                .collect::<Vec<_>>(),
            vec![41, 41]
        );
    }

    #[test]
    fn nulls_only_a_proven_retired_physics_asset_reference() {
        let mut source = source_with_two_material_slots(
            &["MIC_Ebony_Greaves", "MIC_Elven_Cuirass"],
            -4,
            -5,
            -13,
        );
        let donor = donor_with_materials(&[(
            "/Game/Art/Armor/Ebony/MIC_Ebony_Greaves",
            "MIC_Ebony_Greaves",
        )]);
        let dependencies = HashMap::from([
            (
                11,
                material_dependency(11, "Art/Armor/Ebony/MIC_Ebony_Greaves"),
            ),
            (
                12,
                material_dependency(12, "Art/armor/elven/MIC_Elven_Cuirass"),
            ),
        ]);
        let pairs = vec![(5, 3), (6, 4), (7, 10), (8, 12)];
        let (_, candidates) = current_material_candidates(&donor, &dependencies).unwrap();
        let material_array =
            serialized_material_slots(&source, &pairs, &candidates, &BTreeSet::new()).unwrap();
        let evidence = retire_obsolete_physics_asset(
            &mut source,
            &donor,
            &pairs,
            &material_array,
            &BTreeSet::from([3, 4]),
            12,
            0,
        )
        .unwrap();

        assert_eq!(
            evidence,
            vec![RetiredPhysicsAssetEvidence {
                object_import_index: 10,
                reference_offset: Some(147),
                removed_dependency_count: 1,
                already_retired: false,
            }]
        );
        let bytes = skeletal_mesh_export_bytes(&source).unwrap();
        assert_eq!(little_i32(&bytes, 147), Some(0));
        assert!(
            source["Exports"][0]["CreateBeforeSerializationDependencies"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        let repeated = retire_obsolete_physics_asset(
            &mut source,
            &donor,
            &pairs,
            &material_array,
            &BTreeSet::from([3, 4]),
            12,
            1,
        )
        .unwrap();
        assert_eq!(
            repeated,
            vec![RetiredPhysicsAssetEvidence {
                object_import_index: 10,
                reference_offset: None,
                removed_dependency_count: 0,
                already_retired: true,
            }]
        );
    }

    #[test]
    fn strips_only_the_equipment_bodysetup_payload() {
        let path = Path::new(r"C:\mod\Content\Art\Equipment\armor\SM_Test.uasset");
        let mut document = fixture(path, false, 128);
        let before_mesh = document["Exports"][1]["Data"].clone();
        let repairs = repair_document(&mut document, path).unwrap();
        assert_eq!(repairs.len(), 1);
        assert_eq!(repairs[0].old_serial_size, 159);
        assert_eq!(repairs[0].new_serial_size, 16);
        assert_eq!(document["Exports"][1]["Data"], before_mesh);
        let body = BASE64
            .decode(document["Exports"][0]["Data"].as_str().unwrap())
            .unwrap();
        assert_eq!(body.len(), 16);
        assert_eq!(body[15], 0);
    }

    #[test]
    fn refuses_ambiguous_serialization_anchors() {
        let path = Path::new(r"C:\mod\Content\Art\Equipment\armor\SM_Test.uasset");
        let mut document = fixture(path, true, 128);
        let error = repair_document(&mut document, path).unwrap_err();
        assert!(error.to_string().contains("ambiguous repair"));
    }

    #[test]
    fn collision_repair_is_structural_not_location_based() {
        let path = Path::new(r"C:\mod\Content\Unexpected\MeshWithoutAPrefix.uasset");
        let mut document = fixture(path, false, 128);
        let repairs = repair_document(&mut document, path).unwrap();
        assert_eq!(repairs.len(), 1);
        assert_eq!(repairs[0].new_serial_size, 16);
        assert_eq!(
            repairs[0].policy,
            "structural-static-mesh-runtime-boundary-v1.512.105.0"
        );
    }
    #[test]
    fn ignores_an_already_empty_bodysetup() {
        let path = Path::new(r"C:\mod\Content\Art\Equipment\armor\SM_Test.uasset");
        let mut document = fixture(path, false, 8);
        assert!(repair_document(&mut document, path).unwrap().is_empty());
    }

    #[test]
    fn normalizes_only_retoc_linkage_metadata() {
        let data = BASE64.encode([1, 2, 3, 4]);
        let mut source = json!({
            "Imports": [{"ObjectName": "SkeletalMesh", "OuterIndex": -2}],
            "Exports": [{
                "$type": "UAssetAPI.ExportTypes.RawExport, UAssetAPI",
                "ObjectName": "SK_Test",
                "SerialSize": 4,
                "Data": data,
                "CreateBeforeSerializationDependencies": [1, 2]
            }]
        });
        let mut rebuilt = source.clone();
        rebuilt["Imports"][0]["OuterIndex"] = Value::from(-4);
        rebuilt["Exports"][0]["CreateBeforeSerializationDependencies"] = json!([9]);
        assert_eq!(
            normalize_rebased_metadata(&mut source).unwrap(),
            normalize_rebased_metadata(&mut rebuilt).unwrap()
        );
        assert_eq!(source, rebuilt);
    }

    #[test]
    fn does_not_normalize_changed_export_payload() {
        let mut source = json!({
            "Imports": [],
            "Exports": [{
                "$type": "UAssetAPI.ExportTypes.RawExport, UAssetAPI",
                "ObjectName": "SK_Test",
                "SerialSize": 4,
                "Data": BASE64.encode([1, 2, 3, 4])
            }]
        });
        let mut rebuilt = source.clone();
        rebuilt["Exports"][0]["Data"] = Value::String(BASE64.encode([4, 3, 2, 1]));
        normalize_rebased_metadata(&mut source).unwrap();
        normalize_rebased_metadata(&mut rebuilt).unwrap();
        assert_ne!(source, rebuilt);
    }

    fn texture_fixture(class_name: &str) -> Value {
        json!({
            "NameMap": ["None", "PF_BC7", "T_Test_NNRM", "Texture2D"],
            "UseSeparateBulkDataFiles": true,
            "Imports": [{
                "ObjectName": class_name,
                "ClassPackage": "/Script/CoreUObject",
                "ClassName": "Class"
            }],
            "Exports": [{
                "$type": "UAssetAPI.ExportTypes.RawExport, UAssetAPI",
                "ObjectName": "T_Test_NNRM",
                "ClassIndex": -1,
                "SerialSize": 128
            }],
            "DataResources": [{"RawSize": 512}, {"RawSize": 128}]
        })
    }

    #[test]
    fn structurally_identifies_texture2d_and_bulk_sidecars() {
        let temp = tempfile::tempdir().unwrap();
        let asset = temp.path().join("T_Test_NNRM.uasset");
        fs::write(&asset, [1, 2, 3]).unwrap();
        fs::write(asset.with_extension("uexp"), [4, 5]).unwrap();
        fs::write(asset.with_extension("ubulk"), [6, 7, 8, 9]).unwrap();
        let diagnostic = inspect_texture_document(&texture_fixture("Texture2D"), &asset).unwrap();
        assert_eq!(diagnostic.class_name, "Texture2D");
        assert_eq!(diagnostic.pixel_format, "PF_BC7");
        assert_eq!(diagnostic.packed_texture_kind.as_deref(), Some("NNRM"));
        assert_eq!(diagnostic.uexp_bytes, Some(2));
        assert_eq!(diagnostic.ubulk_bytes, Some(4));
        assert!(diagnostic.warnings.is_empty());
    }

    #[test]
    fn refuses_a_non_texture_export_in_the_texture_lane() {
        let temp = tempfile::tempdir().unwrap();
        let asset = temp.path().join("T_Test_NNRM.uasset");
        fs::write(&asset, [1]).unwrap();
        fs::write(asset.with_extension("uexp"), [2]).unwrap();
        let error = inspect_texture_document(&texture_fixture("SkeletalMesh"), &asset).unwrap_err();
        assert!(error.to_string().contains("not Texture2D"));
    }
}
