use crate::archive::sha256_file;
use crate::game::validate_game_install;
use crate::retoc::RetocTool;
use crate::uasset::UAssetGuiTool;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

const CONTAINER: &str = "AAAA_OffhandStaves_NativePhysics_P";
const ASSET_RELATIVE: &str =
    r"OblivionRemastered\Content\Art\Equipment\armor\SM_Offhand_Staff.uasset";
const MATERIAL_OBJECT: &str = "MIC_Indarys_Staff";
const MATERIAL_PACKAGE: &str = "/Game/Art/Equipment/staffs/MIC_Indarys_Staff";
const SOURCE_IMPORT_ID: &str = "5735402301659623535";
const TARGET_IMPORT_ID: &str = "17859529614553109955";
const POLICY: &str = "offhand-staff-current-mic-import-v1.512.105.0";
const SOURCE_PAK_SHA256: &str = "75E7144577253917F6DA7312EF5E585B12FB728226A22B0938323751A6B555CD";
const SOURCE_UCAS_SHA256: &str = "C464EFD15C6324096C2CF72A0271AD16C9DEC417BDC4B3B2A38085FDC5F7D4C2";
const SOURCE_UTOC_SHA256: &str = "4180DD38817A8BD5184FEAFCDB3692F29FDE96BBA83374FDCC35DCBB9D0F49A3";

#[derive(Clone, Debug)]
pub struct OffhandExportRequest {
    pub source_utoc: PathBuf,
    pub game_root: PathBuf,
    pub output_directory: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OffhandExportOutcome {
    pub output_directory: PathBuf,
    pub report_path: PathBuf,
    pub output_hashes: BTreeMap<String, String>,
}

fn expected_source_hash(extension: &str) -> &'static str {
    match extension {
        "pak" => SOURCE_PAK_SHA256,
        "ucas" => SOURCE_UCAS_SHA256,
        "utoc" => SOURCE_UTOC_SHA256,
        _ => unreachable!(),
    }
}

fn same_sha256(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

fn source_triple(source_utoc: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let stem = source_utoc.with_extension("");
    let mut files = BTreeMap::new();
    for extension in ["pak", "ucas", "utoc"] {
        let path = stem.with_extension(extension);
        if !path.is_file() {
            bail!("source donor is missing {}: {}", extension, path.display());
        }
        let actual = sha256_file(&path)?;
        let expected = expected_source_hash(extension);
        if !same_sha256(&actual, expected) {
            bail!(
                "source donor {extension} differs from the pinned physics-working base. Expected {expected}, got {actual}"
            );
        }
        files.insert(extension.to_owned(), path);
    }
    Ok(files)
}

fn args(values: impl IntoIterator<Item = impl Into<OsString>>) -> Vec<OsString> {
    values.into_iter().map(Into::into).collect()
}

fn package_id_for_path(text: &str, path_suffix: &str) -> Result<String> {
    let matches = text
        .lines()
        .filter(|line| line.replace('\\', "/").ends_with(path_suffix))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "expected exactly one current package row for {path_suffix}; found {}",
            matches.len()
        );
    }
    let fields = matches[0].split_whitespace().collect::<Vec<_>>();
    if fields.len() < 5 || fields[3] != "ExportBundleData" {
        bail!("could not parse current package row: {}", matches[0]);
    }
    Ok(fields[2].to_owned())
}

fn export_data(document: &Value) -> Result<Vec<(String, String, u64)>> {
    document["Exports"]
        .as_array()
        .context("UAsset JSON has no Exports")?
        .iter()
        .map(|export| {
            Ok((
                export["ObjectName"]
                    .as_str()
                    .context("export has no ObjectName")?
                    .to_owned(),
                export["Data"]
                    .as_str()
                    .context("export has no Data")?
                    .to_owned(),
                export["SerialSize"]
                    .as_u64()
                    .context("export has no SerialSize")?,
            ))
        })
        .collect()
}

fn patch_material_import(document: &mut Value) -> Result<()> {
    let names = document["NameMap"]
        .as_array_mut()
        .context("UAsset JSON has no NameMap")?;
    for (index, expected) in [
        (1, MATERIAL_OBJECT),
        (25, "/Engine/UnknownPackage"),
        (26, "Object"),
        (27, "UnknownExport"),
    ] {
        let actual = names.get(index).and_then(Value::as_str);
        if actual != Some(expected) {
            bail!(
                "pinned unresolved NameMap anchor {index} changed: expected {expected:?}, got {actual:?}"
            );
        }
    }
    names[25] = Value::String(MATERIAL_PACKAGE.to_owned());
    names[26] = Value::String("MaterialInstanceConstant".to_owned());
    names[27] = Value::String(MATERIAL_OBJECT.to_owned());

    let imports = document["Imports"]
        .as_array_mut()
        .context("UAsset JSON has no Imports")?;
    if imports.len() != 10
        || imports[4]["ObjectName"] != "UnknownExport"
        || imports[4]["OuterIndex"] != -7
        || imports[6]["ObjectName"] != "/Engine/UnknownPackage"
        || imports[6]["OuterIndex"] != 0
    {
        bail!("pinned unresolved material import anchors changed");
    }
    imports[4]["ObjectName"] = Value::String(MATERIAL_OBJECT.to_owned());
    imports[4]["ClassPackage"] = Value::String("/Script/Engine".to_owned());
    imports[4]["ClassName"] = Value::String("MaterialInstanceConstant".to_owned());
    imports[6]["ObjectName"] = Value::String(MATERIAL_PACKAGE.to_owned());
    Ok(())
}

fn copy_verified(source: &Path, destination: &Path) -> Result<String> {
    let source_hash = sha256_file(source)?;
    if destination.exists() {
        if source_hash != sha256_file(destination)? {
            bail!(
                "existing output conflicts with reproducible candidate: {}",
                destination.display()
            );
        }
    } else {
        fs::copy(source, destination)?;
    }
    Ok(source_hash)
}

pub fn run_offhand_export(request: OffhandExportRequest) -> Result<OffhandExportOutcome> {
    let source_utoc = fs::canonicalize(&request.source_utoc)
        .with_context(|| format!("source UTOC not found: {}", request.source_utoc.display()))?;
    let source_files = source_triple(&source_utoc)?;
    let game = validate_game_install(&request.game_root, "offhand export CLI");
    if !game.valid {
        bail!("game folder is incomplete: {}", game.missing.join(", "));
    }
    let game_paks = game.root.join(r"OblivionRemastered\Content\Paks");
    let global_utoc = game_paks.join("global.utoc");
    let global_ucas = game_paks.join("global.ucas");
    let main_utoc = game_paks.join("OblivionRemastered-Windows.utoc");
    for path in [&global_utoc, &global_ucas, &main_utoc] {
        if !path.is_file() {
            bail!("required game container is missing: {}", path.display());
        }
    }

    let retoc = RetocTool::materialize()?;
    let source_store = retoc.run(args([
        "list".into(),
        "--path".into(),
        "--package".into(),
        "--store".into(),
        source_utoc.as_os_str().to_owned(),
    ]))?;
    RetocTool::assert_success(&source_store, "source donor package-store read")?;
    if !source_store.text.contains(&format!(
        "imported_packages: [FPackageId({SOURCE_IMPORT_ID})]"
    )) {
        bail!("source donor does not carry pinned unresolved import ID {SOURCE_IMPORT_ID}");
    }

    let inventory = retoc.run(args([
        "list".into(),
        "--path".into(),
        "--package".into(),
        main_utoc.as_os_str().to_owned(),
    ]))?;
    RetocTool::assert_success(&inventory, "current game package inventory")?;
    let target_id = package_id_for_path(
        &inventory.text,
        "OblivionRemastered/Content/Art/Equipment/staffs/MIC_Indarys_Staff.uasset",
    )?;
    if target_id != TARGET_IMPORT_ID {
        bail!("current MIC package ID changed. Expected {TARGET_IMPORT_ID}, got {target_id}");
    }

    let work = tempfile::Builder::new()
        .prefix("obr-rust-offhand-export-")
        .tempdir()?;
    let input = work.path().join("input");
    let legacy = work.path().join("legacy");
    let json = work.path().join("json");
    let rebuilt = work.path().join("rebuilt");
    let zen = work.path().join("zen");
    for directory in [&input, &legacy, &json, &rebuilt, &zen] {
        fs::create_dir_all(directory)?;
    }
    for path in [&global_utoc, &global_ucas] {
        fs::copy(path, input.join(path.file_name().unwrap()))?;
    }
    for path in source_files.values() {
        fs::copy(path, input.join(path.file_name().unwrap()))?;
    }

    let extraction = retoc.run(args([
        "to-legacy".into(),
        input.as_os_str().to_owned(),
        legacy.as_os_str().to_owned(),
        "--version".into(),
        "UE5_3".into(),
        "--no-shaders".into(),
        "--no-script-objects".into(),
        "--no-parallel".into(),
    ]))?;
    let (extracted, failed) =
        RetocTool::extraction_summary(&extraction, "source donor extraction")?;
    if extracted != 1 || failed != 0 {
        bail!(
            "source donor extraction expected one package; extracted {extracted}, failed {failed}"
        );
    }

    let asset = legacy.join(ASSET_RELATIVE);
    if !asset.is_file() {
        bail!("extracted staff asset is missing: {}", asset.display());
    }
    let tool = UAssetGuiTool::materialize()?;
    let source_json = json.join("source.json");
    let patched_json = json.join("patched.json");
    let verify_json = json.join("verify.json");
    tool.to_json(&asset, &source_json)?;
    let mut document: Value = serde_json::from_slice(&fs::read(&source_json)?)?;
    let original_exports = export_data(&document)?;
    patch_material_import(&mut document)?;
    fs::write(&patched_json, serde_json::to_vec(&document)?)?;

    let rebuilt_asset = rebuilt.join("SM_Offhand_Staff.uasset");
    tool.import_json(&patched_json, &rebuilt_asset)?;
    let rebuilt_uexp = rebuilt_asset.with_extension("uexp");
    if !rebuilt_uexp.is_file() {
        bail!("UAssetGUI did not rebuild the staff UEXP");
    }
    tool.to_json(&rebuilt_asset, &verify_json)?;
    let verified: Value = serde_json::from_slice(&fs::read(&verify_json)?)?;
    if original_exports != export_data(&verified)? {
        bail!("material retarget changed one or more raw exports");
    }
    if verified["Imports"][4]["ObjectName"] != MATERIAL_OBJECT
        || verified["Imports"][6]["ObjectName"] != MATERIAL_PACKAGE
    {
        bail!("resolved material import did not survive UAssetGUI rebuild");
    }

    let bulk = asset.with_extension("ubulk");
    let bulk_hash = sha256_file(&bulk)?;
    fs::copy(&rebuilt_asset, &asset)?;
    fs::copy(&rebuilt_uexp, asset.with_extension("uexp"))?;
    if sha256_file(&bulk)? != bulk_hash {
        bail!("material retarget changed staff bulk data");
    }

    let candidate_utoc = zen.join(format!("{CONTAINER}.utoc"));
    let pack = retoc.run(args([
        "to-zen".into(),
        "--version".into(),
        "UE5_3".into(),
        legacy.as_os_str().to_owned(),
        candidate_utoc.as_os_str().to_owned(),
    ]))?;
    RetocTool::assert_success(&pack, "candidate pack")?;
    retoc.verify(&candidate_utoc, "candidate verify")?;
    let candidate_store = retoc.run(args([
        "list".into(),
        "--path".into(),
        "--package".into(),
        "--store".into(),
        candidate_utoc.as_os_str().to_owned(),
    ]))?;
    RetocTool::assert_success(&candidate_store, "candidate package-store read")?;
    if !candidate_store.text.contains(&format!(
        "imported_packages: [FPackageId({TARGET_IMPORT_ID})]"
    )) {
        bail!("candidate does not import current MIC package ID {TARGET_IMPORT_ID}");
    }

    fs::create_dir_all(&request.output_directory)?;
    let output_directory = fs::canonicalize(&request.output_directory)?;
    let mut output_hashes = BTreeMap::new();
    for extension in ["pak", "ucas", "utoc"] {
        let source = candidate_utoc.with_extension(extension);
        let destination = output_directory.join(format!("{CONTAINER}.{extension}"));
        output_hashes.insert(extension.to_owned(), copy_verified(&source, &destination)?);
    }
    let report_path = output_directory.join("offhand-staff-material-repair-report.json");
    let report = serde_json::json!({
        "schema": "obr-offhand-staff-material-repair",
        "version": 2,
        "implementation": "native-rust",
        "policy": POLICY,
        "status": "candidate_ready_for_runtime_test",
        "runtimeVerified": false,
        "sourceHashes": {
            "pak": SOURCE_PAK_SHA256,
            "ucas": SOURCE_UCAS_SHA256,
            "utoc": SOURCE_UTOC_SHA256,
        },
        "sourceImportedPackageId": SOURCE_IMPORT_ID,
        "targetMaterialPackage": MATERIAL_PACKAGE,
        "targetMaterialPackageId": TARGET_IMPORT_ID,
        "exportsByteIdentical": true,
        "bulkDataSha256": bulk_hash,
        "retocVerified": true,
        "outputHashes": output_hashes,
    });
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(OffhandExportOutcome {
        output_directory,
        report_path,
        output_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        let mut names = (0..30)
            .map(|index| Value::String(format!("Name{index}")))
            .collect::<Vec<_>>();
        names[1] = Value::String(MATERIAL_OBJECT.to_owned());
        names[25] = Value::String("/Engine/UnknownPackage".to_owned());
        names[26] = Value::String("Object".to_owned());
        names[27] = Value::String("UnknownExport".to_owned());
        let mut imports = (0..10)
            .map(|_| json!({"ObjectName":"Other","OuterIndex":0}))
            .collect::<Vec<_>>();
        imports[4] = json!({
            "ObjectName":"UnknownExport","OuterIndex":-7,
            "ClassPackage":"/Script/CoreUObject","ClassName":"Object"
        });
        imports[6] = json!({
            "ObjectName":"/Engine/UnknownPackage","OuterIndex":0,
            "ClassPackage":"/Script/CoreUObject","ClassName":"Package"
        });
        json!({"NameMap":names,"Imports":imports})
    }

    #[test]
    fn patches_only_the_pinned_material_import() {
        let mut document = fixture();
        patch_material_import(&mut document).unwrap();
        assert_eq!(document["Imports"][4]["ObjectName"], MATERIAL_OBJECT);
        assert_eq!(
            document["Imports"][4]["ClassName"],
            "MaterialInstanceConstant"
        );
        assert_eq!(document["Imports"][6]["ObjectName"], MATERIAL_PACKAGE);
    }

    #[test]
    fn refuses_changed_material_anchors() {
        let mut document = fixture();
        document["NameMap"][25] = Value::String("Changed".to_owned());
        assert!(patch_material_import(&mut document).is_err());
    }

    #[test]
    fn parses_exact_package_id_row() {
        let text = "Container chunk 17859529614553109955 ExportBundleData ../../../OblivionRemastered/Content/Art/Equipment/staffs/MIC_Indarys_Staff.uasset";
        assert_eq!(
            package_id_for_path(
                text,
                "OblivionRemastered/Content/Art/Equipment/staffs/MIC_Indarys_Staff.uasset"
            )
            .unwrap(),
            TARGET_IMPORT_ID
        );
    }

    #[test]
    fn pinned_sha256_comparison_accepts_hex_casing_only() {
        assert!(same_sha256(
            "75e7144577253917f6da7312ef5e585b12fb728226a22b0938323751a6b555cd",
            SOURCE_PAK_SHA256
        ));
        assert!(!same_sha256(
            "85e7144577253917f6da7312ef5e585b12fb728226a22b0938323751a6b555cd",
            SOURCE_PAK_SHA256
        ));
    }
}
