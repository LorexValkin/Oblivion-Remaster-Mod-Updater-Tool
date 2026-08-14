use crate::archive::sha256_bytes;
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const RETOC_EXE: &[u8] = include_bytes!("../third_party/retoc/retoc.exe");
const OO2CORE_DLL: &[u8] = include_bytes!("../third_party/retoc/oo2core_9_win64.dll");
pub const RETOC_LICENSE: &str = include_str!("../third_party/retoc/LICENSE");

pub fn embedded_fingerprints() -> Vec<(&'static str, usize, String, bool)> {
    [
        ("retoc.exe", RETOC_EXE),
        ("oo2core_9_win64.dll", OO2CORE_DLL),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        (
            name,
            bytes.len(),
            sha256_bytes(bytes),
            bytes.starts_with(b"MZ"),
        )
    })
    .collect()
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeResult {
    pub command: Vec<String>,
    pub exit_code: i32,
    pub output: Vec<String>,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageEntry {
    pub package_id: u64,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageStoreEntry {
    pub package_id: u64,
    pub path: String,
    pub imported_package_ids: Vec<u64>,
}

pub struct RetocTool {
    _temp: TempDir,
    executable: PathBuf,
}

impl RetocTool {
    pub fn materialize() -> Result<Self> {
        let temp = tempfile::Builder::new().prefix("obr-retoc-").tempdir()?;
        let executable = temp.path().join("retoc.exe");
        fs::write(&executable, RETOC_EXE)?;
        fs::write(temp.path().join("oo2core_9_win64.dll"), OO2CORE_DLL)?;
        Ok(Self {
            _temp: temp,
            executable,
        })
    }

    pub fn run<I, S>(&self, arguments: I) -> Result<NativeResult>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let args = arguments
            .into_iter()
            .map(|value| value.as_ref().to_owned())
            .collect::<Vec<_>>();
        let mut command = Command::new(&self.executable);
        command.args(&args).current_dir(
            self.executable
                .parent()
                .context("embedded retoc has no parent")?,
        );
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let output = command
            .output()
            .with_context(|| format!("launching embedded retoc: {:?}", args))?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            if !text.ends_with('\n') && !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&stderr);
        }
        let lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
        let mut display = vec![self.executable.display().to_string()];
        display.extend(
            args.iter()
                .map(|value| value.to_string_lossy().into_owned()),
        );
        Ok(NativeResult {
            command: display,
            exit_code: output.status.code().unwrap_or(-1),
            output: lines,
            text,
        })
    }

    pub fn assert_success(result: &NativeResult, label: &str) -> Result<()> {
        if result.exit_code != 0 {
            bail!(
                "{label} failed with exit {}:\n{}",
                result.exit_code,
                result.text
            );
        }
        Ok(())
    }

    pub fn extraction_summary(result: &NativeResult, label: &str) -> Result<(usize, usize)> {
        Self::assert_success(result, label)?;
        let regex = Regex::new(r"Extracted\s+(\d+)\s+\((\d+)\s+failed\)\s+legacy assets")?;
        let matches = regex.captures_iter(&result.text).collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!(
                "{label} did not emit one parseable extraction summary:\n{}",
                result.text
            );
        }
        Ok((matches[0][1].parse()?, matches[0][2].parse()?))
    }

    pub fn verify(&self, utoc: &Path, label: &str) -> Result<NativeResult> {
        let result = self.run(["verify".into(), utoc.as_os_str().to_owned()])?;
        Self::assert_success(&result, label)?;
        if !result.text.to_ascii_lowercase().contains("verified") {
            bail!("retoc did not confirm container verification: {label}");
        }
        Ok(result)
    }

    pub fn package_inventory(&self, utoc: &Path) -> Result<(NativeResult, Vec<String>)> {
        let (result, entries) = self.package_entries(utoc)?;
        Ok((
            result,
            entries.into_iter().map(|entry| entry.path).collect(),
        ))
    }

    pub fn package_entries(&self, utoc: &Path) -> Result<(NativeResult, Vec<PackageEntry>)> {
        let result = self.run([
            "list".into(),
            "--path".into(),
            "--package".into(),
            utoc.as_os_str().to_owned(),
        ])?;
        Self::assert_success(&result, &format!("retoc list {}", utoc.display()))?;
        let mut entries = parse_package_entries(&result.output)?;
        entries.sort_by(|left, right| {
            left.path
                .to_ascii_lowercase()
                .cmp(&right.path.to_ascii_lowercase())
        });
        entries.dedup_by(|left, right| {
            left.package_id == right.package_id && left.path.eq_ignore_ascii_case(&right.path)
        });
        if entries.is_empty() {
            bail!("retoc list found no asset packages in {}", utoc.display());
        }
        Ok((result, entries))
    }

    pub fn package_store_entries(
        &self,
        utoc: &Path,
    ) -> Result<(NativeResult, Vec<PackageStoreEntry>)> {
        let result = self.run([
            "list".into(),
            "--path".into(),
            "--package".into(),
            "--store".into(),
            utoc.as_os_str().to_owned(),
        ])?;
        Self::assert_success(&result, &format!("retoc package store {}", utoc.display()))?;
        let mut entries = parse_package_store_entries(&result.output)?;
        entries.sort_by(|left, right| {
            left.path
                .to_ascii_lowercase()
                .cmp(&right.path.to_ascii_lowercase())
        });
        if entries.is_empty() {
            bail!(
                "retoc package store found no asset packages in {}",
                utoc.display()
            );
        }
        Ok((result, entries))
    }

    /// Reads package-store asset rows while allowing a structurally valid
    /// container such as `global.utoc` to contain only script objects.
    pub fn package_store_entries_allow_empty(
        &self,
        utoc: &Path,
    ) -> Result<(NativeResult, Vec<PackageStoreEntry>)> {
        let result = self.run([
            "list".into(),
            "--path".into(),
            "--package".into(),
            "--store".into(),
            utoc.as_os_str().to_owned(),
        ])?;
        Self::assert_success(&result, &format!("retoc package store {}", utoc.display()))?;
        let mut entries = parse_package_store_entries(&result.output)?;
        entries.sort_by(|left, right| {
            left.path
                .to_ascii_lowercase()
                .cmp(&right.path.to_ascii_lowercase())
        });
        Ok((result, entries))
    }
}

fn parse_package_entries(lines: &[String]) -> Result<Vec<PackageEntry>> {
    let regex =
        Regex::new(r"\s[0-9a-fA-F]{24}\s+(\d+)\s+ExportBundleData\s+(.+?\.(?:uasset|umap))\s*$")?;
    lines
        .iter()
        .filter_map(|line| regex.captures(line))
        .map(|captures| {
            Ok(PackageEntry {
                package_id: captures[1].parse()?,
                path: captures[2].replace('\\', "/"),
            })
        })
        .collect()
}

fn parse_package_store_entries(lines: &[String]) -> Result<Vec<PackageStoreEntry>> {
    let row = Regex::new(
        r#"\s[0-9a-fA-F]{24}\s+(\d+)\s+ExportBundleData\s+(.+?\.(?:uasset|umap))\s+"StoreEntry \{.*imported_packages: \[(.*?)\], shader_map_hashes:"#,
    )?;
    let import = Regex::new(r"FPackageId\((\d+)\)")?;
    lines
        .iter()
        .filter_map(|line| row.captures(line))
        .map(|captures| {
            Ok(PackageStoreEntry {
                package_id: captures[1].parse()?,
                path: captures[2].replace('\\', "/"),
                imported_package_ids: import
                    .captures_iter(&captures[3])
                    .map(|value| value[1].parse())
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_ids_and_paths_from_list_output() {
        let entries = parse_package_entries(&[
            "betterdaedric_p 64d149156faf6d8b00000001 10046879235366834532 ExportBundleData ../../../OblivionRemastered/Content/Art/armor/Daedric/SK_Daedric_Cuirass_f.uasset".to_owned(),
            "betterdaedric_p 853a7d403710eee000000006 - ContainerHeader -".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            entries,
            vec![PackageEntry {
                package_id: 10_046_879_235_366_834_532,
                path: "../../../OblivionRemastered/Content/Art/armor/Daedric/SK_Daedric_Cuirass_f.uasset".to_owned(),
            }]
        );
    }

    #[test]
    fn parses_package_store_import_ids() {
        let entries = parse_package_store_entries(&[
            "betterdaedric_p 64d149156faf6d8b00000001 10046879235366834532 ExportBundleData ../../../OblivionRemastered/Content/Art/armor/Daedric/SK_Daedric_Cuirass_f.uasset \"StoreEntry { export_bundles_size: 0, load_order: 0, export_count: 0, export_bundle_count: 0, imported_packages: [FPackageId(2800363135405804391), FPackageId(7232882329597048327)], shader_map_hashes: [] }\"".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            entries,
            vec![PackageStoreEntry {
                package_id: 10_046_879_235_366_834_532,
                path: "../../../OblivionRemastered/Content/Art/armor/Daedric/SK_Daedric_Cuirass_f.uasset".to_owned(),
                imported_package_ids: vec![
                    2_800_363_135_405_804_391,
                    7_232_882_329_597_048_327
                ],
            }]
        );
    }
}
