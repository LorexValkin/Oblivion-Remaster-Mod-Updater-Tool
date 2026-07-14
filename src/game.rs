use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub const REQUIRED_GAME_FILES: &[(&str, &str)] = &[
    (
        "shipping executable",
        r"OblivionRemastered\Binaries\Win64\OblivionRemastered-Win64-Shipping.exe",
    ),
    (
        "Oblivion.esm",
        r"OblivionRemastered\Content\Dev\ObvData\Data\Oblivion.esm",
    ),
    (
        "global.utoc",
        r"OblivionRemastered\Content\Paks\global.utoc",
    ),
    (
        "global.ucas",
        r"OblivionRemastered\Content\Paks\global.ucas",
    ),
    (
        "main UTOC",
        r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.utoc",
    ),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GameInstall {
    pub valid: bool,
    pub source: String,
    pub root: PathBuf,
    pub missing: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub version: u32,
    pub game_root: PathBuf,
    pub output_parent: PathBuf,
    pub connected_tools: Vec<PathBuf>,
    pub saved_at: String,
}

pub fn settings_path() -> PathBuf {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    base.join("OBRModUpdater").join("settings-native.json")
}

pub fn load_settings() -> Option<Settings> {
    let text = fs::read_to_string(settings_path()).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save_settings_with_tools(
    game_root: &Path,
    output_parent: &Path,
    connected_tools: &[PathBuf],
) -> Result<()> {
    let path = settings_path();
    fs::create_dir_all(path.parent().context("settings path has no parent")?)?;
    let settings = Settings {
        version: 2,
        game_root: game_root.to_path_buf(),
        output_parent: output_parent.to_path_buf(),
        connected_tools: connected_tools.to_vec(),
        saved_at: chrono::Utc::now().to_rfc3339(),
    };
    fs::write(&path, serde_json::to_vec_pretty(&settings)?)
        .with_context(|| format!("writing settings {}", path.display()))
}

pub fn save_settings(game_root: &Path, output_parent: &Path) -> Result<()> {
    let connected_tools = load_settings()
        .map(|settings| settings.connected_tools)
        .unwrap_or_default();
    save_settings_with_tools(game_root, output_parent, &connected_tools)
}

pub fn normalize_install_root(path: &Path) -> PathBuf {
    let mut full = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let display = full.to_string_lossy();
    if let Some(value) = display.strip_prefix(r"\\?\UNC\") {
        full = PathBuf::from(format!(r"\\{value}"));
    } else if let Some(value) = display.strip_prefix(r"\\?\") {
        full = PathBuf::from(value);
    }
    if full
        .join(r"Binaries\Win64\OblivionRemastered-Win64-Shipping.exe")
        .is_file()
        && let Some(parent) = full.parent()
    {
        full = parent.to_path_buf();
    }
    full
}

pub fn validate_game_install(path: &Path, source: impl Into<String>) -> GameInstall {
    let root = normalize_install_root(path);
    let missing = REQUIRED_GAME_FILES
        .iter()
        .filter(|(_, relative)| !root.join(relative).is_file())
        .map(|(_, relative)| (*relative).to_owned())
        .collect::<Vec<_>>();
    GameInstall {
        valid: missing.is_empty(),
        source: source.into(),
        root,
        missing,
    }
}

fn add_candidate(
    rows: &mut Vec<(PathBuf, String)>,
    seen: &mut HashSet<String>,
    path: impl Into<PathBuf>,
    source: &str,
) {
    let path = normalize_install_root(&path.into());
    let key = path.to_string_lossy().to_lowercase();
    if !key.is_empty() && seen.insert(key) {
        rows.push((path, source.to_owned()));
    }
}

fn registry_string(root: *mut std::ffi::c_void, key: &str, value: &str) -> Option<String> {
    RegKey::predef(root)
        .open_subkey(key)
        .ok()?
        .get_value::<String, _>(value)
        .ok()
}

fn push_unique_path(roots: &mut Vec<PathBuf>, seen: &mut HashSet<String>, path: PathBuf) {
    let key = path.to_string_lossy().to_lowercase();
    if seen.insert(key) {
        roots.push(path);
    }
}

fn steam_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    if let Some(value) = env::var_os("ProgramFiles(x86)") {
        push_unique_path(&mut roots, &mut seen, PathBuf::from(value).join("Steam"));
    }
    if let Some(value) = env::var_os("ProgramFiles") {
        push_unique_path(&mut roots, &mut seen, PathBuf::from(value).join("Steam"));
    }
    for (root, key) in [
        (HKEY_CURRENT_USER, r"Software\Valve\Steam"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam"),
    ] {
        for value in ["SteamPath", "InstallPath"] {
            if let Some(path) = registry_string(root, key, value) {
                push_unique_path(&mut roots, &mut seen, PathBuf::from(path));
            }
        }
    }
    let path_re = Regex::new(r#""path"\s+"([^"]+)""#).expect("valid Steam VDF regex");
    let initial = roots.clone();
    for steam_root in initial {
        let vdf = steam_root.join(r"steamapps\libraryfolders.vdf");
        if let Ok(text) = fs::read_to_string(vdf) {
            for captures in path_re.captures_iter(&text) {
                push_unique_path(
                    &mut roots,
                    &mut seen,
                    PathBuf::from(captures[1].replace(r"\\", r"\")),
                );
            }
        }
    }
    roots
}

fn add_uninstall_candidates(rows: &mut Vec<(PathBuf, String)>, seen: &mut HashSet<String>) {
    for (root, path) in [
        (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ] {
        let Ok(key) = RegKey::predef(root).open_subkey(path) else {
            continue;
        };
        for name in key.enum_keys().flatten() {
            let Ok(app) = key.open_subkey(name) else {
                continue;
            };
            let display = app
                .get_value::<String, _>("DisplayName")
                .unwrap_or_default();
            if !display.to_lowercase().contains("oblivion")
                || !display.to_lowercase().contains("remastered")
            {
                continue;
            }
            if let Ok(location) = app.get_value::<String, _>("InstallLocation") {
                add_candidate(
                    rows,
                    seen,
                    PathBuf::from(location),
                    "installed-app registry",
                );
            }
        }
    }
}

pub fn find_game_installs(hint: Option<&Path>) -> Vec<GameInstall> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    if let Some(path) = hint {
        add_candidate(&mut candidates, &mut seen, path, "hint");
    }
    if let Some(path) = env::var_os("OBLIVION_REMASTERED_ROOT") {
        add_candidate(
            &mut candidates,
            &mut seen,
            PathBuf::from(path),
            "environment",
        );
    }
    if let Some(settings) = load_settings() {
        add_candidate(
            &mut candidates,
            &mut seen,
            settings.game_root,
            "saved preference",
        );
    }
    let install_re = Regex::new(r#""installdir"\s+"([^"]+)""#).expect("valid ACF regex");
    for steam_root in steam_roots() {
        let steam_apps = steam_root.join("steamapps");
        let manifest = steam_apps.join("appmanifest_2623190.acf");
        if let Ok(text) = fs::read_to_string(manifest)
            && let Some(capture) = install_re.captures(&text)
        {
            add_candidate(
                &mut candidates,
                &mut seen,
                steam_apps.join("common").join(&capture[1]),
                "Steam app manifest",
            );
        }
        add_candidate(
            &mut candidates,
            &mut seen,
            steam_apps.join(r"common\Oblivion Remastered"),
            "Steam library",
        );
    }
    add_uninstall_candidates(&mut candidates, &mut seen);
    for drive in b'C'..=b'Z' {
        let root = PathBuf::from(format!("{}:\\", drive as char));
        if !root.exists() {
            continue;
        }
        for relative in [
            r"SteamLibrary\steamapps\common\Oblivion Remastered",
            r"Program Files (x86)\Steam\steamapps\common\Oblivion Remastered",
            r"Program Files\Steam\steamapps\common\Oblivion Remastered",
            r"XboxGames\The Elder Scrolls IV- Oblivion Remastered\Content",
            r"XboxGames\Oblivion Remastered\Content",
            r"Games\Oblivion Remastered",
            r"Oblivion Remastered",
        ] {
            add_candidate(
                &mut candidates,
                &mut seen,
                root.join(relative),
                "bounded drive probe",
            );
        }
    }
    candidates
        .into_iter()
        .map(|(path, source)| validate_game_install(&path, source))
        .filter(|result| result.valid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_inner_project_directory() {
        let temp = tempfile::tempdir().unwrap();
        let inner = temp.path().join("OblivionRemastered");
        for (_, relative) in REQUIRED_GAME_FILES {
            let file = temp.path().join(relative);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, b"fixture").unwrap();
        }
        let result = validate_game_install(&inner, "test");
        assert!(result.valid, "{:?}", result.missing);
        assert_eq!(result.root, temp.path());
    }
}
