use crate::dependencies::{DependencyKind, installed_state, scan_dependencies};
use crate::engine::{UpdateOutcome, UpdateRequest, run_update};
use crate::game::{
    find_game_installs, load_settings, save_settings_with_tools, validate_game_install,
};
use crate::modlist::{ModlistRequest, run_modlist_update};
use crate::preflight::{
    PreflightRequest, analyze_with_progress, human_summary, stable_signature, write_report,
};
use crate::replacement::{ARMOR_REPLACEMENT_ADAPTER, TEXTURE_REPLACEMENT_ADAPTER};
use slint::ComponentHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};

slint::include_modules!();

const KOFI_URL: &str = "https://ko-fi.com/lorex_";

#[derive(Clone, Copy)]
enum Tone {
    Neutral = 0,
    Success = 1,
    Warning = 2,
    Error = 3,
}

#[derive(Default)]
struct AppState {
    dependency_inputs: Vec<PathBuf>,
    last_output: Option<PathBuf>,
    last_report: Option<PathBuf>,
    last_preflight_signature: Option<String>,
}

enum WorkflowCompletion {
    Candidate(UpdateOutcome),
    ReportOnly {
        status: String,
        signature: String,
        report_path: PathBuf,
    },
}

type SharedState = Arc<Mutex<AppState>>;

fn state(state: &SharedState) -> MutexGuard<'_, AppState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn desktop_folder() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|directories| directories.desktop_dir().map(Path::to_path_buf))
        .unwrap_or_else(std::env::temp_dir)
}

fn set_status(app: &AppWindow, title: &str, message: &str, tone: Tone) {
    app.set_status_title(title.into());
    app.set_status_message(message.into());
    app.set_status_tone(tone as i32);
}

fn append_log_line(log: &mut String, line: &str) {
    if !log.is_empty() {
        log.push('\n');
    }
    log.push_str(line);
}

fn publish_live_step(
    weak: &slint::Weak<AppWindow>,
    log: &mut String,
    line: &str,
    progress: i32,
    status_message: &str,
) {
    append_log_line(log, line);
    let weak = weak.clone();
    let log_snapshot = log.clone();
    let status_message = status_message.to_owned();
    let live_warning = if status_message.starts_with("[UNSUPPORTED]")
        || status_message.starts_with("[INCOMPLETE]")
    {
        Some(status_message.clone())
    } else {
        None
    };
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(app) = weak.upgrade() {
            app.set_progress(progress);
            app.set_status_message(status_message.into());
            app.set_log_text(log_snapshot.into());
            if let Some(live_warning) = live_warning {
                app.set_live_warning(live_warning.into());
            }
        }
    });
}

fn invalidate_preflight(app: &AppWindow) {
    app.set_preflight_ready(false);
    app.set_preflight_status(
        "Safety checks will run automatically when Analyze & update starts.".into(),
    );
}

fn leaf(path: &str) -> String {
    Path::new(path.trim())
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("(not selected)")
        .to_owned()
}

fn persist_setup(app: &AppWindow, shared: &SharedState) {
    let game = PathBuf::from(app.get_game_path().as_str().trim());
    let output = PathBuf::from(app.get_output_path().as_str().trim());
    let tools = state(shared).dependency_inputs.clone();
    let _ = save_settings_with_tools(&game, &output, &tools);
}

fn runtime_tools_install_root(game_root: &Path) -> PathBuf {
    game_root.join(r"OblivionRemastered\Binaries\Win64")
}

fn validate_game_path(app: &AppWindow) {
    let raw = app.get_game_path().to_string();
    if raw.trim().is_empty() {
        app.set_game_valid(false);
        app.set_runtime_tools_path("Choose a valid game folder to show the install path.".into());
        app.set_game_tone(Tone::Warning as i32);
        app.set_game_status(
            "The game was not found automatically. Choose its installation folder.".into(),
        );
        return;
    }

    let game = validate_game_install(Path::new(raw.trim()), "Slint UI");
    app.set_game_valid(game.valid);
    if game.valid {
        app.set_game_path(game.root.to_string_lossy().into_owned().into());
        app.set_runtime_tools_path(
            runtime_tools_install_root(&game.root)
                .to_string_lossy()
                .into_owned()
                .into(),
        );
        app.set_game_tone(Tone::Success as i32);
        app.set_game_status(
            "Game found and validated. Required ESM and Unreal containers are present.".into(),
        );
    } else {
        app.set_runtime_tools_path("Choose a valid game folder to show the install path.".into());
        app.set_game_tone(Tone::Error as i32);
        app.set_game_status(
            format!(
                "Incomplete game folder. Missing: {}",
                game.missing.join(", ")
            )
            .into(),
        );
    }
}

fn refresh_dependencies(app: &AppWindow, shared: &SharedState, include_nearby: bool) {
    let mod_path = app.get_mod_path().to_string();
    if mod_path.trim().is_empty() {
        app.set_runtime_tools_status(
            "Runtime tools will be checked after you choose a mod.".into(),
        );
        app.set_runtime_tools_tone(Tone::Neutral as i32);
        return;
    }
    if !include_nearby {
        app.set_runtime_tools_status(
            "Connection payloads will be content-validated by the next bounded preflight.".into(),
        );
        app.set_runtime_tools_tone(Tone::Neutral as i32);
        return;
    }
    if !include_nearby {
        app.set_runtime_tools_status(
            "Connection payloads will be content-validated by the next bounded preflight.".into(),
        );
        app.set_runtime_tools_tone(Tone::Neutral as i32);
        return;
    }

    let game = validate_game_install(
        Path::new(app.get_game_path().as_str().trim()),
        "Slint UI dependency check",
    );
    if !game.valid {
        app.set_runtime_tools_status(
            "Choose a valid game folder before runtime tools can be checked.".into(),
        );
        app.set_runtime_tools_tone(Tone::Warning as i32);
        return;
    }

    let installed = installed_state(&game.root);
    if installed.ue4ss.installed && installed.tes_sync_map_injector.installed {
        app.set_runtime_tools_status("Installed: UE4SS and TesSyncMapInjector are ready.".into());
        app.set_runtime_tools_tone(Tone::Success as i32);
        return;
    }

    let attached = state(shared).dependency_inputs.clone();
    let near_path = include_nearby.then(|| Path::new(mod_path.trim()));
    let candidates = scan_dependencies(&attached, near_path);
    let mut missing = Vec::new();
    if !installed.ue4ss.installed
        && !candidates
            .iter()
            .any(|candidate| candidate.kinds.contains(&DependencyKind::UE4SS))
    {
        missing.push("UE4SS");
    }
    if !installed.tes_sync_map_injector.installed
        && !candidates.iter().any(|candidate| {
            candidate
                .kinds
                .contains(&DependencyKind::TesSyncMapInjector)
        })
    {
        missing.push("TesSyncMapInjector");
    }

    if missing.is_empty() {
        app.set_runtime_tools_status(
            "Required tools were found nearby and will be installed with backups.".into(),
        );
        app.set_runtime_tools_tone(Tone::Warning as i32);
    } else {
        app.set_runtime_tools_status(
            format!(
                "Not connected: {}. If requested, use Add archives or Add folder below.",
                missing.join(", ")
            )
            .into(),
        );
        app.set_runtime_tools_tone(Tone::Warning as i32);
    }
}

fn diagnostic(app: &AppWindow, shared: &SharedState) -> String {
    let mut log = app.get_log_text().to_string();
    for (value, replacement) in [
        (app.get_mod_path().to_string(), "<MOD_INPUT>"),
        (app.get_game_path().to_string(), "<GAME_ROOT>"),
        (app.get_output_path().to_string(), "<OUTPUT_ROOT>"),
    ] {
        if !value.trim().is_empty() {
            log = log.replace(value.trim(), replacement);
        }
    }
    let report = state(shared)
        .last_report
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("(none)")
        .to_owned();
    format!(
        "OBR Mod Updater native diagnostic\nVersion: {}\nStatus: {}\nDetails: {}\nMod: {}\nGame connected: {}\nLast shareable report: {}\nAbsolute setup paths: redacted\nRuntime verification: not claimed\n\nUpdater log:\n{}",
        env!("CARGO_PKG_VERSION"),
        app.get_status_title(),
        app.get_status_message(),
        leaf(app.get_mod_path().as_str()),
        app.get_game_valid(),
        report,
        if log.trim().is_empty() {
            "(No raw updater output has been produced yet.)"
        } else {
            log.trim()
        }
    )
}

fn configure_initial_state(app: &AppWindow, shared: &SharedState) {
    let settings = load_settings();
    if let Some(settings) = &settings {
        state(shared).dependency_inputs = settings
            .connected_tools
            .iter()
            .filter(|path| path.exists())
            .cloned()
            .collect();
    }
    let game_root = find_game_installs(None)
        .into_iter()
        .next()
        .map(|game| game.root)
        .or_else(|| settings.as_ref().map(|value| value.game_root.clone()));
    if let Some(game_root) = game_root {
        app.set_game_path(game_root.to_string_lossy().into_owned().into());
    }
    validate_game_path(app);

    let output = settings
        .as_ref()
        .filter(|value| value.output_parent.is_dir())
        .map(|value| value.output_parent.clone())
        .unwrap_or_else(desktop_folder);
    app.set_output_path(output.to_string_lossy().into_owned().into());
    let connected = state(shared).dependency_inputs.len();
    app.set_connected_tools_status(
        format!(
            "Built in: retoc + UAssetGUI. {} external dependency source(s) saved.",
            connected
        )
        .into(),
    );
}

fn register_callbacks(app: &AppWindow, shared: &SharedState) {
    {
        let weak = app.as_weak();
        app.on_open_kofi(move || {
            if let Err(error) = Command::new("rundll32.exe")
                .args(["url.dll,FileProtocolHandler", KOFI_URL])
                .spawn()
            {
                if let Some(app) = weak.upgrade() {
                    set_status(
                        &app,
                        "Could not open Ko-fi",
                        &format!("Default browser error: {error}"),
                        Tone::Error,
                    );
                }
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_choose_archive(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Choose an Oblivion Remastered mod archive")
                .add_filter("Mod archives", &["zip", "7z", "rar"])
                .pick_file()
            {
                app.set_mod_path(path.to_string_lossy().into_owned().into());
                set_status(
                    &app,
                    "Mod selected",
                    "The selected archive is ready for the updater safety checks.",
                    Tone::Neutral,
                );
                invalidate_preflight(&app);
                refresh_dependencies(&app, &shared, true);
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_choose_mod_folder(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Choose the extracted mod folder")
                .pick_folder()
            {
                app.set_mod_path(path.to_string_lossy().into_owned().into());
                set_status(
                    &app,
                    "Mod selected",
                    "The selected folder is ready for the updater safety checks.",
                    Tone::Neutral,
                );
                invalidate_preflight(&app);
                refresh_dependencies(&app, &shared, true);
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_mod_path_edited(move || {
            if let Some(app) = weak.upgrade() {
                invalidate_preflight(&app);
                refresh_dependencies(&app, &shared, false);
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_attach_tools(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if let Some(paths) = rfd::FileDialog::new()
                .set_title("Attach body compatibility and/or runtime dependency archives")
                .add_filter("Dependency archives", &["zip", "7z", "rar"])
                .pick_files()
            {
                let mut shared_state = state(&shared);
                for path in paths {
                    if !shared_state.dependency_inputs.contains(&path) {
                        shared_state.dependency_inputs.push(path);
                    }
                }
                drop(shared_state);
                let connected = state(&shared).dependency_inputs.len();
                app.set_connected_tools_status(
                    format!(
                        "Built in: retoc + UAssetGUI. {} external dependency source(s) connected.",
                        connected
                    )
                    .into(),
                );
                invalidate_preflight(&app);
                persist_setup(&app, &shared);
                refresh_dependencies(&app, &shared, true);
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_attach_tool_folder(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Connect an extracted body or runtime dependency folder")
                .pick_folder()
            {
                let mut shared_state = state(&shared);
                if !shared_state.dependency_inputs.contains(&path) {
                    shared_state.dependency_inputs.push(path);
                }
                let connected = shared_state.dependency_inputs.len();
                drop(shared_state);
                app.set_connected_tools_status(
                    format!(
                        "Built in: retoc + UAssetGUI. {} external dependency source(s) connected.",
                        connected
                    )
                    .into(),
                );
                invalidate_preflight(&app);
                persist_setup(&app, &shared);
                refresh_dependencies(&app, &shared, true);
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_clear_tools(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            state(&shared).dependency_inputs.clear();
            app.set_connected_tools_status(
                "Built in: retoc + UAssetGUI. No external dependency sources saved.".into(),
            );
            invalidate_preflight(&app);
            persist_setup(&app, &shared);
            refresh_dependencies(&app, &shared, true);
            set_status(
                &app,
                "Dependency connections cleared",
                "Installed dependencies are unchanged. Connect archives or folders again if the selected adapter requires them.",
                Tone::Neutral,
            );
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_find_game(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            set_status(
                &app,
                "Searching for the game",
                "Checking Steam libraries and installed-application records.",
                Tone::Neutral,
            );
            if let Some(game) = find_game_installs(None).into_iter().next() {
                app.set_game_path(game.root.to_string_lossy().into_owned().into());
                validate_game_path(&app);
                set_status(
                    &app,
                    "Game found",
                    "Required ESM and Unreal containers are present.",
                    Tone::Success,
                );
                invalidate_preflight(&app);
                refresh_dependencies(&app, &shared, true);
            } else {
                app.set_game_valid(false);
                app.set_game_tone(Tone::Warning as i32);
                app.set_game_status(
                    "Automatic discovery could not find the game. Choose its folder manually."
                        .into(),
                );
                set_status(
                    &app,
                    "Game not found",
                    "Choose the folder where Oblivion Remastered is installed.",
                    Tone::Warning,
                );
                invalidate_preflight(&app);
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_choose_game_folder(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Choose the Oblivion Remastered installation folder")
                .pick_folder()
            {
                app.set_game_path(path.to_string_lossy().into_owned().into());
                validate_game_path(&app);
                invalidate_preflight(&app);
                refresh_dependencies(&app, &shared, true);
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_game_path_edited(move || {
            if let Some(app) = weak.upgrade() {
                validate_game_path(&app);
                invalidate_preflight(&app);
                refresh_dependencies(&app, &shared, false);
            }
        });
    }

    {
        let weak = app.as_weak();
        app.on_choose_output_folder(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Choose where updated mods should be saved")
                .pick_folder()
            {
                app.set_output_path(path.to_string_lossy().into_owned().into());
                invalidate_preflight(&app);
            }
        });
    }

    {
        let weak = app.as_weak();
        app.on_output_path_edited(move || {
            if let Some(app) = weak.upgrade() {
                invalidate_preflight(&app);
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_copy_log(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            match arboard::Clipboard::new()
                .and_then(|mut clipboard| clipboard.set_text(diagnostic(&app, &shared)))
            {
                Ok(()) => set_status(
                    &app,
                    "Log copied",
                    "The complete diagnostic is on the clipboard.",
                    Tone::Success,
                ),
                Err(error) => set_status(
                    &app,
                    "Could not copy the log",
                    &format!("Clipboard error: {error}"),
                    Tone::Error,
                ),
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_open_report(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            let report = state(&shared).last_report.clone();
            let Some(report) = report else {
                set_status(
                    &app,
                    "No report yet",
                    "Run Analyze & update to create a shareable JSON report.",
                    Tone::Warning,
                );
                return;
            };
            let folder = report.parent().unwrap_or(&report);
            if let Err(error) = Command::new("explorer.exe").arg(folder).spawn() {
                set_status(
                    &app,
                    "Could not open report folder",
                    &format!("Windows Explorer error: {error}"),
                    Tone::Error,
                );
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_open_output(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            let output = state(&shared).last_output.clone();
            let Some(output) = output else {
                set_status(
                    &app,
                    "No completed output",
                    "Run the updater successfully before opening its output.",
                    Tone::Warning,
                );
                return;
            };
            if let Err(error) = Command::new("explorer.exe").arg(&output).spawn() {
                set_status(
                    &app,
                    "Could not open output",
                    &format!("Windows Explorer error: {error}"),
                    Tone::Error,
                );
            }
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_fix_modlist(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if app.get_update_running() {
                return;
            }
            if !app.get_modlist_warning_visible() || !app.get_modlist_risk_accepted() {
                set_status(
                    &app,
                    "Risk acknowledgement required",
                    "Use Fix installed modlist and accept the warning before starting the batch overwrite.",
                    Tone::Error,
                );
                return;
            }
            let request = ModlistRequest {
                game_root: PathBuf::from(app.get_game_path().as_str().trim()),
                backup_parent: PathBuf::from(app.get_output_path().as_str().trim()),
                dependency_inputs: state(&shared).dependency_inputs.clone(),
            };
            let game = validate_game_install(&request.game_root, "Slint UI modlist request");
            if !game.valid {
                app.set_game_valid(false);
                set_status(
                    &app,
                    "Game folder required",
                    &format!("Missing: {}", game.missing.join(", ")),
                    Tone::Error,
                );
                return;
            }
            if !request.backup_parent.is_dir() {
                set_status(
                    &app,
                    "Backup folder required",
                    "Choose an existing output folder for the original mod backups and batch report.",
                    Tone::Error,
                );
                return;
            }
            app.set_modlist_warning_visible(false);
            app.set_modlist_risk_accepted(false);
            persist_setup(&app, &shared);
            {
                let mut app_state = state(&shared);
                app_state.last_output = None;
                app_state.last_report = None;
                app_state.last_preflight_signature = None;
            }
            app.set_update_running(true);
            app.set_update_complete(false);
            app.set_preflight_ready(false);
            app.set_last_report_path("".into());
            app.set_preflight_status("Scanning installed ~mods containers.".into());
            app.set_progress(0);
            app.set_live_warning("".into());
            app.set_log_text(
                "[modlist] RISK ACKNOWLEDGED: eligible installed containers will be backed up, rebuilt, and overwritten.\n[modlist] START: scanning the game ~mods directory."
                    .into(),
            );
            set_status(
                &app,
                "Fixing installed modlist",
                "Scanning every container set. Unsupported or ambiguous mods will be left untouched.",
                Tone::Warning,
            );

            let weak = app.as_weak();
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                let mut log = "[modlist] RISK ACKNOWLEDGED: eligible installed containers will be backed up, rebuilt, and overwritten.\n[modlist] START: scanning the game ~mods directory.".to_owned();
                let result = run_modlist_update(request, &mut |step, total, message| {
                    let progress = if total == 0 {
                        0
                    } else {
                        ((step.saturating_mul(100) / total).min(100)) as i32
                    };
                    publish_live_step(
                        &weak,
                        &mut log,
                        &format!("[modlist {step}/{total}] {message}"),
                        progress,
                        message,
                    );
                });
                match result {
                    Ok(outcome) => {
                        {
                            let mut app_state = state(&shared);
                            app_state.last_output = Some(outcome.backup_directory.clone());
                            app_state.last_report = Some(outcome.report_path.clone());
                        }
                        append_log_line(
                            &mut log,
                            &format!(
                                "[modlist] COMPLETE: scanned={} updated={} already-converted={} unsupported={} skipped={} failed={}",
                                outcome.scanned,
                                outcome.updated,
                                outcome.already_converted,
                                outcome.unsupported,
                                outcome.skipped,
                                outcome.failed
                            ),
                        );
                        append_log_line(
                            &mut log,
                            &format!("[modlist] BACKUP: {}", outcome.backup_directory.display()),
                        );
                        append_log_line(
                            &mut log,
                            &format!("[modlist] REPORT: {}", outcome.report_path.display()),
                        );
                        let report_display = outcome.report_path.display().to_string();
                        let tone = if outcome.failed > 0 || outcome.skipped > 0 {
                            Tone::Warning
                        } else {
                            Tone::Success
                        };
                        let title = if outcome.failed > 0 {
                            "Modlist finished with errors"
                        } else if outcome.updated > 0 && outcome.unsupported > 0 {
                            "Supported mods updated"
                        } else if outcome.updated > 0 {
                            "Installed modlist updated"
                        } else if outcome.already_converted > 0 {
                            "Installed modlist already current"
                        } else {
                            "Modlist analysis complete"
                        };
                        let message = format!(
                            "{} updated, {} already converted for this game, {} unsupported, {} total skipped, {} failed. Unsupported mods were left unchanged and did not stop eligible updates.",
                            outcome.updated,
                            outcome.already_converted,
                            outcome.unsupported,
                            outcome.skipped,
                            outcome.failed
                        );
                        let weak = weak.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak.upgrade() {
                                app.set_progress(100);
                                app.set_update_running(false);
                                app.set_update_complete(true);
                                app.set_preflight_ready(false);
                                app.set_preflight_status(
                                    format!(
                                        "Batch complete: {} updated, {} already converted, {} unsupported, {} total skipped, {} failed.",
                                        outcome.updated,
                                        outcome.already_converted,
                                        outcome.unsupported,
                                        outcome.skipped,
                                        outcome.failed
                                    )
                                    .into(),
                                );
                                if outcome.unsupported > 0 {
                                    app.set_live_warning(
                                        format!(
                                            "UNSUPPORTED: {} mod container(s) left unchanged; eligible mods continued.",
                                            outcome.unsupported
                                        )
                                        .into(),
                                    );
                                } else if outcome.skipped > 0 {
                                    app.set_live_warning(
                                        format!(
                                            "SKIPPED: {} ineligible container set(s) left unchanged.",
                                            outcome.skipped
                                        )
                                        .into(),
                                    );
                                } else {
                                    app.set_live_warning("".into());
                                }
                                app.set_last_report_path(report_display.into());
                                app.set_log_text(log.into());
                                set_status(&app, title, &message, tone);
                            }
                        });
                    }
                    Err(error) => {
                        append_log_line(&mut log, &format!("[modlist] ERROR: {error:#}"));
                        let weak = weak.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak.upgrade() {
                                app.set_update_running(false);
                                app.set_update_complete(false);
                                app.set_preflight_ready(false);
                                app.set_preflight_status(
                                    "Batch workflow stopped. Review the live output and backup folder."
                                        .into(),
                                );
                                app.set_log_text(log.into());
                                set_status(
                                    &app,
                                    "Modlist workflow stopped",
                                    "Review the log before launching the game. If any earlier item completed, its original is in the timestamped backup folder.",
                                    Tone::Error,
                                );
                            }
                        });
                    }
                }
            });
        });
    }

    {
        let weak = app.as_weak();
        let shared = Arc::clone(shared);
        app.on_update_mod(move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if app.get_update_running() {
                return;
            }

            let request = UpdateRequest {
                adapter: String::new(),
                mod_input: PathBuf::from(app.get_mod_path().as_str().trim()),
                game_root: PathBuf::from(app.get_game_path().as_str().trim()),
                output_parent: PathBuf::from(app.get_output_path().as_str().trim()),
                dependency_inputs: state(&shared).dependency_inputs.clone(),
                installed_collision_exclusions: Vec::new(),
                persist_settings: true,
            };
            if !request.mod_input.exists() {
                set_status(
                    &app,
                    "Choose a mod",
                    "The selected archive or folder does not exist.",
                    Tone::Error,
                );
                return;
            }
            let game = validate_game_install(&request.game_root, "Slint UI update request");
            if !game.valid {
                app.set_game_valid(false);
                set_status(
                    &app,
                    "Game folder required",
                    &format!("Missing: {}", game.missing.join(", ")),
                    Tone::Error,
                );
                return;
            }
            if !request.output_parent.is_dir() {
                set_status(
                    &app,
                    "Output folder required",
                    "Choose an existing output folder.",
                    Tone::Error,
                );
                return;
            }
            persist_setup(&app, &shared);

            {
                let mut app_state = state(&shared);
                app_state.last_output = None;
                app_state.last_report = None;
                app_state.last_preflight_signature = None;
            }
            app.set_update_running(true);
            app.set_update_complete(false);
            app.set_preflight_ready(false);
            app.set_last_report_path("".into());
            app.set_preflight_status("Automatic safety checks are running.".into());
            app.set_progress(2);
            app.set_live_warning("".into());
            app.set_log_text(
                "[workflow] START: automatic preflight will continue into update only if every gate passes."
                    .into(),
            );
            set_status(
                &app,
                "Analyzing & updating",
                "Starting automatic safety checks. The original mod and game remain read-only.",
                Tone::Neutral,
            );

            let weak = app.as_weak();
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                let mut log = "[workflow] START: automatic preflight will continue into update only if every gate passes.".to_owned();
                let result = (|| -> Result<WorkflowCompletion, String> {
                    let mut request = request;
                    let preflight_request = PreflightRequest {
                        mod_input: request.mod_input.clone(),
                        game_root: Some(request.game_root.clone()),
                        output_parent: Some(request.output_parent.clone()),
                        connected_tools: request.dependency_inputs.clone(),
                    };
                    let mut preflight_step = 0_i32;
                    let report = analyze_with_progress(
                        &preflight_request,
                        &mut |message| {
                            preflight_step += 1;
                            let progress = (2 + preflight_step * 3).min(18);
                            publish_live_step(
                                &weak,
                                &mut log,
                                &format!("[preflight step {preflight_step}] {message}"),
                                progress,
                                message,
                            );
                        },
                    );
                    publish_live_step(
                        &weak,
                        &mut log,
                        &format!(
                            "[preflight] COMPLETE: status={} canUpdate={}",
                            report.status, report.can_update
                        ),
                        18,
                        "Writing the shareable preflight report",
                    );
                    let summary = human_summary(&report);
                    let signature = stable_signature(&report);
                    let report_path = write_report(&report, &request.output_parent)
                        .map_err(|error| format!("{error:#}"))?;
                    {
                        let mut app_state = state(&shared);
                        app_state.last_report = Some(report_path.clone());
                        app_state.last_preflight_signature = Some(signature.clone());
                    }
                    let report_display = report_path.display().to_string();
                    publish_live_step(
                        &weak,
                        &mut log,
                        &format!("[report] SAVED: {report_display}"),
                        20,
                        "Preflight report saved",
                    );
                    if !report.can_update {
                        append_log_line(&mut log, &summary);
                        append_log_line(
                            &mut log,
                            &format!(
                                "[workflow] STOP: no proven adapter passed every gate ({signature})"
                            ),
                        );
                        return Ok(WorkflowCompletion::ReportOnly {
                            status: report.status,
                            signature,
                            report_path,
                        });
                    }
                    request.adapter = report.selected_adapter.clone().ok_or_else(|| {
                        "fresh preflight passed without selecting an update adapter".to_owned()
                    })?;
                    publish_live_step(
                        &weak,
                        &mut log,
                        &format!(
                            "[preflight] PASS: selected adapter {} ({signature})",
                            request.adapter
                        ),
                        20,
                        "All safety gates passed; continuing automatically",
                    );
                    {
                        let weak = weak.clone();
                        let status = report.status.clone();
                        let signature = signature.clone();
                        let report_display = report_display.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak.upgrade() {
                                app.set_preflight_ready(true);
                                app.set_preflight_status(
                                    format!("{status}. Stable signature: {signature}").into(),
                                );
                                app.set_last_report_path(report_display.into());
                            }
                        });
                    }
                    let outcome = run_update(request, &mut |step, total, message| {
                        let progress = 20 + ((step * 80) / total) as i32;
                        publish_live_step(
                            &weak,
                            &mut log,
                            &format!("[update {step}/{total}] {message}"),
                            progress,
                            message,
                        );
                    })
                    .map_err(|error| format!("{error:#}"))?;
                    Ok(WorkflowCompletion::Candidate(outcome))
                })();

                match result {
                    Ok(WorkflowCompletion::Candidate(outcome)) => {
                        state(&shared).last_output = Some(outcome.output_directory.clone());
                        let weak = weak.clone();
                        append_log_line(
                            &mut log,
                            "[workflow] PASS: native structural update complete",
                        );
                        append_log_line(
                            &mut log,
                            &format!("Candidate: {}", outcome.output_archive.display()),
                        );
                        append_log_line(
                            &mut log,
                            &format!("Report: {}", outcome.report_path.display()),
                        );
                        let message = if outcome.adapter == ARMOR_REPLACEMENT_ADAPTER {
                            format!(
                                "{} armor packages rebuilt; current material/skeleton imports migrated and source export payloads/sidecars preserved. In-game texture testing is still required.",
                                outcome.package_count
                            )
                        } else if outcome.adapter == TEXTURE_REPLACEMENT_ADAPTER {
                            format!(
                                "{} Texture2D packages rebuilt; raw exports plus UEXP/UBULK sidecars were byte-preserved through a verified current-Zen roundtrip. In-game texture and streaming testing is still required.",
                                outcome.package_count
                            )
                        } else {
                            format!(
                                "{} Unreal packages rebuilt; ESP bytes and FormIDs preserved. In-game testing is still required.",
                                outcome.package_count
                            )
                        };
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak.upgrade() {
                                app.set_progress(100);
                                app.set_update_running(false);
                                app.set_update_complete(true);
                                app.set_log_text(log.into());
                                set_status(
                                    &app,
                                    "Candidate created",
                                    &message,
                                    Tone::Success,
                                );
                            }
                        });
                    }
                    Ok(WorkflowCompletion::ReportOnly {
                        status,
                        signature,
                        report_path,
                    }) => {
                        let weak = weak.clone();
                        let report_display = report_path.display().to_string();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak.upgrade() {
                                app.set_progress(100);
                                app.set_update_running(false);
                                app.set_update_complete(false);
                                app.set_preflight_ready(false);
                                app.set_preflight_status(
                                    format!("{status}. Stable signature: {signature}").into(),
                                );
                                app.set_last_report_path(report_display.into());
                                app.set_log_text(log.into());
                                set_status(
                                    &app,
                                    "Analysis complete — update not run",
                                    "The report explains which safety or adapter gate stopped the automatic workflow. No source or game files were changed.",
                                    Tone::Warning,
                                );
                            }
                        });
                    }
                    Err(error) => {
                        let weak = weak.clone();
                        append_log_line(&mut log, &format!("[workflow] ERROR: {error}"));
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak.upgrade() {
                                app.set_update_running(false);
                                app.set_update_complete(false);
                                app.set_preflight_ready(false);
                                app.set_preflight_status(
                                    "Workflow stopped before completion. Review the live output."
                                        .into(),
                                );
                                app.set_log_text(log.into());
                                set_status(
                                    &app,
                                    "Workflow stopped safely",
                                    "No verified candidate was produced. Copy the log and send it with the mod link.",
                                    Tone::Error,
                                );
                            }
                        });
                    }
                }
            });
        });
    }
}

pub fn run_app() -> Result<(), slint::PlatformError> {
    // Keep startup small: the heavier checks begin only after the user chooses an input and asks for a run.
    let app = AppWindow::new()?;
    app.set_application_version(env!("CARGO_PKG_VERSION").into());
    let shared = Arc::new(Mutex::new(AppState::default()));
    configure_initial_state(&app, &shared);
    register_callbacks(&app, &shared);
    app.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_gates_follow_required_ui_state() {
        let app = AppWindow::new().unwrap();
        let shared = Arc::new(Mutex::new(AppState::default()));
        register_callbacks(&app, &shared);
        assert!(!app.get_can_update());
        assert!(!app.get_can_copy_log());
        assert!(!app.get_can_open_output());
        assert!(!app.get_can_open_report());
        assert!(!app.get_can_fix_modlist());
        assert!(app.get_experimental_notice_visible());
        app.set_mod_path("mod.7z".into());
        app.set_game_valid(true);
        app.set_output_path("output".into());
        assert!(!app.get_can_update());
        app.set_experimental_notice_visible(false);
        assert!(app.get_can_update());
        assert!(app.get_can_fix_modlist());

        app.set_modlist_warning_visible(true);
        assert!(!app.get_can_fix_modlist());
        app.set_modlist_warning_visible(false);
        assert!(app.get_can_fix_modlist());

        app.set_update_running(true);
        assert!(!app.get_can_update());
        assert!(!app.get_can_fix_modlist());
        app.set_log_text("diagnostic".into());
        app.set_live_warning("UNSUPPORTED: test".into());
        assert_eq!(app.get_live_warning().as_str(), "UNSUPPORTED: test");
        app.set_update_complete(true);
        app.set_last_report_path("report.json".into());
        assert!(app.get_can_copy_log());
        assert!(app.get_can_open_output());
        assert!(app.get_can_open_report());
    }
}
