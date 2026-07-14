#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> Result<(), slint::PlatformError> {
    obr_mod_updater::updater::run_app()
}
