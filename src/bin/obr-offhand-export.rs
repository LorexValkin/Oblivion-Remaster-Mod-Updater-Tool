use anyhow::{Result, bail};
use obr_mod_updater::offhand_export::{OffhandExportRequest, run_offhand_export};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

const USAGE: &str = "Usage:\n  obr-offhand-export --source-utoc <path> --game <path> --output <directory>\n\nBuilds the pinned Staff A native-physics/material repair candidate. The source\nUTOC must be the audited physics-working donor; the game folder supplies the\ncurrent MIC package ID and global IoStore metadata. Outputs are candidates and\nare not marked runtime-verified by this command.";

#[derive(Default)]
struct Arguments {
    source_utoc: Option<PathBuf>,
    game_root: Option<PathBuf>,
    output_directory: Option<PathBuf>,
}

fn take_value(
    values: &mut impl Iterator<Item = OsString>,
    flag: &str,
    slot: &mut Option<PathBuf>,
) -> Result<()> {
    if slot.is_some() {
        bail!("{flag} was supplied more than once");
    }
    let value = values
        .next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a path"))?;
    *slot = Some(PathBuf::from(value));
    Ok(())
}

fn parse_arguments() -> Result<Option<Arguments>> {
    let mut parsed = Arguments::default();
    let mut values = env::args_os().skip(1);
    while let Some(argument) = values.next() {
        match argument.to_str() {
            Some("--help" | "-h") => return Ok(None),
            Some("--source-utoc") => {
                take_value(&mut values, "--source-utoc", &mut parsed.source_utoc)?
            }
            Some("--game") => take_value(&mut values, "--game", &mut parsed.game_root)?,
            Some("--output") => take_value(&mut values, "--output", &mut parsed.output_directory)?,
            Some(flag) => bail!("unknown argument: {flag}\n\n{USAGE}"),
            None => bail!("argument names must be valid Unicode\n\n{USAGE}"),
        }
    }
    Ok(Some(parsed))
}

fn required(value: Option<PathBuf>, flag: &str) -> Result<PathBuf> {
    value.ok_or_else(|| anyhow::anyhow!("missing {flag}\n\n{USAGE}"))
}

fn run() -> Result<()> {
    let Some(arguments) = parse_arguments()? else {
        println!("{USAGE}");
        return Ok(());
    };
    let outcome = run_offhand_export(OffhandExportRequest {
        source_utoc: required(arguments.source_utoc, "--source-utoc")?,
        game_root: required(arguments.game_root, "--game")?,
        output_directory: required(arguments.output_directory, "--output")?,
    })?;
    println!("{}", serde_json::to_string_pretty(&outcome)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("offhand export failed: {error:#}");
        std::process::exit(1);
    }
}
