use anyhow::{Context, Result, bail};
use obr_mod_updater::preflight::{
    PreflightRequest, analyze, attach_stress, stable_signature, write_report,
};
use std::path::{Path, PathBuf};

const USAGE: &str = "Usage:\n  obr-report --mod <zip|7z|rar|folder> [--game <folder>] [--output <folder|json>] [--tool <archive|folder>]... [--stress-runs <1..100>] [--stdout]\n\nCreates a non-mutating, path-sanitized mod inventory and capability report. Unknown mod types remain report-only. Stress runs repeat the same bounded preflight and record whether its stable signature is deterministic.";

#[derive(Default)]
struct Arguments {
    mod_input: Option<PathBuf>,
    game_root: Option<PathBuf>,
    output: Option<PathBuf>,
    tools: Vec<PathBuf>,
    stress_runs: usize,
    stdout: bool,
}

fn value(values: &[String], index: &mut usize, flag: &str) -> Result<String> {
    *index += 1;
    values
        .get(*index)
        .cloned()
        .with_context(|| format!("{flag} requires a value"))
}

fn parse() -> Result<Option<Arguments>> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.is_empty()
        || values
            .iter()
            .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        println!("{USAGE}");
        return Ok(None);
    }
    let mut result = Arguments {
        stress_runs: 1,
        ..Default::default()
    };
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--mod" => result.mod_input = Some(PathBuf::from(value(&values, &mut index, "--mod")?)),
            "--game" => {
                result.game_root = Some(PathBuf::from(value(&values, &mut index, "--game")?))
            }
            "--output" => {
                result.output = Some(PathBuf::from(value(&values, &mut index, "--output")?))
            }
            "--tool" => result
                .tools
                .push(PathBuf::from(value(&values, &mut index, "--tool")?)),
            "--stress-runs" => {
                result.stress_runs = value(&values, &mut index, "--stress-runs")?.parse()?;
                if !(1..=100).contains(&result.stress_runs) {
                    bail!("--stress-runs must be between 1 and 100");
                }
            }
            "--stdout" => result.stdout = true,
            unknown => bail!("unknown argument: {unknown}\n\n{USAGE}"),
        }
        index += 1;
    }
    if result.mod_input.is_none() {
        bail!("--mod is required\n\n{USAGE}");
    }
    Ok(Some(result))
}

fn report_output_parent(output: Option<&Path>, fallback: &Path) -> PathBuf {
    let Some(output) = output else {
        return fallback.to_path_buf();
    };
    if output
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("json"))
    {
        return output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(fallback)
            .to_path_buf();
    }
    output.to_path_buf()
}

fn run() -> Result<()> {
    let Some(arguments) = parse()? else {
        return Ok(());
    };
    let current_dir = std::env::current_dir()?;
    let request = PreflightRequest {
        mod_input: arguments.mod_input.context("--mod is required")?,
        game_root: arguments.game_root,
        output_parent: Some(report_output_parent(
            arguments.output.as_deref(),
            &current_dir,
        )),
        connected_tools: arguments.tools,
    };
    let mut timings = Vec::with_capacity(arguments.stress_runs);
    let mut signatures = Vec::with_capacity(arguments.stress_runs);
    let mut report = analyze(&request);
    timings.push(report.performance.elapsed_ms);
    signatures.push(stable_signature(&report));
    for _ in 1..arguments.stress_runs {
        let next = analyze(&request);
        timings.push(next.performance.elapsed_ms);
        signatures.push(stable_signature(&next));
        report = next;
    }
    attach_stress(&mut report, arguments.stress_runs, &timings, &signatures);
    if arguments.stdout {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let output = arguments.output.unwrap_or(current_dir);
        let path = write_report(&report, &output)?;
        println!("{}", path.display());
    }
    if !report
        .stress
        .as_ref()
        .is_some_and(|value| value.deterministic)
    {
        bail!("preflight stress signature changed between runs");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_output_uses_its_parent_for_preflight() {
        let fallback = Path::new("fallback");
        assert_eq!(
            report_output_parent(Some(Path::new("reports/result.JSON")), fallback),
            PathBuf::from("reports")
        );
        assert_eq!(
            report_output_parent(Some(Path::new("result.json")), fallback),
            fallback
        );
    }

    #[test]
    fn directory_output_is_unchanged() {
        let fallback = Path::new("fallback");
        assert_eq!(
            report_output_parent(Some(Path::new("reports")), fallback),
            PathBuf::from("reports")
        );
        assert_eq!(report_output_parent(None, fallback), fallback);
    }
}
