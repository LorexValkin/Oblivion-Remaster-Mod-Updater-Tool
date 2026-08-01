# Oblivion Remaster Mod Updater Tool

A native Windows beta utility for examining Oblivion Remastered mod archives and folders, then creating an updated candidate only when the input matches a supported and verified conversion path.

The project is written in Rust with a Slint desktop interface. It does not use a browser runtime, install scripts, or modify the game during analysis.

## What it does

- Reads ZIP, 7Z, single-volume RAR, and extracted-folder inputs.
- Produces a bounded, shareable preflight report before any conversion work begins.
- Checks the selected game installation, required tools, input layout, and output location.
- Supports a small set of guarded Unreal-container update paths.
- Writes candidates to a separate output folder and verifies their structure after rebuilding.
- Can inspect an installed mod list and prepare verified backups before an explicitly confirmed replacement.

## Safety model

This is a beta tool. A readable input is not automatically a convertible input.

Each run begins with fresh preflight checks. If the tool cannot prove that an input fits a supported path, it stops with a report instead of guessing. Source inputs and stock game files stay read-only in the normal workflow. A successful candidate still needs an in-game test.

The installed-modlist feature is intentionally separate because it can replace eligible installed container files. It requires a clear confirmation, creates verified backups outside the active mod folder, and attempts rollback if a replacement step fails.

## Build from source

Install Rust 1.95 or newer, then run:

```text
cargo test
cargo build --release
```

The desktop application is `target/release/obr-mod-updater.exe`. The repository also includes `obr-report`, a non-mutating report and stress-test companion.

To assemble the Windows tester package, run `scripts/Build-Release.ps1`. The generated package is written under `dist/` and is not committed.

## Project layout

- `src/` contains the Rust application, preflight checks, conversion adapters, and verification code.
- `src/fixes.rs` exposes reusable, evidence-bearing fix APIs; `docs/FIX-APIS.md` defines their extension contract.
- `ui/` contains the Slint desktop interface.
- `tests/` contains automated coverage and optional local integration fixtures.
- `docs/RELEASE.md` and `docs/STRESS-TESTING.md` describe the release checks and repeatable report testing.
- `third_party/` contains the pinned third-party components and their notices.

## Third-party components

The tool embeds pinned copies of retoc and UAssetGUI for temporary use during supported conversions. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for license details.

## License

Original OBR Mod Updater code is source-available under the MIT terms with the Commons Clause License Condition v1.0. See [LICENSE](LICENSE). Third-party components retain their own licenses.
