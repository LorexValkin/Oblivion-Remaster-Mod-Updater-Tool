# Stress testing and report submission

Use the report companion to test discovery, classification, tool connections,
performance, and deterministic results without changing the selected mod or
game installation.

## Basic report

    obr-report.exe --mod <zip-7z-or-folder> --output <existing-folder>

Add a target game when testing update capability:

    obr-report.exe --mod <mod> --game <game-folder> --output <existing-folder>

External runtime tools can be archives or extracted folders in any locations:

    obr-report.exe --mod <mod> --game <game> --output <folder> --tool <tool-one> --tool <tool-two>

## Repeated stress run

    obr-report.exe --mod <mod> --game <game> --output <folder> --stress-runs 25

The command exits nonzero if the stable signature changes between runs.
Requested/completed run counts, stable signature, deterministic status, and
min/mean/max elapsed milliseconds are written under the stress object.

Use --stdout to emit only JSON for automation:

    obr-report.exe --mod <mod> --game <game> --stress-runs 10 --stdout

## What to submit

Submit:

- the generated preflight JSON;
- the mod download URL and exact version;
- whether the test used the desktop app or obr-report;
- what action was expected;
- any visible shipping-game result, separately from structural report results.

The preflight report omits absolute mod, game, output, and connected-tool paths.
It retains relative mod file samples, hashes, declared sizes, platform and
architecture, tool fingerprints/status, checks, blockers, capabilities, and
performance so results remain comparable.

Do not submit installed game files, extracted game assets, donor containers, or
credentials. Runtime captures belong under docs/research/runtime-probes only
when deliberately archived with their SHA-256 and required capture_end evidence.

## Interpretation

- ready-for-guarded-update means a known adapter and its preconditions passed.
  It does not mean the resulting content is runtime verified.
- report-only means analysis succeeded but no proven adapter is authorized.
- input-error means the source was missing, unreadable, unsafe, encrypted in an
  unsupported way, or outside the bounded format contract.
- runtimeVerified false is expected until representative shipping-game evidence
  proves the intended behavior.
