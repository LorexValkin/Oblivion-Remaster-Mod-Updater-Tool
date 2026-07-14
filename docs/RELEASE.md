# Release candidate gates

The authentic-repair policy applies to every release. A green build is not
permission to claim unsupported runtime behavior.

## Automated gates

The release builder runs:

1. cargo fmt --all -- --check
2. cargo test
3. cargo build --release --bins
4. obr-report deterministic smoke run through the ordinary test suite
5. SHA-256 manifest generation for every shipped file

Run:

    powershell -ExecutionPolicy Bypass -File scripts/Build-Release.ps1

Output is written below ignored dist. The ZIP contains:

- OBR Mod Updater.exe
- obr-report.exe
- obr-offhand-export.exe
- README.txt
- Dependencies/PLACE TOOL ARCHIVES HERE.txt
- LICENSE
- THIRD_PARTY_NOTICES.md
- RELEASE-MANIFEST.json

It must not contain source, build scripts, donors, extracted assets, installed
game files, local settings, logs, captures, target, or temporary work.

## Capability wording

- Report inventory is structurally verified only to the level stated in its
  checks and metadata strategy.
- Native additive output is a candidate_ready_for_runtime_test.
- Staff A donor output retains runtimeVerified false until the authoritative
  probe capture is archived and reviewed, despite the prior human shipping-game
  confirmation.
- Staff B remains unavailable.
- Final release wording is blocked on the two-staff workflow and representative
  shipping-game evidence required by the handoff.

## Manual production gates still open

- Reproducible Staff B current-engine donor.
- Staff B Rust adapter with independent hashes and fail-closed anchors.
- Full mod assembly with repaired Staff A and Staff B plus untouched content.
- Shipping runtime probe for Staff A and BP_Iron_Shield_C with
  actorHandlePresent true and capture_end.
- Equivalent visual, physics, and probe gates for Staff B.
- Archive raw JSONL and SHA-256 under docs/research/runtime-probes after reading
  its compact unique index first.
