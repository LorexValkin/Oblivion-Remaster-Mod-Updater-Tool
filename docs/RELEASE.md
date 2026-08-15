# Release candidate gates

The authentic-repair policy applies to every release. A green build is not
permission to claim unsupported runtime behavior.

## Automated gates

The release builder runs:

1. cargo fmt --all -- --check
2. cargo test
3. cargo build --release --bins
4. executable FileVersion and ProductVersion verification
5. privacy scan of every shipped file
6. SHA-256 manifest generation for every shipped file

Run:

    powershell -ExecutionPolicy Bypass -File scripts/Build-Release.ps1

Output is written below ignored dist. The ZIP contains:

- OBR Mod Updater.exe
- WHATS-NEW.md
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
- A published conversion remains `candidate_ready_for_runtime_test`; successful
  structural validation is not a gameplay claim.
- Unsupported export classes, unresolved dependencies, missing package
  identities, plugin semantics, and ambiguous authored choices remain
  report-only.
- Tested-against lists distinguish structural conversion results from completed
  shipping-game runtime validation.

## Manual production gates still open

- Open the staged executable and confirm the visible version matches the release.
- Confirm ZIP membership and checksums match the generated release manifest.
- Exercise representative conversion candidates in the shipping game before
  making runtime behavior claims.
- Label structurally verified candidates as runtime-unverified until that test
  is complete.
