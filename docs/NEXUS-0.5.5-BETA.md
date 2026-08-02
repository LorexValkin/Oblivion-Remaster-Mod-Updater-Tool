# OBR Mod Updater 0.5.5 Beta Pre-Release

Version 0.5.5 adds the plugin-aware safety foundation needed to handle mods that include ESP, ESM, or ESL files without making unsafe guesses about record changes.

## What changed

### Plugin and ESP safety

- Reads and fingerprints every bundled ESP, ESM, and ESL without rewriting it.
- Reports plugin header flags, ordered masters, dependency edges, record types, FormID ownership, compressed records, deleted records, duplicate IDs, and unsafe local-ID ranges.
- Keeps plugin files byte-for-byte identical through supported updates and verifies the complete plugin set before publication.
- Adds bounded compressed-record decoding so malformed plugins cannot request unlimited memory.

### Guarded additive SyncMap updates

- Requires one full ESP, one exact `Oblivion.esm` master, one non-empty SyncMap, complete IoStore container triples, and no unsupported loose runtime files.
- Verifies that every SyncMap FormID belongs to the ESP and that mapped Unreal package paths are valid.
- Validates supported `CONT` overrides against the selected current `Oblivion.esm`, allowing proven inventory additions while rejecting removals or functional changes.
- Anchors the ESP and SyncMap to the exact selected mod root so look-alike folders cannot pass preflight and fail later.

### Safer archives and installation

- Makes RAR support explicit in both archive-picker labels and provides an All Files fallback when a Windows shell hides `.rar` files under the combined filter.
- Inspects only bounded plugin metadata from ZIP, 7Z, and RAR archives instead of expanding large PAK, UCAS, and UTOC payloads during preflight.
- Detects archive metadata changes between validation and extraction, enforces per-file and total limits, and publishes completed ZIPs atomically without overwriting an existing output.
- Stages UE4SS and TesSyncMapInjector changes as one transaction, backs up existing files, verifies hashes, and attempts every rollback path if installation fails.
- Publishes and verifies the converted candidate before changing runtime dependencies.

### Release verification

- The app header, Windows FileVersion, Windows ProductVersion, package name, and release manifest all report `0.5.5`.
- The complete automated suite passes with 83 tests passed, 6 environment-dependent fixture tests ignored, and no failures.
- The release package includes this change summary, licenses, dependency instructions, and a machine-readable SHA-256 manifest.

## Compatibility scope

Automatic plugin-aware updating remains intentionally narrow. ESM mutations, ESL/light plugins, multi-plugin load-order changes, placed-reference or worldspace edits, quests, scripts, and unknown record mutations are inspected and reported but are not rewritten. They remain report-only until a dedicated adapter and runtime evidence prove that transformation safe.

## Download and installation

For the normal installation, download `OBR-Mod-Updater-v0.5.5-windows-x64.zip`, extract the complete ZIP to a normal folder, and run `OBR Mod Updater.exe`.

A standalone EXE is also provided for people updating an existing extracted copy. Keep the `Dependencies` folder and its instructions if the required runtime tools are not already installed or connected in the app.

## Beta warning

A completed conversion means the files passed the updater's structural and preservation checks. It does not prove runtime behavior. Keep the original mod archive and test the generated candidate in-game, including inventory/menu models, world models, textures, materials, collision, physics, plugin behavior, and save loading.

Support is entirely optional. If you would like to support continued development, visit [Lorex_ on Ko-fi](https://ko-fi.com/lorex_).
