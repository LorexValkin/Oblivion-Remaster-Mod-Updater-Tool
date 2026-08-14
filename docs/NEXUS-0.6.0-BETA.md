# OBR Mod Updater 0.6.0 Beta

Version 0.6.0 expands the guarded conversion engine, publishes choice-free wrapped layouts without flattening them, and can install a confirmed candidate directly into the selected game after a separate Yes/No confirmation.

## What changed

### Plugin and ESP safety

- Reads and fingerprints every bundled ESP, ESM, and ESL without rewriting it.
- Reports plugin header flags, ordered masters, dependency edges, record types, FormID ownership, compressed records, deleted records, duplicate IDs, and unsafe local-ID ranges.
- Keeps plugin files byte-for-byte identical through supported updates and verifies the complete plugin set before publication.
- Adds bounded compressed-record decoding so malformed plugins cannot request unlimited memory.
- Recognizes direct MagicLoader configuration sidecars and reports when the separate MagicLoader 2 runtime is missing.
- Resolves multi-master worldspace overrides in the ESP-declared master order against matching installed files by defining plugin, local FormID, and record type while keeping their field and deletion semantics report-only.

### Guarded additive SyncMap updates

- Requires one full ESP, one exact `Oblivion.esm` master, one non-empty SyncMap, complete IoStore container triples, and no unsupported loose runtime files.
- Verifies that every SyncMap FormID belongs to the ESP and that mapped Unreal package paths are valid.
- Validates supported `CONT` overrides against the selected current `Oblivion.esm`, allowing proven inventory additions while rejecting removals or functional changes.
- Anchors the ESP and SyncMap to the exact selected mod root so look-alike folders cannot pass preflight and fail later.

### Mixed replacement diagnostics and guarded updates

- Upgrades shareable preflight reports to schema v8 with a package-by-package view of heterogeneous IoStore replacement containers: exact stock-main replacements, additive packages, path/ID conflicts, and every resolved or unresolved dependency edge.
- Adds an explicit layered resolver across connected dependency mods, recursively discovered active installed mods, game/DLC containers, and stock main data. Same-layer ambiguity remains a blocker, non-IoStore tool connections are disclosed but skipped, and fingerprints cover every container member.
- Adds a guarded heterogeneous update path when every package is an existing-game StaticMesh or Texture2D replacement with exact path/ID identity, matching imports, complete dependency closure, and verified rebuild/roundtrip preservation. Other mixed bundles remain report-only.
- Uses the exact installed package path casing when building Retoc filters for an existing package ID, preventing a differently cased source path from producing a false zero-file extraction. Additive packages keep their source casing.
- Stops safely when the selected input is the connected game's active `Content/Paks/~mods` directory. Select the original archive or complete extracted mod root so the report does not combine unrelated installs or miss the ESP, SyncMap, sidecars, or wrapper root.
- Adds bounded logical install plans for canonical wrappers, explicit unconditional FOMOD file mappings, and unambiguous manual Data/Paks layouts. Choice-free canonical and manual structural plans can now publish a proven nested adapter while retaining every original physical path and pass-through hash. FOMOD choices and condition-bearing installers remain report-only and are never guessed.

### Safer archives and installation

- Fixes solid 7Z metadata extraction when the archive library reports streamed files before directory entries.
- Correctly counts TES4 `GRUP` headers, accepts safe mounted `/Game/...` SyncMap paths, and keeps stale HEDR `nextObjectId` bookkeeping advisory for byte-preserved ESPs.
- Makes RAR support explicit in both archive-picker labels and provides an All Files fallback when a Windows shell hides `.rar` files under the combined filter.
- Inspects bounded plugin metadata from ZIP, 7Z, and RAR archives. The report-only mixed-IoStore diagnostic stages UTOC/UCAS package-store data only under its explicit byte limit, so large payloads still fail closed instead of being expanded without a bound.
- Reports unresolved IoStore dependency edges deterministically for mixed-mod research while the strict conversion gate continues to reject them.
- Detects archive metadata changes between validation and extraction, enforces per-file and total limits, and publishes completed ZIPs atomically without overwriting an existing output.
- Stages UE4SS and TesSyncMapInjector changes as one transaction, backs up existing files, verifies hashes, and attempts every rollback path if installation fails.
- Publishes and verifies the converted candidate before changing runtime dependencies.
- Adds an **Install to game** button beside **Open output**. The action is unavailable until conversion has successfully published an output folder.
- Opens a Yes/No install prompt immediately after successful conversion. Choosing No leaves the candidate untouched; choosing Yes copies the confirmed output to the selected game.
- Refuses to install while Oblivion Remastered is running, verifies every copied file, backs up replaced destinations beside the output, and attempts rollback if a copy fails.

### Release verification

- The app header, Windows FileVersion, Windows ProductVersion, package name, and release manifest all report `0.6.0`.
- The complete automated suite passes with 150 tests passed, 8 environment-dependent fixture tests ignored, and no failures.
- The release package includes this change summary, licenses, dependency instructions, and a machine-readable SHA-256 manifest.

### Tested against

- **Zireael 1.0 weapon replacement on Oblivion Remastered Steam build `19115871`:** completed conversion and candidate publication, launched the game through UNBSE, and spawned the weapon for in-game validation.
- **Supported layout fixtures:** direct replacement triples, guarded additive ESP/SyncMap layouts, choice-free canonical wrappers, and conservative manual Data/Paks layouts.
- **Failure boundaries:** report-only outcomes, failed conversions, incomplete container triples, ambiguous installer choices, and attempts made while the game is running do not enable automatic installation.

## Compatibility scope

Automatic plugin-aware updating remains intentionally narrow. ESM mutations, ESL/light plugins, multi-plugin load-order changes, placed-reference or worldspace edits, quests, scripts, and unknown record mutations are inspected and reported but are not rewritten. They remain report-only until a dedicated adapter and runtime evidence prove that transformation safe.

## Download and installation

For the normal installation, download `OBR-Mod-Updater-v0.6.0-windows-x64.zip`, extract the complete ZIP to a normal folder, and run `OBR Mod Updater.exe`.

A standalone EXE is also provided for people updating an existing extracted copy. Keep the `Dependencies` folder and its instructions if the required runtime tools are not already installed or connected in the app.

## Beta warning

A completed conversion means the files passed the updater's structural and preservation checks. It does not prove runtime behavior. Keep the original mod archive and test the generated candidate in-game, including inventory/menu models, world models, textures, materials, collision, physics, plugin behavior, and save loading.

Support is entirely optional. If you would like to support continued development, visit [Lorex_ on Ko-fi](https://ko-fi.com/lorex_).
