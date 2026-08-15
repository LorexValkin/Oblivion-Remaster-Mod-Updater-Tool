# Oblivion Remaster Mod Updater Tool

A native Windows beta utility for examining Oblivion Remastered mod archives and folders, then creating an updated candidate only when the input matches a supported and verified conversion path.

Part of the **Unblivion Editor tool set**.

The project is written in Rust with a Slint desktop interface. It does not use a browser runtime, install scripts, or modify the game during analysis.

## What it does

- Reads ZIP, 7Z, single-volume RAR, and extracted-folder inputs.
- Produces a bounded, shareable preflight report before any conversion work begins.
- Content-hashes every ESP/ESM/ESL and reports masters, header/extension mismatches, record domains, FormID ranges, deleted records, and bundled plugin dependencies without generically rewriting plugins.
- Recognizes path-bound MagicLoader configuration sidecars and resolves complex multi-master worldspace override identities in the ESP-declared master order against matching installed files regardless of sidecar layout, while leaving unproven field, deletion, save, and runtime semantics report-only.
- Reports every unresolved mixed-IoStore dependency edge under bounded `Content/Paks` subdirectories without weakening the strict conversion gate.
- Schema-v8 reports inventory heterogeneous replacement containers package by package, distinguishes exact stock-main replacements, additive packages, path/ID conflicts, and every dependency edge, and adds an explicit layered resolver across connected dependencies, active installed mods, game/DLC containers, and stock main data.
- Builds bounded physical-to-logical install plans for canonical wrappers, explicit unconditional FOMOD file mappings, and unambiguous manual Data/Paks layouts. Choice-free canonical and manual structural plans can publish a proven nested adapter while preserving the original physical path inventory and pass-through hashes; FOMOD and choice-bearing plans remain diagnostic only.
- Uses the exact current-game package path casing for Retoc filters when an existing package ID is matched; additive packages retain their source path casing.
- For the guarded additive lane, binds the ESP, non-empty SyncMap, ordered installed full-master chain, and IoStore root before enabling Update. Proven `CONT`, `CREA`, and `NPC_` inventory additions are merged three ways so newly installed master rows are preserved without dropping the mod's additions; conflicts remain report-only.
- Checks the selected game installation, required tools, input layout, and output location.
- Supports guarded homogeneous Unreal-container paths, heterogeneous existing-game StaticMesh/Texture2D replacements, and a system-wide composite rebase path for decoded meshes, textures, material instances, generated Blueprints, `/Script/Altar` TES forms, and exact current-template packages. Valid custom project `Content` roots and direct author-named Paks folders are normalized structurally. Missing package identities may be recovered only from raw NameMap data, authoritative package IDs, structural source relationships, and serialized Blueprint roles. A proven optional secondary Blueprint component may be retired only when its serialized role is unique and the rebuilt package preserves every unrelated dependency. Package identity, dependency closure, authored imports, and payload preservation are verified through rebuild and round trip.
- Writes candidates to a separate output folder and verifies their structure after rebuilding.
- Offers an explicit **Install to game** confirmation only after a candidate has been published successfully. Replaced destination files are backed up beside the output.
- Can inspect an installed mod list and prepare verified backups before an explicitly confirmed replacement.

## Safety model

This is a beta tool. A readable input is not automatically a convertible input.

Each run begins with fresh preflight checks. If the tool cannot prove that an input fits a supported path, it stops with a report instead of guessing. Source inputs and stock game files stay read-only during analysis and conversion. Installation is offered only after successful candidate publication and requires a separate Yes/No confirmation. A successful candidate still needs an in-game test.

Complex mods that combine a multi-master TES plugin with converted Unreal containers remain report-only as a complete archive. The updater can verify the Unreal plane and resolve current master record identities without rewriting the plugin, but it does not claim CELL/REFR/WRLD field behavior, deletion behavior, save compatibility, or runtime compatibility.

Select the original mod archive or its complete extracted root for preflight. Selecting the connected game's active `Content/Paks/~mods` directory fails closed because that folder can mix unrelated installed mods and omit the ESP, SyncMap, sidecars, or wrapper root needed to understand one mod. Mixed StaticMesh-and-Texture bundles remain report-only unless every package passes the dedicated heterogeneous replacement contract. FOMOD choices, conditional installers, and ambiguous physical layouts remain report-only; only choice-free canonical wrappers and conservative manual structural layouts enter mapped publication.

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
- `CONTRIBUTING.md` requires compatibility fixes to be generalized from structural evidence before a mod-specific exception is considered.
- `src/plugin.rs` implements the plugin manifest and byte-preservation boundary; `docs/PLUGIN-COMPATIBILITY.md` records supported and report-only mixed-mod scenarios.
- `ui/` contains the Slint desktop interface.
- `tests/` contains automated coverage and optional local integration fixtures.
- `docs/RELEASE.md` and `docs/STRESS-TESTING.md` describe the release checks and repeatable report testing.
- `third_party/` contains the pinned third-party components and their notices.

## Third-party components

The tool embeds pinned copies of retoc and UAssetGUI for temporary use during supported conversions. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for license details.

## Support the project

If the updater has been useful and you would like to support continued development, you can [support Lorex_ on Ko-fi](https://ko-fi.com/lorex_). Support is entirely optional—using the tool, testing candidates, and sharing useful bug reports already helps the project.

## License

Original OBR Mod Updater code is source-available under the MIT terms with the Commons Clause License Condition v1.0. See [LICENSE](LICENSE). Third-party components retain their own licenses.
