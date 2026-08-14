# Plugin and mixed-mod compatibility

Oblivion Remastered mods can span three linked planes:

1. TES data in ESP/ESM/ESL files.
2. SyncMap entries that bind a plugin-local FormID to an Unreal object path.
3. Unreal packages inside PAK/UTOC/UCAS containers.

The updater reports all three planes but mutates only a registered, fail-closed adapter. A readable plugin or preserved hash does not by itself prove master compatibility, load order, save compatibility, or runtime behavior.

## Current scenario matrix

| Scenario | Detection and report | Automatic mutation |
| --- | --- | --- |
| One full ESP + one SyncMap + additive IoStore packages | Full plugin manifest, FormID/master checks, SyncMap closure, package dependency trace | Supported only by `native-additive-syncmap-v1` after every policy and current-master `CONT` check passes |
| Plugin-only ESP | Masters, record types/domains, FormID ranges, hashes, external-master requirements | Report-only |
| ESP plus existing-asset replacements | Both plugin and container presence disclosed | Report-only until a composed adapter proves both planes together |
| Heterogeneous existing/additive IoStore replacements, including StaticMesh + Texture packages | Schema-v8 per-package identity status, layered dependency evidence, and complete dependency-edge report across every container | Supported only when every package is an exact existing-game StaticMesh or Texture2D replacement and the dedicated heterogeneous contract passes; additive, conflicting, or other-class mixtures remain report-only |
| Choice-free canonical wrapper or manual structural layout around a proven adapter | Immutable physical/logical mapping context, source and pass-through hashes, nested adapter identity, fresh preflight, and reopened ZIP verification | Supported through `logical-install-publication-v1`; FOMOD and choice-bearing plans remain report-only |
| Multiple ESP/ESM files | Per-plugin manifest and bundled master edges | Report-only; load-order and ownership metadata are required |
| ESM | Parsed and fingerprinted | Report-only |
| ESL/light plugin | Detected, parsed where structurally possible, explicitly marked unproven | Report-only until shipped/runtime evidence proves light-plugin FormID rules |
| WRLD/CELL/REFR changes | Record domains and override types disclosed | Report-only; a future bridge-aware adapter must preserve master CELL/WRLD payloads and existing XAAG identity |
| Multi-master worldspace ESP + SyncMap + MagicLoader JSON + IoStore | Path-bound MagicLoader inventory and installed-master override/type resolution | Report-only until deleted-reference semantics, stock-plus-mod SyncMap closure, every Unreal dependency, and MagicLoader runtime compatibility are proven |
| Deleted records | Counted and disclosed | Report-only |
| Scripts/loaders with plugins or containers | Classified as mixed content | Report-only |
| BSA/BA2, localization, configuration, or arbitrary loose files | Extension inventory and mixed-content report | Report-only |

## Proven plugin invariants

- Ordinary full-plugin owned records use the plugin index after the ordered master list.
- Plugin-local object IDs below `0x800` are reserved and are rejected by the additive mutation policy.
- The current additive lane keeps the ESP byte-for-byte and rechecks the complete plugin set after candidate creation.
- Only `CONT` master overrides can enter that lane, and only when the current `Oblivion.esm` record proves the override is a pure inventory addition.
- The ESP and SyncMap must live under the same unique mod root as the selected IoStore containers. Empty SyncMaps, duplicate local IDs, mappings without plugin-owned records, and invalid Unreal object paths are blockers.
- TES4 master/light header flags are authoritative safety evidence even when the filename says `.esp`; mismatches remain report-only.
- Compressed TES4 records have a 64 MiB declared-size and decoded-output ceiling, preventing small plugin inputs from becoming unbounded allocations.
- Runtime dependencies are not installed until plugin, FormID, SyncMap, package, candidate-preservation validation, report writing, and portable candidate publication have completed. All dependency payloads are then committed as one rollback-capable transaction.
- Archive preflight validates the whole path/size inventory and extracts only bounded plugin and SyncMap metadata by default. The report-only mixed-IoStore diagnostic may additionally stage UTOC/UCAS package-store data under its explicit byte limit; it never expands an unbounded container payload.
- Schema-v8 mixed-replacement diagnostics classify each source package as an exact stock-main replacement, additive package, or path/ID conflict and retain every resolved or unresolved import edge. The layered resolver separately evaluates explicit connected, installed, game/DLC, and stock-main providers, rejects same-layer ambiguity, and records cross-layer shadowing. Neither diagnostic authorizes mutation by itself.
- `native-heterogeneous-static-mesh-texture-v1` classifies every package independently and accepts only an all-existing replacement set made entirely of proven StaticMesh and Texture2D assets. Exact current identities, equal import sets, complete dependency closure, source-case extraction, one rebuilt container pass, roundtrip classes, and payload preservation are required; format/bulk-layout warnings and shipping-game testing remain explicit.
- Retoc filters are case-sensitive: an existing package uses the exact path casing from the current-game package entry matched by ID, while a genuinely additive package retains its source casing.
- Selecting the connected game's active `Content/Paks/~mods` directory as the source fails closed. That directory may mix unrelated installed containers and omit a mod's ESP, SyncMap, MagicLoader sidecars, or wrapper root; select the original archive or complete extracted mod root instead.
- ESL semantics are not inferred from full ESP rules.
- Direct `Data/MagicLoader/*.json` sidecars are functional configuration, not documentation. They are counted separately and kept report-only; nested, misplaced, or arbitrary JSON remains unknown functional content. The runtime check recognizes only a path-bound file with a readable Windows executable signature and does not claim its version or behavior.
- Multi-master override resolution proves that a current installed record with the same defining plugin, local FormID, and record type exists. It does not prove that an old `CELL`, `REFR`, or `WRLD` payload—or deletion—is safe against the current bridge data.

## Next adapters

The next safe expansion should be versioned and evidence-driven:

1. Installed plugin diffing keyed by defining plugin plus local FormID, including master reorder, FormID reuse, EDID/type changes, XAAG changes, and reverse dependencies.
2. A cross-plane bundle graph keyed by `(plugin filename, local FormID)` and exact Unreal object/package identity.
3. A current-master `CONT` rebase adapter that reconstructs only a proven inventory addition.
4. A read-only Altar `REFR` bridge audit for `NAME`, `XAAG`, `XACN`, optional `XSCL`, and `DATA`; it must never synthesize missing bridge data.
5. A transaction spanning plugin files, SyncMaps, and every container triple, with rollback and mod-manager ownership awareness.

Every generated candidate still requires a shipping-game test. Structural success never sets `runtimeVerified` by itself.
