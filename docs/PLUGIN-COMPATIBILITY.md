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
| Multiple ESP/ESM files | Per-plugin manifest and bundled master edges | Report-only; load-order and ownership metadata are required |
| ESM | Parsed and fingerprinted | Report-only |
| ESL/light plugin | Detected, parsed where structurally possible, explicitly marked unproven | Report-only until shipped/runtime evidence proves light-plugin FormID rules |
| WRLD/CELL/REFR changes | Record domains and override types disclosed | Report-only; a future bridge-aware adapter must preserve master CELL/WRLD payloads and existing XAAG identity |
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
- Archive preflight validates the whole path/size inventory but extracts only bounded plugin and SyncMap metadata instead of expanding PAK/UCAS/UTOC content.
- ESL semantics are not inferred from full ESP rules.

## Next adapters

The next safe expansion should be versioned and evidence-driven:

1. Installed plugin diffing keyed by defining plugin plus local FormID, including master reorder, FormID reuse, EDID/type changes, XAAG changes, and reverse dependencies.
2. A cross-plane bundle graph keyed by `(plugin filename, local FormID)` and exact Unreal object/package identity.
3. A current-master `CONT` rebase adapter that reconstructs only a proven inventory addition.
4. A read-only Altar `REFR` bridge audit for `NAME`, `XAAG`, `XACN`, optional `XSCL`, and `DATA`; it must never synthesize missing bridge data.
5. A transaction spanning plugin files, SyncMaps, and every container triple, with rollback and mod-manager ownership awareness.

Every generated candidate still requires a shipping-game test. Structural success never sets `runtimeVerified` by itself.
