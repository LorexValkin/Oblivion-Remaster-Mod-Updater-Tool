# Fix APIs

Fix APIs are reusable, fail-closed building blocks for asset migrations. They exist so a verified lesson from one mod becomes a structural capability instead of a filename- or mod-specific exception.

## Required workflow

1. Trace the source package graph and classify every dependency edge as bundled with the mod or present in the selected current game.
2. Reject unresolved package IDs before converting any asset.
3. Extract only the intended packages against a dependency-complete view containing stock metadata, current-game packages, and every sibling mod container.
4. Apply a narrowly scoped transformation backed by serialized evidence.
5. Rebuild and compare package paths, IDs, and imported-package sets with the approved source or target graph.
6. Record the API identifier and evidence in the candidate report.
7. Keep runtime verification as a separate required gate.

## Initial APIs

- `zen-dependency-trace-v1` records every source import edge and its proven origin.
- `zen-exact-dependency-extraction-v1` extracts one requested package at a time from a complete dependency view.
- `zen-dependency-preservation-v1` rejects rebuilt containers when package paths, IDs, or imported-package sets change.
- `tes4-plugin-manifest-v1` content-hashes every bundled ESP/ESM/ESL and records its ordered masters, record census, FormID ownership ranges, deleted/compressed records, change domains, and bundled-master edges. ESM, ESL, multi-plugin, and unknown record semantics remain report-only.
- `tes4-plugin-byte-preservation-v1` requires the candidate plugin set to retain the exact case-insensitive relative paths, kinds, sizes, and SHA-256 hashes of the source set.
- `tes4-additive-syncmap-policy-v1` admits only the proven single full-ESP lane: the ESP is directly under `Content/Dev/ObvData/Data`, has exactly one `Oblivion.esm` master, uses plugin-local IDs at or above `0x800`, has no duplicate or out-of-range FormIDs, and contains no master override type other than `CONT`. The existing field-aware current-master comparator still decides whether each `CONT` is a pure inventory addition.
- `tes4-syncmap-additive-contract-v1` binds the ESP and SyncMap to the one root that contains both `Content/Dev/ObvData/Data` and `Content/Paks/~mods`. It requires a non-empty, duplicate-free SyncMap, resolves every mapped local FormID to a plugin-owned record, validates Unreal object paths, and compares every `CONT` override field-by-field with the selected current `Oblivion.esm`.
- `archive-selected-metadata-extraction-v1` validates the complete ZIP/7Z/RAR inventory and collision rules but materializes only bounded ESP/ESM/ESL/INI files for preflight. Multi-gigabyte IoStore payloads are not expanded just to inspect plugin metadata.
- `runtime-dependency-transaction-v1` expands, validates, backs up, and stages every required runtime dependency before changing an active game file. Commit failure rolls every changed destination back. The verified candidate ZIP is published before this transaction begins.

These APIs prevented a previously accepted rebuild from replacing valid material and sibling-container imports with `/Engine/UnknownPackage`.

Plugin analysis is not a generic plugin writer. Preserving bytes proves identity preservation, not compatibility with a changed master or save. Master-flagged or light-flagged files are classified from both extension and TES4 header flags; extension/header mismatches cannot enter the full-ESP lane. Compressed records are bounded to 64 MiB before allocation and while decoding. Any future `CONT`, `REFR`, `CELL`, leveled-list, quest, script, ESM, or ESL mutation needs its own versioned semantic adapter and runtime gate.

## Adding another fix

- Give the API a versioned identifier.
- Define the exact structural evidence it consumes and the mutation it permits.
- Make ambiguity and missing evidence errors, not warnings.
- Serialize before/after evidence into the update report.
- Add a focused synthetic regression and, when available, an ignored current-game fixture.
- Never promote a structurally verified candidate to runtime-verified without an explicit in-game test.
