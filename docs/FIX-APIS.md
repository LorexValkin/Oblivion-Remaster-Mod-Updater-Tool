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
- `zen-dependency-diagnostic-v1` reports every resolved and unresolved source import edge deterministically. It is read-only; the strict trace still rejects any unresolved dependency before conversion.
- `zen-mixed-iostore-dependency-probe-v1` stages bounded UTOC/UCAS package-store data from every selected mod container, compares its package paths and IDs with the connected current game, and reports the complete resolved or unresolved dependency graph. It is report-only and never drops a missing import or enables conversion; archives over the probe limit remain report-only without expansion.
- `zen-mixed-replacement-package-diagnostic-v1` powers the schema-v8 per-package view of heterogeneous replacement containers. It records each source container, package path, package ID, imported IDs, exact/additive/conflict identity status, and the complete resolved or unresolved dependency graph against bundled packages and the connected game's stock main package store. This diagnostic remains read-only; a separate adapter may act only when every package passes its own stronger structural contract.
- `zen-layered-iostore-dependency-resolver-v1` resolves reachable imports under explicit selected-mod, connected-dependency, active-installed-mod, game/DLC, and stock-main precedence. It rejects same-layer path or ID ambiguity, preserves every cross-layer collision, recursively inventories installed container paths, excludes non-IoStore tool connections without hiding them, and fingerprints every PAK/UCAS/UTOC member. It is evidence, not a claim about live mount behavior.
- `source-agnostic-install-plan-v1` maps physical source paths to logical game destinations for canonical wrappers, explicit unconditional FOMOD file mappings, and conservative manual Data/Paks structures. It preserves option groups and rejects links, traversal, collisions, incomplete triples, and unmodeled FOMOD conditions.
- `logical-install-publication-v1` accepts only choice-free canonical or manual-structural plans whose logical view selected an existing proven adapter. It snapshots the complete physical inventory and immutable mapping set, permits changes only to mapped IoStore files owned by that adapter, reconstructs the original physical paths without adding the nested report, verifies every pass-through and mapped hash, reruns preflight, reopens the ZIP, and verifies source immutability. The additive nested adapter defers runtime dependency installation until the verified outer candidate, archive, and report are durably published. FOMOD plans remain report-only.
- `zen-exact-dependency-extraction-v1` extracts one requested package at a time from a complete dependency view.
- `zen-dependency-preservation-v1` rejects rebuilt containers when package paths, IDs, or imported-package sets change.
- `tes4-plugin-manifest-v1` content-hashes every bundled ESP/ESM/ESL and records its ordered masters, record census, FormID ownership ranges, deleted/compressed records, change domains, and bundled-master edges. ESM, ESL, multi-plugin, and unknown record semantics remain report-only.
- `tes4-plugin-byte-preservation-v1` requires the candidate plugin set to retain the exact case-insensitive relative paths, kinds, sizes, and SHA-256 hashes of the source set.
- `tes4-additive-syncmap-policy-v1` admits only the proven single full-ESP lane: the ESP is directly under `Content/Dev/ObvData/Data`, has exactly one `Oblivion.esm` master, uses plugin-local IDs at or above `0x800`, has no duplicate or out-of-range FormIDs, and contains no master override type other than `CONT`. The existing field-aware current-master comparator still decides whether each `CONT` is a pure inventory addition.
- `tes4-syncmap-additive-contract-v1` binds the ESP and SyncMap to the one root that contains both `Content/Dev/ObvData/Data` and `Content/Paks/~mods`. It requires a non-empty, duplicate-free SyncMap, resolves every mapped local FormID to a plugin-owned record, validates Unreal object paths, and compares every `CONT` override field-by-field with the selected current `Oblivion.esm`.
- `tes4-worldspace-master-resolution-probe-v1` streams the installed master set, remaps each override by defining plugin plus local FormID, applies installed load-order precedence, and requires the current target record type to agree. It remains report-only and explicitly does not prove `CELL`, `REFR`, `WRLD`, deleted-record, or save semantics.
- `magicloader-config-sidecar-v1` recognizes direct JSON sidecars only under the selected mod root's `Content/Dev/ObvData/Data/MagicLoader` folder and reports the separate MagicLoader runtime requirement. It never turns an otherwise unsupported mixed mod into an additive update.
- `archive-selected-metadata-extraction-v1` validates the complete ZIP/7Z/RAR inventory and collision rules but materializes only bounded ESP/ESM/ESL/INI files for preflight. Multi-gigabyte IoStore payloads are not expanded just to inspect plugin metadata.
- `runtime-dependency-transaction-v1` expands, validates, backs up, and stages every required runtime dependency before changing an active game file. Commit failure rolls every changed destination back. The verified candidate ZIP is published before this transaction begins.
- `native-heterogeneous-static-mesh-texture-v1` accepts only existing-game replacement containers made entirely of independently proven StaticMesh and Texture2D packages. Paths, IDs, imports, dependency closure, exact extraction, rebuilt inventory/classes, and payload preservation are all verified; source texture format or bulk-layout differences are disclosed and still require runtime testing.

These APIs prevented a previously accepted rebuild from replacing valid material and sibling-container imports with `/Engine/UnknownPackage`.

Retoc path filters are case-sensitive. For a package ID already present in the connected game, extraction must use the exact current-game package path casing; only genuinely additive packages use source path casing. A case-insensitive identity match is not enough to construct the filter.

The active game `Content/Paks/~mods` directory is an installed-state boundary, not a complete source-mod boundary. Selecting it directly fails closed because it can combine unrelated containers and omit an archive's ESP, SyncMap, MagicLoader sidecars, or wrapper root. Preflight requires the original archive or complete extracted mod root; installed-state work belongs to the separate installed-mod scan.

Plugin analysis is not a generic plugin writer. Preserving bytes proves identity preservation, not compatibility with a changed master or save. Master-flagged or light-flagged files are classified from both extension and TES4 header flags; extension/header mismatches cannot enter the full-ESP lane. Compressed records are bounded to 64 MiB before allocation and while decoding. Any future `CONT`, `REFR`, `CELL`, leveled-list, quest, script, ESM, or ESL mutation needs its own versioned semantic adapter and runtime gate.

## Adding another fix

- Give the API a versioned identifier.
- Define the exact structural evidence it consumes and the mutation it permits.
- Make ambiguity and missing evidence errors, not warnings.
- Serialize before/after evidence into the update report.
- Add a focused synthetic regression and, when available, an ignored current-game fixture.
- Never promote a structurally verified candidate to runtime-verified without an explicit in-game test.
