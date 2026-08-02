# Changelog

## 0.5.5-beta - 2026-08-01

- Added a versioned ESP/ESM/ESL manifest and byte-preservation layer with master graphs, header-flag checks, FormID ownership rules, and bounded compressed-record decoding.
- Bound the guarded additive lane to one mod root and a non-empty SyncMap, then validate mapped local IDs and `CONT` additions against the selected current `Oblivion.esm` before enabling Update.
- Added bounded selected-metadata extraction for ZIP, 7Z, and RAR preflight so IoStore payloads are not expanded just to inspect plugins.
- Publish the verified candidate before installing runtime dependencies, and stage dependency changes as one rollback-capable transaction.
- Kept ESM, ESL/light, multi-plugin, placed-reference, quest/script, and unknown record mutations report-only until dedicated adapters and runtime evidence exist.

## 0.5.3-beta - 2026-07-15

- Added a guarded, mod-agnostic update lane for custom-project StaticMesh containers.
- Resolved custom mesh dependencies against the current game and repaired only uniquely matched legacy material imports.
- Normalized incompatible cooked BodySetup physics data that could crash the game with a `Bad name index` loader error, while preserving the mesh's serialized collision properties and reporting the repair.
- Added a real-archive regression fixture for the Ebony quiver mod and kept runtime testing clearly separate from structural verification.

## 0.5.2-beta - 2026-07-14

- Prepared the repository as a clean public beta source release.
- Added guarded support for the current report-first and verified conversion workflows.
- Simplified public documentation and removed internal research notes and draft release posts.
- Kept the build, release, stress-test, licensing, and third-party notices needed to inspect and build the project.
