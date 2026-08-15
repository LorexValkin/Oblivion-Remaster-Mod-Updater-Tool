# Changelog

## 0.6.2 - 2026-08-14

- Add `native-composite-package-rebase-v2`, which recovers missing Unreal package names from raw Zen NameMap data by verifying them against Unreal package IDs. Recovery is bounded, class-driven, and refuses ambiguous names or source candidates.
- Add deterministic package-root/public-export identity aliases for role-proven Blueprint dependencies. Material aliases require a serialized blood-splatter component reference; StaticMesh aliases require a serialized scabbard component reference. Authored export payloads and sidecars remain preserved.
- Resolve package-store paths that disagree with their internal Unreal identity from the package's own NameMap instead of trusting either source alone.
- Isolate Retoc prefix-filter results and publish only the exact requested package and sidecars, preventing similarly named sibling packages from entering a candidate.
- Support resolved generated-Blueprint and `/Script/Altar` TES form packages in composite containers. Decoder placeholders may be repaired only when the source package-store delta identifies one available dependency and that dependency exposes one package-named top-level public export.
- Generalize multi-master worldspace master-resolution and risk classification beyond MagicLoader layouts. Complex TES plugin planes remain byte-preserved and report-only; deletion-bearing plugins are classified separately from broad override sets without deletions.
- Keep automatic installation disabled for complex multi-plane mods until the complete archive has passed conversion and shipping-game validation.
- Structurally tested Tribal Minotaur Camps 1.4 as 12 source packages plus two recovered material aliases, and Farmer's Revenge 1.2 as 74 source packages plus two recovered aliases. Both Unreal planes passed rebuild, import-set equality, Retoc verification, current-stock roundtrip, and payload-equivalence checks. In-game behavior remains unverified.

## 0.6.1 - 2026-08-14

- Add `native-composite-package-rebase-v1`, a system-wide package adapter that classifies decoded exports across content domains instead of matching mod or asset names. It supports guarded StaticMesh, Texture2D, material-instance, SkeletalMesh, and exact current-template package repairs.
- Rebase stale current-template import tables only when package identity, cooked flags, import semantics, and export topology agree with the current game. Authored exports and sidecars must remain byte-identical, and every rebuilt package path, ID, import set, and payload is verified again after a current-Zen round trip.
- Repair SkeletalMesh skeleton and PhysicsAsset imports only when serialized properties prove their roles. Existing custom material imports remain authored dependencies, and retired physics references are removed only under the explicit current-donor policy.
- Make composite extraction transactional: directory batching is now a speculative optimization whose output is discarded unless it contains the exact requested package set; exact per-package extraction remains the fallback.
- Recognize mod container sets under any bounded `Content/Paks` subdirectory for classification and read-only dependency diagnostics, including `~mods`, `mods`, and author-named folders.
- Separate archive per-entry limits from total selected-payload limits so large bounded IoStore members can be diagnosed without weakening metadata limits.
- Add the project-wide rule that compatibility work must first be expressed as reusable, evidence-driven, fail-closed behavior; mod-specific exceptions remain a documented last resort.
- Structurally converted CL Blades 1.3 as a 41-package, two-container candidate with current imports and authored payloads verified. Runtime behavior remains unverified and still requires an in-game test.

## 0.6.0 - 2026-08-14

- Upgrade preflight reports to schema v8 with bounded per-package diagnostics for heterogeneous replacement containers, including exact replacements, additions, path/ID conflicts, and complete dependency-edge results.
- Add `native-heterogeneous-static-mesh-texture-v1` for containers composed entirely of structurally proven existing-game StaticMesh and Texture2D replacements. It requires exact current paths and IDs, matching import sets, complete dependency closure, exact source-case extraction, and verified inventory, class, imports, and payload preservation after rebuilding.
- Add deterministic layered IoStore dependency resolution across the selected mod, connected dependencies, active installed mods, game/DLC containers, and stock main data. Ambiguity and unresolved dependencies continue to fail closed.
- Add source-agnostic logical install plans and `logical-install-publication-v1` for choice-free canonical wrappers and conservative manual Data/Paks layouts. Publication preserves every physical source path and pass-through hash, reruns preflight, reopens the candidate ZIP, and verifies source immutability. FOMOD choices and conditional installers remain report-only.
- Reject unsafe package-store paths and ambiguous dependency identities, prevent recursive logical replanning, and use exact current-game package-path casing for replacement extraction.
- Stop safely when the selected input is the connected game's active `~mods` directory; conversions require the original archive or complete extracted mod root.
- Recognize path-bound MagicLoader configuration sidecars and add bounded, report-only multi-master worldspace and mixed-IoStore dependency diagnostics without weakening conversion gates.
- Add an **Install to game** action beside **Open output**. It appears only after a candidate is successfully published, immediately offers a Yes/No confirmation, refuses to install while the game is running, verifies copied files, and backs up replaced destinations beside the output.
- Tested end to end with the Zireael 1.0 weapon replacement on Oblivion Remastered Steam build `19115871`: conversion completed, the candidate loaded through UNBSE, and the weapon was spawned for in-game validation.

## 0.5.5-beta - 2026-08-01

- Fixed selective 7Z metadata extraction for solid archives whose streamed-file callback order differs from their directory-first metadata order.
- Count TES4 `GRUP` headers in HEDR declarations, report parsed group counts, and treat stale `nextObjectId` bookkeeping as advisory when the ESP is preserved byte-for-byte.
- Accept validated mounted SyncMap package paths such as `/Game/...` in addition to disk-style `/Content/` paths.
- Distinguish archive metadata-staging failures from malformed-plugin parse failures in preflight guidance.
- Made RAR support explicit in both native archive pickers and added an All Files fallback for Windows shell configurations that hide `.rar` files under the combined archive filter.
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
