# Changelog

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