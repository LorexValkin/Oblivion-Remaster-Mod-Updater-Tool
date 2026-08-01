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

These APIs prevented a previously accepted rebuild from replacing valid material and sibling-container imports with `/Engine/UnknownPackage`.

## Adding another fix

- Give the API a versioned identifier.
- Define the exact structural evidence it consumes and the mutation it permits.
- Make ambiguity and missing evidence errors, not warnings.
- Serialize before/after evidence into the update report.
- Add a focused synthetic regression and, when available, an ignored current-game fixture.
- Never promote a structurally verified candidate to runtime-verified without an explicit in-game test.
