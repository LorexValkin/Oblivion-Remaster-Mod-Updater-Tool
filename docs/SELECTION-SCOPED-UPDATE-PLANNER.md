# Selection-scoped update planner

The updater operates on the archive or complete extracted root selected by the user. Compatibility
decisions are derived only from the selected files and the connected game installation.

## Invariants

- Treat the selected input as one immutable source boundary and content-hash it before analysis.
- Never scan unrelated downloads or installed mods in the normal update workflow.
- Preserve the selected input's archive layout, installer metadata, documentation, and unsupported
  pass-through files unless a registered adapter explicitly replaces a payload.
- Never infer compatibility from an author name, mod name, archive name, container name, or folder
  label such as `Place in Paks folder`.
- Make every mutation decision from parsed identities, package structure, dependency closure, current
  game evidence, and a versioned adapter contract.
- Publish no candidate when a required option or payload would be only partially updated.
- Keep the installed-modlist workflow separate. It has a different source boundary, confirmation,
  backup, rollback, and precedence model.

## Planning model

### 1. Selected source

Validate and inventory exactly one user-selected ZIP, 7Z, RAR, or folder. Record relative paths,
sizes, hashes, and archive safety evidence.

Multiple MAIN files on a download page are separate source selections. If the user selects one file,
only that file is analyzed and updated.

### 2. Install variants

Build explicit install variants before classifying payloads:

- Parse a bounded FOMOD `ModuleConfig.xml` when present. The current reader accepts explicit file
  mappings in required sections and option groups, preserves group constraints, and rejects
  conditional/type-dependent elements and folder mappings until those semantics are modeled.
- Use canonical destination paths from the installer manifest as logical roles while preserving the
  physical source paths in the output archive.
- Without an installer manifest, recognize unambiguous structural suffixes and associations: a
  plugin, a parsed matching SyncMap, complete PAK/UCAS/UTOC sibling triples, and known runtime
  sidecars.
- If files could represent mutually exclusive choices but no manifest or structural boundary proves
  their grouping, report an ambiguous variant boundary. Do not combine them into an invented mod.

Every discovered variant receives its own report. A file shared by multiple variants is represented
once in the source inventory and referenced by each applicable variant.

### 3. Logical payload graph

For each variant, construct a graph rather than assigning one coarse type to the whole archive:

- TES plugin nodes use logical plugin identity. A proven byte-identical Data/SyncMap mirror may share
  one logical node while both physical files remain preserved.
- SyncMap nodes bind parsed local FormIDs to plugin-owned records and Unreal object identities.
- IoStore container nodes retain whole-container identity and runtime precedence.
- IoStore package nodes record package path, package ID, export classes, imports, bundled edges, and
  current-game edges.
- Loose-file and runtime-tool nodes remain explicit; they cannot disappear because another payload
  matched an adapter.

### 4. Per-payload capabilities

Classify packages independently. For example, one selected container may contain a StaticMesh and
several Texture2D packages. The planner asks each registered adapter for a non-mutating capability
result instead of trying whole-archive adapters in sequence.

Each result is one of:

- `unchanged-current`: no migration is required for the selected game fingerprint.
- `adapter-ready`: a named, versioned adapter proved its preconditions.
- `evidence-blocked`: required game, dependency, installer, or package evidence is unavailable.
- `unsupported-layout`: the payload or option boundary is understood but has no safe adapter.
- `transform-failed`: a matching adapter could not produce structurally valid output.
- `runtime-unknown`: structural output exists but still requires an in-game test.

Dependency strongly connected components are planned together. A package cannot be rebuilt in
isolation when another bundled package is required for its identity or imports.

### 5. Atomic mutation plan

Create a deterministic plan keyed by source hash and current-game fingerprint. The plan lists every
source artifact as preserved, replaced by a specific adapter, or blocking. No adapter may claim the
whole selected input merely because it recognized one package.

The planner can proceed only when:

- every applicable install variant has a complete plan;
- every payload requiring migration is `adapter-ready`;
- shared files have identical planned bytes in every variant that references them;
- all dependency and TES/SyncMap cross-plane obligations are satisfied; and
- the complete reconstructed archive passes inventory, path, hash, container, and adapter-specific
  round-trip checks.

Otherwise the selected mod remains report-only with blockers attached to the exact variant and
payload that caused them.

### 6. Publication

Reconstruct the selected archive in a new output location. Preserve all original relative paths and
installer choices. Replace only artifacts named in the approved plan, then re-run preflight against
the candidate and compare it with the plan. Never modify the source selection or silently install the
candidate. Installation is offered only after successful publication and requires explicit user
confirmation.

## Capability roadmap

The user must not select an adapter or understand an internal capability name. Preflight builds the
plan, selects compatible adapters, and returns one user-facing outcome for the complete selection:
updated candidate, no migration required, missing evidence or runtime, unsupported semantic change,
or invalid input.

### Phase 1: logical install view (bounded mapped publication available)

- Extend the bounded FOMOD reader beyond its current explicit unconditional file mappings only when
  conditions, folder expansion, option priorities, and every physical pass-through artifact can be
  represented without guessing.
- Build a normalized logical install view for manual archives only when plugin/SyncMap basenames,
  complete container siblings, and unique structural roots make the mapping unambiguous.
- Treat documentation as preserved pass-through content instead of allowing it to disable an
  otherwise applicable adapter.
- Represent PAK-only payloads separately from IoStore UTOC/UCAS payloads. A PAK is not an incomplete
  IoStore triple merely because no UTOC and UCAS share its stem.
- Preserve physical archive paths even when analysis uses logical game destinations. Choice-free
  canonical and manual-structural plans may select `logical-install-publication-v1` only after the
  nested adapter passes. Publication carries the immutable mapping context, permits changes only to
  adapter-owned mapped IoStore payloads, reconstructs the full physical inventory, preserves all
  pass-through hashes, reruns preflight, reopens the ZIP, and re-hashes the source. FOMOD and
  choice-bearing plans remain report-only.

### Phase 2: TES component graph

- Replace the one-plugin archive rule with independent plugin components linked to their matching
  SyncMaps and IoStore packages.
- Recognize a Data/SyncMap plugin mirror only when the two physical files are byte-identical, have
  one matching direct SyncMap INI, and belong to the same proven install component. Keep both files
  in the candidate while analyzing one logical plugin.
- Infer full-plugin source slots from record evidence instead of assuming `masters.len()`. Require a
  unique solution and report every candidate when the source is ambiguous.
- Canonicalize records by defining plugin plus local FormID before comparing current masters.
- Add record-domain adapters incrementally. A resolved record identity is necessary but does not by
  itself authorize changes to CELL, REFR, WRLD, scripts, quests, deleted records, or saves.

### Phase 3: per-package IoStore planner

- Inventory package path, package ID, exports, imports, bulk sidecars, and current-game identity once.
- Classify each package independently, then plan dependency strongly connected components together.
- Separate source extraction filters from current-target extraction filters. Each must use the exact
  path spelling recorded by the container being read; a case-insensitive identity match is not a
  valid filter for the other container.
- Let multiple package adapters contribute to one container plan. Rebuild the container once, after
  every package is accounted for, rather than trying one class adapter against the whole container.
- Preserve unchanged packages and dependency metadata byte-for-byte unless an adapter explicitly
  owns their transformation.

### Phase 4: layered dependency and precedence view

- Build one cached package registry for the selected game fingerprint across stock main/global
  stores, installed DLC or official containers, the complete selected mod, and explicitly included
  installed-mod evidence.
- Resolve whole-package precedence by package ID, mount order, and container order. Never assume
  partial package merging.
- Distinguish an intentional package-ID alias replacement from a path/ID conflict only after export
  class, object identity, dependency closure, and the winning runtime package are unambiguous.
- Keep genuinely stale or unresolved imports evidence-blocked; never delete them to make a rebuild
  pass.

### Phase 5: adapter registry

Every adapter exposes a probe and a transform contract. Initial reusable adapters should cover:

- existing and additive StaticMesh packages;
- Texture2D packages with preserved imported-package sets;
- material-instance packages whose parent and parameter identities resolve;
- skeletal meshes and their required skeleton, physics, and material graph;
- audio PAK pass-through or migration after a PAK reader proves its payload format;
- plugin-owned additive records and field-aware current-master overrides by record domain; and
- UE4SS/runtime payload validation as a separate compatibility lane, not an Unreal asset mutation.

Blueprints, animation graphs, shader-bearing materials, world packages, executable tools, and script
APIs require their own structural and runtime contracts. They must not inherit approval from a nearby
mesh or texture package.

### Phase 6: atomic candidate verification

Before publication, require all of the following:

- every selected option and physical source artifact is accounted for;
- every required transformation has one registered adapter and no ambiguous donor;
- package paths, IDs, imports, exports, bulk sidecars, and container precedence match the plan;
- plugin paths and hashes are preserved unless a versioned TES adapter owns a change;
- the rebuilt archive retains its installer choices and pass-through files;
- fresh preflight of the candidate produces the planned topology and no new blocker; and
- the output report distinguishes structural verification from runtime verification.

Candidate publication remains atomic. One unsupported required component blocks that install variant;
it never produces a silently partial update.
