OBLIVION REMASTER MOD UPDATER v0.5.3
EXPERIMENTAL TEST RELEASE

Made by Lorex_

OVERVIEW

OBR Mod Updater analyzes older Oblivion Remastered mods and creates an updated
candidate only when a guarded compatibility adapter passes every safety check.
Unsupported or unrecognized mods receive a diagnostic report and are left
unchanged. A generated candidate is structurally verified, but it still needs
to be tested in the game.

Current guarded lanes include selected additive SyncMap equipment mods, pure
existing SK_ armor replacements, separated mixed armor/form replacements, and
pure existing Texture2D replacement containers. Custom-project SM_ StaticMesh
containers can also be updated when their dependencies and material slots
resolve uniquely against the current game. Mixed body-dependent armor can use
one installed or connected custom body archive to rebind its current body
material and skeleton automatically. The body replacer stays external and is
never bundled into the result. Texture packages must match the current game's
package identity and pixel format and may not include material, blueprint,
cloth, or shader dependencies.

BEFORE YOU START

- Windows x64 and an installed copy of Oblivion Remastered are required.
- Extract this entire distribution ZIP before opening the application.
- Keep the original mod archive. The updater reads it but does not modify it.
- Close Oblivion Remastered if runtime tools need to be installed.
- Remove older copies of the same mod from the game's ~mods folder before
  testing so package load order does not hide the result.

HOW TO UPDATE A MOD

1. Open "OBR Mod Updater.exe".
2. Read the Experimental Software Notice and select "I understand".
3. Under SOURCE MOD, choose Archive for a ZIP/7Z/single-volume RAR file or Folder for an already
   extracted mod.
4. Under GAME INSTALLATION, use Find game. If automatic discovery fails, choose
   Folder and select the Oblivion Remastered installation directory manually.
5. Review DEPENDENCIES & RUNTIME TOOLS. The read-only Runtime Install Path
   field shows where runtime dependencies are or will be installed.
6. If UE4SS, TesSyncMapInjector, or a required custom body/skeleton dependency
   is reported missing, use Add archives or Add folder to connect its original
   download. Required body replacers are read as compatibility profiles and
   are never bundled into the converted mod. The included Dependencies folder
   is optional and is only a convenient place to put those downloads.
7. Under SAVE UPDATED MOD TO, choose an existing output folder.
8. Select "Analyze & update" once. The updater automatically runs preflight and
   continues into conversion only when every required gate passes.
9. Follow progress in Live activity. The box is read-only, but its text can be
   selected and copied. Use Copy log to copy the complete diagnostic.
10. When processing finishes, use Open report to view the JSON report. If an
    updated candidate was created, use Open output to locate it.

HOW TO FIX THE INSTALLED MODLIST (HIGH RISK)

1. Close Oblivion Remastered and OBSE.
2. Choose a valid GAME INSTALLATION and an existing SAVE UPDATED MOD TO folder.
   This output folder will hold verified originals and reports; it must be
   outside the active ~mods directory.
3. Select "Fix installed modlist".
4. Read the large warning shown after the click. This operation may break your
   mods. Use it entirely at your own risk.
5. Check the acknowledgement only if you accept the risk, then select
   "Overwrite eligible mods".
6. Keep the application open while it inventories every container set under
   ~mods. Each complete triple is preflighted independently. Unsupported,
   incomplete, ambiguous, or conflicting mods are skipped and left unchanged.
7. Eligible mods are rebuilt against a fingerprint of the current game. Mods
   proven already current are reported separately and left untouched. Changed
   candidates automatically overwrite their installed PAK/UCAS/UTOC files;
   before replacement, every original is copied and SHA-256 verified in a
   timestamped OBR-Modlist-Backup-* folder under the selected output folder.
8. Review Live activity and modlist-update-report.json. Open output takes you
   to the backup/report folder. Test every updated mod in-game.

The batch can contain updated, already-current, skipped, and failed results. An
already-current armor result requires a fresh current-game rebuild with zero
semantic mutations and preserved exports/sidecars; it is not overwritten. The
report records installed and rebuilt hashes separately because no-op retoc
UTOC/UCAS output is not byte-stable. A later failure does not undo an earlier
successful replacement. Structural verification cannot guarantee runtime
compatibility; keep the timestamped backup until all updated mods have been
tested.

HOW TO INSTALL AND TEST THE CANDIDATE

The updater does not install the converted mod automatically. Install the
generated candidate with your mod manager, or place its .pak/.ucas/.utoc files
in:

  OblivionRemastered\Content\Paks\~mods

Preserve the generated filenames and keep all files from a container set
together. Make sure an older version of the same mod is not still installed.
Test the affected item in game, including its model, textures, materials,
animation, collision, and physics where applicable.

For legacy custom meshes, the updater may remove incompatible cooked physics
bytes from BodySetup while preserving its serialized collision properties. The
report records this as a BodySetup repair. Always test collision in-game.

REPORTING A PROBLEM

This release is experimental and may not update every mod successfully. If a
mod is not fixed or behaves incorrectly, report it in the release thread and
include:

- The original mod name, version, and download link.
- The generated candidate output archive or output folder.
- The complete diagnostic copied with Copy log.
- The generated preflight/update JSON report.
- A screenshot or short description of the expected and actual in-game result.
- Your current Oblivion Remastered game version.

Do not publish personal absolute paths. The Copy log diagnostic and generated
reports redact setup paths intended to remain private.

SAFETY AND CURRENT LIMITS

- The ordinary single-mod source, Oblivion.esm, and stock game containers
  remain read-only. The separately confirmed modlist batch intentionally
  overwrites only eligible installed files under ~mods after verified backups.
- Runtime dependencies are installed only when an adapter explicitly requires
  them, and replaced files are backed up first.
- retoc and UAssetGUI are embedded and fingerprinted. UE4SS and
  TesSyncMapInjector are not bundled.
- Unsupported layouts stop safely in report-only mode.
- "Runtime verification: not claimed" means the updater verified file
  structure but cannot guarantee behavior inside the running game.
- Existing defects in the original mod, such as authoring-level mesh or cloth
  problems, may remain after conversion.
- Already-current decisions are tied to a SHA-256 fingerprint of the installed
  game metadata. A game update forces a fresh evaluation and may require a new
  updater release if serialization or package rules changed; unsupported cases
  fail closed.
- The texture lane preserves authored image and bulk bytes; it does not repair
  incorrect NNRM channels, alpha masks, UVs, or material authoring.

LICENSE AND REDISTRIBUTION

The original OBR Mod Updater software is source-available under the MIT terms
with the Commons Clause License Condition v1.0. You may use, inspect, modify,
and share the tool at no charge. You may not sell the updater or charge for a
product or service whose value derives entirely or substantially from the
updater's functionality. Read LICENSE for the controlling terms.

Third-party components retain their original licenses as listed in
THIRD_PARTY_NOTICES.md.
