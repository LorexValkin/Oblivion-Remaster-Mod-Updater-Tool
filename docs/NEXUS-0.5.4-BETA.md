# OBR Mod Updater 0.5.4 Beta

## What changed

Version 0.5.4 fixes dependency preservation for additive custom-mesh rebuilds.

- Preserves texture, material, Blueprint, and mesh package dependencies from the complete game and mod container view.
- Prevents valid imports from being rewritten to `UnknownPackage` during rebuilt container generation.
- Allows distinct SyncMap/FormID entries to share one Unreal package while still rejecting duplicate FormIDs.
- Adds exact package extraction and dependency-graph verification as reusable, versioned fix APIs.
- Improves preflight and status messages for supported custom StaticMesh updates.
- Adds regression coverage based on the Parrying Daggers offhand-staves conversion.

## Beta warning

A completed conversion means the files passed the updater's structural checks. It does not prove runtime behavior. Keep the original mod archive and test the generated candidate in-game, including menu models, world models, textures, materials, collision, and physics.

## Download

Download `OBR-Mod-Updater-v0.5.4-windows-x64.zip`, extract the complete ZIP to a normal folder, and run `OBR Mod Updater.exe`.

The application header and Windows executable properties should both report version `0.5.4`.
