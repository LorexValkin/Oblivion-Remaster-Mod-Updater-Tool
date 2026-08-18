# Oblivion Remaster Mod Updater Tool

A native Windows beta utility for examining Oblivion Remastered mod archives and folders, then creating an updated candidate only when the input matches a supported and verified conversion path.

Part of the **Unblivion Editor tool set**.

The project is written in Rust with a Slint desktop interface. It does not use a browser runtime, install scripts, or modify the game during analysis.

## What it does

- Reads ZIP, 7Z, single-volume RAR, and extracted-folder inputs.
- Produces a bounded, shareable preflight report before any conversion work begins.
- Content-hashes every ESP/ESM/ESL and reports masters, header/extension mismatches, record domains, FormID ranges, deleted records, and bundled plugin dependencies without generically rewriting plugins.
- Recognizes path-bound MagicLoader configuration sidecars and resolves complex multi-master worldspace override identities in the ESP-declared master order against matching installed files regardless of sidecar layout, while leaving unproven field, deletion, save, and runtime semantics report-only.
- Reports every unresolved mixed-IoStore dependency edge under bounded `Content/Paks` subdirectories without weakening the strict conversion gate.
- Schema-v8 reports inventory heterogeneous replacement containers package by package, distinguishes exact stock-main replacements, additive packages, path/ID conflicts, and every dependency edge, and adds an explicit layered resolver across connected dependencies, active installed mods, game/DLC containers, and stock main data.
- Builds bounded physical-to-logical install plans for canonical wrappers, explicit unconditional FOMOD file mappings, and unambiguous manual Data/Paks layouts. Choice-free canonical and manual structural plans can publish a proven nested adapter while preserving the original physical path inventory and pass-through hashes; FOMOD and choice-bearing plans remain diagnostic only.
- Uses the exact current-game package path casing for Retoc filters when an existing package ID is matched; additive packages retain their source path casing.
- For the guarded additive lane, binds the ESP, non-empty SyncMap, ordered installed full-master chain, and IoStore root before enabling Update. Proven `CONT`, `CREA`, and `NPC_` inventory additions are merged three ways so newly installed master rows are preserved without dropping the mod's additions; conflicts remain report-only.
- Checks the selected game installation, required tools, input layout, and output location.
- Supports guarded homogeneous Unreal-container paths, heterogeneous existing-game StaticMesh/Texture2D replacements, and a system-wide composite rebase path for decoded meshes, textures, material instances, generated Blueprints, `/Script/Altar` TES forms, and exact current-template packages. Valid custom project `Content` roots and direct author-named Paks folders are normalized structurally. Missing package identities may be recovered only from raw NameMap data, authoritative package IDs, structural source relationships, and serialized Blueprint roles. A proven optional secondary Blueprint component may be retired only when its serialized role is unique and the rebuilt package preserves every unrelated dependency. Package identity, dependency closure, authored imports, and payload preservation are verified through rebuild and round trip.
- Writes candidates to a separate output folder and verifies their structure after rebuilding.
- Offers an explicit **Install to game** confirmation only after a candidate has been published successfully. Replaced destination files are backed up beside the output.
- Can inspect an installed mod list and prepare verified backups before an explicitly confirmed replacement.

## Safety model

This is a beta tool. A readable input is not automatically a convertible input.

Each run begins with fresh preflight checks. If the tool cannot prove that an input fits a supported path, it stops with a report instead of guessing. Source inputs and stock game files stay read-only during analysis and conversion. Installation is offered only after successful candidate publication and requires a separate Yes/No confirmation. A successful candidate still needs an in-game test.

Complex mods that combine a multi-master TES plugin with converted Unreal containers remain report-only as a complete archive. The updater can verify the Unreal plane and resolve current master record identities without rewriting the plugin, but it does not claim CELL/REFR/WRLD field behavior, deletion behavior, save compatibility, or runtime compatibility.

Select the original mod archive or its complete extracted root for preflight. Selecting the connected game's active `Content/Paks/~mods` directory fails closed because that folder can mix unrelated installed mods and omit the ESP, SyncMap, sidecars, or wrapper root needed to understand one mod. Mixed StaticMesh-and-Texture bundles remain report-only unless every package passes the dedicated heterogeneous replacement contract. FOMOD choices, conditional installers, and ambiguous physical layouts remain report-only; only choice-free canonical wrappers and conservative manual structural layouts enter mapped publication.

The installed-modlist feature is intentionally separate because it can replace eligible installed container files. It requires a clear confirmation, creates verified backups outside the active mod folder, and attempts rollback if a replacement step fails.

## Build from source

Install Rust 1.95 or newer, then run:

```text
cargo test
cargo build --release
```

The desktop application is `target/release/obr-mod-updater.exe`. The repository also includes `obr-report`, a non-mutating report and stress-test companion.

To assemble the Windows tester package, run `scripts/Build-Release.ps1`. The generated package is written under `dist/` and is not committed.

## Tested Mods (v0.7.0)

Structurally verified against the conversion pipeline. Each mod passed preflight, adapter selection, and candidate production. In-game runtime testing is separate.

### Passing (126 mods)

| Nexus ID | Mod | Adapter |
|----------|-----|---------|
| 509 | Zireael | Armor Replacement |
| 511 | Long-Neck Poison Club | Armor Replacement |
| 534 | Sweet Roll Club | Armor Replacement |
| 845 | Zireael - Ciri's Sword | Armor Replacement |
| 860 | BeksBlades | Armor Replacement |
| 977 | Super Sledge Standalone | Additive SyncMap |
| 1069 | Anduril | Armor Replacement |
| 1592 | Off-hand Staves (Standalone) | Additive SyncMap |
| 1592 | Parrying Daggers (Standalone) | Additive SyncMap |
| 1943 | Shadowrend One-Handed Sword | Armor Replacement |
| 1951 | Skull Mask of Nocturnal | Armor Replacement |
| 2469 | LegolasDagger | Mixed Composite |
| 2505 | Jack of Blades v2.1 | Armor Replacement |
| 2511 | Sword of Aeons v1 | Armor Replacement |
| 2623 | Excalibur | Mixed Composite |
| 2661 | Super Sledge in Blacksmith Basement | Additive SyncMap |
| 2674 | Moonveil Standalone | Additive SyncMap |
| 2674 | Replaces Shadowrend Two Handed | Armor Replacement |
| 2674 | Replaces Sword of Jyggalag | Armor Replacement |
| 2674 | Replaces Umbra One Handed | Armor Replacement |
| 2674 | Replaces Umbra Katana | Armor Replacement |
| 2699 | Dragonslayer - Regular Size | Armor Replacement |
| 2811 | DaneAxe v1.1 | Armor Replacement |
| 2833 | SaroumaneStaff | Mixed Composite |
| 2889 | Sword Of Aeons (Standalone) | Logical Install |
| 2936 | Unbroken Blade | Plugin-Only ESP |
| 3004 | Jack Of Blades Armor (Standalone) | Logical Install |
| 3058 | Dragon Slayer | Additive SyncMap |
| 3091 | Dildo Sword | Armor Replacement |
| 3140 | Dante's Rebellion (Daedric Claymore) | Armor Replacement |
| 3140 | Dante's Rebellion (Shadowrend) | Armor Replacement |
| 3140 | Dante's Rebellion (Sword of Jyggalag) | Armor Replacement |
| 3140 | Dante's Rebellion (Umbra) | Armor Replacement |
| 3180 | Blackwater Basket-Hilt | Armor Replacement |
| 3180 | Debaser Replacer Steel | Armor Replacement |
| 3180 | Scabbard Remover | Armor Replacement |
| 3180 | Shortsword of Akatosh | Armor Replacement |
| 3184 | Imperial Glock | Armor Replacement |
| 3184 | Glock (Standalone) | Additive SyncMap |
| 3194 | Cutlass Shortsword Conversion | Mixed Composite |
| 3265 | Fortnite Peter Griffin (Mesh) | Armor Replacement |
| 3265 | Fortnite Peter Griffin (Standalone) | Logical Install |
| 3274 | The Quint (Less shiny, Shadowrend) | Heterogeneous |
| 3274 | The Quint (Less shiny, Jyggalag) | Heterogeneous |
| 3274 | The Quint (Shadowrend) | Heterogeneous |
| 3274 | The Quint (Sword of Jyggalag) | Heterogeneous |
| 3310 | Minecraft Sword | Heterogeneous |
| 3362 | Wilburgurs LIL REE | Plugin-Only ESP |
| 3453 | All Heads Invisible | Armor Replacement |
| 3525 | Berserker Armor (Standalone) | Logical Install |
| 3569 | NecroCarnis | Additive SyncMap |
| 3569 | NecroCarnis No Enchant | Additive SyncMap |
| 3599 | Scythe Standalone | Logical Install |
| 3634 | Ashbringer (Standalone) | Logical Install |
| 3640 | Sword | Armor Replacement |
| 3874 | N12 - Transmute Apparel | Plugin-Only ESP |
| 3999 | Torch Weapons | Additive SyncMap |
| 4065 | EBONY XIPHOS v1 | Armor Replacement |
| 4065 | EBONY XIPHOS v2 | Armor Replacement |
| 4076 | Brick (Standalone) | Additive SyncMap |
| 4226 | The Bereaver | Additive SyncMap |
| 4228 | Avo's Tear | Additive SyncMap |
| 4230 | Brass Katana | Additive SyncMap |
| 4230 | Shadow Katana | Additive SyncMap |
| 4230 | Steel Katana | Additive SyncMap |
| 4232 | Tree | Additive SyncMap |
| 4233 | Invincible | Additive SyncMap |
| 4234 | Casca's Sword | Additive SyncMap |
| 4279 | Soul Edge (SHINY) | Additive SyncMap |
| 4279 | Soul Edge v2 (NOT SHINY) | Additive SyncMap |
| 4290 | Cataclysm's Edge | Additive SyncMap |
| 4291 | Lion's Head Halberd | Additive SyncMap |
| 4322 | Flame Assassin Set | Additive SyncMap |
| 4322 | Regular Assassin Set | Additive SyncMap |
| 4326 | Skorm's Bow | Additive SyncMap |
| 4327 | Dragon Longsword (Runescape 3) | Additive SyncMap |
| 4394 | Caladbolg - Non Shiny | Additive SyncMap |
| 4394 | Caladbolg - Shiny | Additive SyncMap |
| 4430 | Farm Scythe (FOMOD) | FOMOD Logical Install |
| 4432 | Ancient Muramasa | Mixed Composite |
| 4459 | Icebreaker | Additive SyncMap |
| 4626 | Mihawk's Kogatana (Mini Yoru) | Additive SyncMap |
| 4626 | Mihawk's Yoru | Additive SyncMap |
| 4630 | The Infinity Blade | Additive SyncMap |
| 4633 | Corrupted Ashbringer | Additive SyncMap |
| 4634 | Frying Pan (Mega included) | Additive SyncMap |
| 4635 | The Penetrator | Additive SyncMap |
| 4636 | Morgul Blade | Additive SyncMap |
| 4637 | Moonlight Greatsword | Additive SyncMap |
| 4639 | Mugen's Katana | Additive SyncMap |
| 4640 | Oblivion Blade of Nulgath | Additive SyncMap |
| 4641 | Shovel | Additive SyncMap |
| 4642 | Gael's Greatsword | Additive SyncMap |
| 4681 | Cosmic's Glock Sounds Effects | Pak-Only Passthrough |
| 4681 | Glock Standalone w/ Holster | Mixed Composite |
| 4702 | Cosmic's Lightsaber Sound Effects | Pak-Only Passthrough |
| 4702 | Lightsabers All in One | Mixed Composite |
| 4709 | Cosmic's Spear | Additive SyncMap |
| 4710 | Sepulchure's DOOMBlade | Additive SyncMap |
| 4720 | Ray Gun | Additive SyncMap |
| 4720 | Ray Gun (sound variant) | Pak-Only Passthrough |
| 4725 | Hotdog Bun Quiver and Arrow | Additive SyncMap |
| 4729 | Warglaives of Azzinoth | Additive SyncMap |
| 4748 | Cosmic's Backpack LOWERED | Additive SyncMap |
| 4758 | Link's Backpack | Additive SyncMap |
| 4770 | The Master Sword | Additive SyncMap |
| 4771 | The Kingdom Key Keyblade | Additive SyncMap |
| 4778 | THE ALMIGHTY HAIRBALL | Additive SyncMap |
| 4840 | Cosmic's Black Cape | Additive SyncMap |
| 4840 | Cosmic's Capes | Additive SyncMap |
| 4843 | Anakin Easter with Force Push | Additive SyncMap |
| 5027 | Cosmic's Stances - Dual Wielding (Anime) | Additive SyncMap |
| 5027 | Cosmic's Stances - Dual Wielding (Regular) | Additive SyncMap |
| 5027 | Nerfed Weapon Damage ESP | Plugin-Only ESP |
| 5039 | Cosmic's Dances n Emotes | Armor Replacement |
| 5050 | Cosmic's Simple Flip (MultiJump) | Armor Replacement |
| 5050 | Cosmic's Simple Flip (Single Jump) | Armor Replacement |
| 5051 | Cosmic's Simple Slide | Armor Replacement |
| 5081 | Cosmic's Flail | Additive SyncMap |
| 5086 | Cosmic's Equippable Wings | Additive SyncMap |
| 5086 | Cosmic's Permanent Wings | Additive SyncMap |
| 5095 | Cosmic's Movement | Additive Container-Only |
| 5469 | Cosmic's Homelander Armor | Mixed Composite |

### Known Issues (6 mods)

| Nexus ID | Mod | Reason |
|----------|-----|--------|
| 1757 | BaskethiltSwordResource | Source resource pack (loose FBX/PNG files only, no game containers) |
| 4891 | C.A.F.E | External standalone tool (exe + DLLs), not a game mod |
| 4979 | Berserk Armor | Multi-container structural conflict under investigation |
| 5497 | CosmicMCM | Pure UE4SS Lua script mod, no game containers to update |
| 5498 | TimeCrunch | Mixed script + container mod, script sidecar publication pending |
| 5503 | Better Horse Control | Pure UE4SS Lua script mod, no game containers to update |

## Project layout

- `src/` contains the Rust application, preflight checks, conversion adapters, and verification code.
- `src/fixes.rs` exposes reusable, evidence-bearing fix APIs; `docs/FIX-APIS.md` defines their extension contract.
- `CONTRIBUTING.md` requires compatibility fixes to be generalized from structural evidence before a mod-specific exception is considered.
- `src/plugin.rs` implements the plugin manifest and byte-preservation boundary; `docs/PLUGIN-COMPATIBILITY.md` records supported and report-only mixed-mod scenarios.
- `ui/` contains the Slint desktop interface.
- `tests/` contains automated coverage and optional local integration fixtures.
- `docs/RELEASE.md` and `docs/STRESS-TESTING.md` describe the release checks and repeatable report testing.
- `third_party/` contains the pinned third-party components and their notices.

## Third-party components

The tool embeds pinned copies of retoc and UAssetGUI for temporary use during supported conversions. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for license details.

## Support the project

If the updater has been useful and you would like to support continued development, you can [support Lorex_ on Ko-fi](https://ko-fi.com/lorex_). Support is entirely optional—using the tool, testing candidates, and sharing useful bug reports already helps the project.

## License

Original OBR Mod Updater code is source-available under the MIT terms with the Commons Clause License Condition v1.0. See [LICENSE](LICENSE). Third-party components retain their own licenses.
