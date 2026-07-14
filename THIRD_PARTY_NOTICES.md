# Third-party notices

## retoc

This project embeds a pinned Windows build of
[retoc](https://github.com/trumank/retoc) for Unreal IoStore inspection and
conversion. retoc is licensed under the MIT License. Its unmodified license is
included at `third_party/retoc/LICENSE`.

The embedded `oo2core_9_win64.dll` is used by retoc when handling game
containers. Distribution of release builds must be reviewed against the
applicable game/tool licensing terms before public publication.

## UAssetGUI / UAssetAPI

This project embeds the official UAssetGUI 1.1.0 Windows release from
[atenfyr/UAssetGUI](https://github.com/atenfyr/UAssetGUI) for legacy Unreal
package JSON round-tripping and verification. UAssetGUI and UAssetAPI are
licensed under the MIT License. The upstream license and notice are included at
`third_party/uassetgui/LICENSE` and `third_party/uassetgui/NOTICE.md`.

Pinned executable SHA-256:
`B7D75C0893F1A60E565853AE638BC21F2416CD12C2D9D854E297ABB87CEB3263`.

## unrar / UnRAR

RAR listing and extraction use the `unrar` 0.5.8 Rust wrapper, selected under
its MIT license, and its statically linked RARLAB UnRAR extraction source.
The wrapper license is included at `third_party/unrar/LICENSE-MIT.txt`; the
RARLAB license is included at `third_party/unrar/LICENSE-RARLAB.txt`.

RARLAB-required distribution notice:

> UnRAR source code may be used in any software to handle RAR archives without
> limitations free of charge, but cannot be used to develop RAR (WinRAR)
> compatible archiver and to re-create RAR compression algorithm, which is
> proprietary. Distribution of modified UnRAR source code in separate form or
> as a part of other software is permitted, provided that full text of this
> paragraph, starting from "UnRAR source code" words, is included in license,
> or in documentation if license is not available, and in source code comments
> of resulting package.
