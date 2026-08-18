//! Bounded legacy UnrealPak (`.pak`) index reader for the fail-closed legacy
//! pak passthrough lane.
//!
//! This is intentionally not a general pak extractor. It proves exactly what
//! the passthrough contract needs and refuses everything else:
//! footer shape, unencrypted index, index SHA-1 against the footer, a fully
//! decoded entry table with no trailing bytes, per-entry stored-payload SHA-1,
//! zlib block decompression roundtrips, mount/path shape under the game
//! content root, a single proven content plane, and presence of every entry in
//! the current game's own shipped pak index.

use crate::archive::{sha256_bytes, sha256_file};
use crate::replacement::stage_input;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use walkdir::WalkDir;

pub const LEGACY_PAK_PASSTHROUGH_ADAPTER: &str = "native-legacy-pak-passthrough-v1";
pub const LEGACY_PAK_PASSTHROUGH_PROBE_API: &str = "legacy-pak-passthrough-probe-v1";

const PAK_MAGIC: u32 = 0x5A6F_12E1;
/// Legacy footer: magic + version + index offset + index size + index SHA-1.
const LEGACY_FOOTER_TAIL_BYTES: usize = 44;
/// Modern (index version 10/11) footer adds five 32-byte compression method
/// names after the index hash; the encryption flag and key GUID precede magic.
const MODERN_FOOTER_TAIL_BYTES: usize = LEGACY_FOOTER_TAIL_BYTES + 160;
const FOOTER_SCAN_BYTES: u64 = 4096;
const MAX_MOD_PAK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PAK_INDEX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PAK_STRING_BYTES: usize = 4096;
const MAX_PAK_ENTRIES: usize = 100_000;
const MAX_COMPRESSION_BLOCKS: usize = 65_536;
const MAX_DECOMPRESSED_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MOD_PAK_FILES: usize = 16;

const GAME_MAIN_PAK_RELATIVE: &str = r"OblivionRemastered\Content\Paks\OblivionRemastered-Windows.pak";
const GAME_CONTENT_PREFIX_LOWER: &str = "oblivionremastered/content/";
const WWISE_AUDIO_PREFIX_LOWER: &str = "oblivionremastered/content/wwiseaudio/";
const MOVIES_PREFIX_LOWER: &str = "oblivionremastered/content/movies/";
pub const WWISE_AUDIO_MEDIA_PLANE: &str = "wwise-audio-media";
const INSTALL_RELATIVE_PREFIX: &str = "OblivionRemastered/Content/Paks/~mods/";

#[derive(Clone, Copy, Debug)]
struct PakFooter {
    version: i32,
    index_offset: u64,
    index_size: u64,
    index_hash: [u8; 20],
    encrypted_index: bool,
}

#[derive(Clone, Debug)]
struct LegacyPakEntry {
    name: String,
    data_offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: u32,
    stored_hash: [u8; 20],
    compression_blocks: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PakPassthroughEntry {
    pub logical_path: String,
    pub content_plane: String,
    pub compression: String,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub stored_payload_sha1_verified: bool,
    pub decompressed_size_verified: bool,
    pub current_game_media_present: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PakPassthroughPak {
    pub file_name: String,
    pub source_relative_path: String,
    pub install_relative_path: String,
    pub pak_sha256: String,
    pub pak_index_version: i32,
    pub mount_point: String,
    pub index_sha1_verified: bool,
    pub patch_priority_suffix: bool,
    pub entry_count: usize,
    pub entries: Vec<PakPassthroughEntry>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentGameAudioIndex {
    pub pak_file_name: String,
    pub pak_index_version: i32,
    pub primary_index_sha1_verified: bool,
    pub directory_index_sha1_verified: bool,
    pub wwise_media_file_count: usize,
    #[serde(skip)]
    pub wwise_paths_lower: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PakPassthroughProbeSummary {
    pub api: String,
    pub pak_count: usize,
    pub entry_count: usize,
    pub content_planes: Vec<String>,
    pub current_game: CurrentGameAudioIndex,
    pub matched_current_media_count: usize,
    pub paks: Vec<PakPassthroughPak>,
    pub disclosures: Vec<String>,
}

fn read_bytes<'a>(buffer: &'a [u8], cursor: &mut usize, count: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(count)
        .filter(|end| *end <= buffer.len())
        .context("pak index record extends past the end of its region")?;
    let slice = &buffer[*cursor..end];
    *cursor = end;
    Ok(slice)
}

fn read_u32(buffer: &[u8], cursor: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        read_bytes(buffer, cursor, 4)?.try_into()?,
    ))
}

fn read_i32(buffer: &[u8], cursor: &mut usize) -> Result<i32> {
    Ok(i32::from_le_bytes(
        read_bytes(buffer, cursor, 4)?.try_into()?,
    ))
}

fn read_u64(buffer: &[u8], cursor: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        read_bytes(buffer, cursor, 8)?.try_into()?,
    ))
}

fn read_i64_non_negative(buffer: &[u8], cursor: &mut usize, label: &str) -> Result<u64> {
    let value = i64::from_le_bytes(read_bytes(buffer, cursor, 8)?.try_into()?);
    u64::try_from(value).with_context(|| format!("pak index field {label} is negative"))
}

fn read_fstring(buffer: &[u8], cursor: &mut usize) -> Result<String> {
    let length = read_i32(buffer, cursor)?;
    if length >= 0 {
        let length = length as usize;
        if length > MAX_PAK_STRING_BYTES {
            bail!("pak index string exceeds the bounded parser limit");
        }
        let bytes = read_bytes(buffer, cursor, length)?;
        let text = std::str::from_utf8(bytes).context("pak index string is not valid UTF-8")?;
        Ok(text.trim_end_matches('\0').to_owned())
    } else {
        let count = usize::try_from(length.checked_neg().context("pak index string length")?)?;
        if count > MAX_PAK_STRING_BYTES {
            bail!("pak index string exceeds the bounded parser limit");
        }
        let bytes = read_bytes(buffer, cursor, count * 2)?;
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let text =
            String::from_utf16(&units).context("pak index string is not valid UTF-16")?;
        Ok(text.trim_end_matches('\0').to_owned())
    }
}

fn sha1_bytes(bytes: &[u8]) -> [u8; 20] {
    let mut digest = Sha1::new();
    digest.update(bytes);
    digest.finalize().into()
}

fn footer_block_at(tail: &[u8], from_end: usize) -> Option<(u32, i32, u64, u64, [u8; 20])> {
    let base = tail.len().checked_sub(from_end)?;
    let magic = u32::from_le_bytes(tail[base..base + 4].try_into().ok()?);
    let version = i32::from_le_bytes(tail[base + 4..base + 8].try_into().ok()?);
    let index_offset = u64::from_le_bytes(tail[base + 8..base + 16].try_into().ok()?);
    let index_size = u64::from_le_bytes(tail[base + 16..base + 24].try_into().ok()?);
    let index_hash = tail[base + 24..base + 44].try_into().ok()?;
    Some((magic, version, index_offset, index_size, index_hash))
}

/// Parses the pak footer from a byte slice whose end coincides with the end of
/// the file. Only index versions 2-7 (legacy index) and 10-11 (path-hash /
/// directory index) are accepted; everything else fails closed.
fn parse_footer(tail: &[u8], file_len: u64) -> Result<PakFooter> {
    let mut candidates = Vec::new();
    if let Some((magic, version, index_offset, index_size, index_hash)) =
        footer_block_at(tail, LEGACY_FOOTER_TAIL_BYTES)
        && magic == PAK_MAGIC
        && (2..=7).contains(&version)
    {
        let encrypted_index = version >= 4
            && tail
                .len()
                .checked_sub(LEGACY_FOOTER_TAIL_BYTES + 1)
                .is_some_and(|position| tail[position] != 0);
        candidates.push(PakFooter {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted_index,
        });
    }
    if let Some((magic, version, index_offset, index_size, index_hash)) =
        footer_block_at(tail, MODERN_FOOTER_TAIL_BYTES)
        && magic == PAK_MAGIC
        && (10..=11).contains(&version)
    {
        let encrypted_index = tail
            .len()
            .checked_sub(MODERN_FOOTER_TAIL_BYTES + 1)
            .is_some_and(|position| tail[position] != 0);
        candidates.push(PakFooter {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted_index,
        });
    }
    let footer = match candidates.as_slice() {
        [footer] => *footer,
        [] => bail!(
            "no supported pak footer was found (the bounded parser accepts index versions 2-7 and 10-11)"
        ),
        _ => bail!("the pak footer is ambiguous across supported layouts"),
    };
    if footer.index_size < 5 || footer.index_size > MAX_PAK_INDEX_BYTES {
        bail!("pak index size {} is outside the bounded parser limits", footer.index_size);
    }
    let index_end = footer
        .index_offset
        .checked_add(footer.index_size)
        .context("pak index region overflows")?;
    if index_end > file_len {
        bail!("pak index region extends past the end of the file");
    }
    Ok(footer)
}

fn legacy_entry_header_size(version: i32, compression_method: u32, block_count: usize) -> u64 {
    let mut size: u64 = 8 + 8 + 8 + 4 + 20;
    if version >= 3 {
        if compression_method != 0 {
            size += 4 + 16 * block_count as u64;
        }
        size += 1 + 4;
    }
    size
}

fn parse_legacy_index(index: &[u8], version: i32) -> Result<(String, Vec<LegacyPakEntry>)> {
    let mut cursor = 0usize;
    let mount_point = read_fstring(index, &mut cursor)?;
    let entry_count = read_i32(index, &mut cursor)?;
    if entry_count < 0 || entry_count as usize > MAX_PAK_ENTRIES {
        bail!("pak index declares {entry_count} entries, outside the bounded parser limits");
    }
    let mut entries = Vec::with_capacity(entry_count as usize);
    for _ in 0..entry_count {
        let name = read_fstring(index, &mut cursor)?;
        let data_offset = read_i64_non_negative(index, &mut cursor, "entry offset")?;
        let compressed_size = read_i64_non_negative(index, &mut cursor, "entry size")?;
        let uncompressed_size =
            read_i64_non_negative(index, &mut cursor, "entry uncompressed size")?;
        let compression_method = read_u32(index, &mut cursor)?;
        let stored_hash: [u8; 20] = read_bytes(index, &mut cursor, 20)?.try_into()?;
        let mut compression_blocks = Vec::new();
        if version >= 3 && compression_method != 0 {
            let block_count = read_i32(index, &mut cursor)?;
            if block_count < 0 || block_count as usize > MAX_COMPRESSION_BLOCKS {
                bail!("pak entry declares {block_count} compression blocks, outside the bounded parser limits");
            }
            for _ in 0..block_count {
                let start = read_i64_non_negative(index, &mut cursor, "block start")?;
                let end = read_i64_non_negative(index, &mut cursor, "block end")?;
                compression_blocks.push((start, end));
            }
        }
        if version >= 3 {
            let _flags = read_bytes(index, &mut cursor, 1)?;
            let _block_size = read_u32(index, &mut cursor)?;
        }
        entries.push(LegacyPakEntry {
            name,
            data_offset,
            compressed_size,
            uncompressed_size,
            compression_method,
            stored_hash,
            compression_blocks,
        });
    }
    if cursor != index.len() {
        bail!(
            "pak index has {} undecoded trailing byte(s); the bounded parser fails closed",
            index.len() - cursor
        );
    }
    Ok((mount_point, entries))
}

/// Verifies one legacy entry fail-closed: data region bounds, stored-payload
/// SHA-1 against the index record, and (for zlib) a full block decompression
/// roundtrip to the declared uncompressed size. Returns the compression label.
fn verify_legacy_entry(
    pak: &[u8],
    footer: &PakFooter,
    entry: &LegacyPakEntry,
) -> Result<(&'static str, bool)> {
    let header_size = legacy_entry_header_size(
        footer.version,
        entry.compression_method,
        entry.compression_blocks.len(),
    );
    let payload_start = entry
        .data_offset
        .checked_add(header_size)
        .context("pak entry payload offset overflows")?;
    let payload_end = payload_start
        .checked_add(entry.compressed_size)
        .context("pak entry payload end overflows")?;
    if payload_end > footer.index_offset {
        bail!(
            "pak entry {} extends into the index region; the container is inconsistent",
            entry.name
        );
    }
    let payload = &pak[payload_start as usize..payload_end as usize];
    if sha1_bytes(payload) != entry.stored_hash {
        bail!(
            "pak entry {} failed its stored-payload SHA-1 integrity check",
            entry.name
        );
    }
    match entry.compression_method {
        0 => {
            if entry.compressed_size != entry.uncompressed_size {
                bail!(
                    "pak entry {} is stored uncompressed but declares mismatched sizes",
                    entry.name
                );
            }
            Ok(("none", true))
        }
        1 => {
            if entry.compression_blocks.is_empty() {
                bail!("pak entry {} is zlib compressed without a block table", entry.name);
            }
            if entry.uncompressed_size > MAX_DECOMPRESSED_ENTRY_BYTES {
                bail!(
                    "pak entry {} declares an uncompressed size outside the bounded parser limits",
                    entry.name
                );
            }
            // Block offsets are file-absolute in early index versions and
            // entry-relative from version 5. Community pak writers are not
            // consistent, so both interpretations are tried, but only one may
            // place every block inside this entry's verified payload region.
            let bases = [entry.data_offset, 0u64];
            let base = bases
                .into_iter()
                .find(|base| {
                    entry.compression_blocks.iter().all(|(start, end)| {
                        start < end
                            && base.checked_add(*start).is_some_and(|absolute| absolute >= payload_start)
                            && base
                                .checked_add(*end)
                                .is_some_and(|absolute| absolute <= payload_end)
                    })
                })
                .with_context(|| {
                    format!(
                        "pak entry {} compression blocks do not fit its payload region",
                        entry.name
                    )
                })?;
            let mut total_decompressed: u64 = 0;
            for (start, end) in &entry.compression_blocks {
                let block = &pak[(base + start) as usize..(base + end) as usize];
                let mut decoder = flate2::read::ZlibDecoder::new(block);
                let mut sink = Vec::new();
                let limit = MAX_DECOMPRESSED_ENTRY_BYTES
                    .saturating_sub(total_decompressed)
                    .saturating_add(1);
                decoder
                    .by_ref()
                    .take(limit)
                    .read_to_end(&mut sink)
                    .with_context(|| {
                        format!("pak entry {} zlib block did not decompress", entry.name)
                    })?;
                total_decompressed = total_decompressed.saturating_add(sink.len() as u64);
            }
            if total_decompressed != entry.uncompressed_size {
                bail!(
                    "pak entry {} decompressed to {} byte(s) but declares {}",
                    entry.name,
                    total_decompressed,
                    entry.uncompressed_size
                );
            }
            Ok(("zlib", true))
        }
        other => bail!(
            "pak entry {} uses compression method {other}, outside the proven passthrough subset (none, zlib)",
            entry.name
        ),
    }
}

fn normalized_slashes(raw: &str) -> String {
    raw.replace('\\', "/")
}

/// Strips leading `./` and `../` segments (the conventional `../../../` engine
/// mount prefix) and any leading slash, returning the remaining relative path.
fn strip_relative_prefix(raw: &str) -> String {
    let mut rest = raw.trim();
    loop {
        if let Some(stripped) = rest.strip_prefix("../") {
            rest = stripped;
        } else if let Some(stripped) = rest.strip_prefix("./") {
            rest = stripped;
        } else if let Some(stripped) = rest.strip_prefix('/') {
            rest = stripped;
        } else {
            break;
        }
    }
    rest.to_owned()
}

fn validate_clean_relative(path: &str, label: &str) -> Result<()> {
    if path.is_empty() {
        bail!("pak {label} is empty");
    }
    if path.contains(':') || path.contains("//") {
        bail!("pak {label} is not a clean relative path: {path}");
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        bail!("pak {label} contains unsafe path segments: {path}");
    }
    Ok(())
}

/// Resolves the pak mount point to a game-root-relative content prefix. The
/// mount must land inside `OblivionRemastered/Content` and outside `Paks`.
fn logical_mount_tail(mount_point: &str) -> Result<String> {
    let normalized = normalized_slashes(mount_point);
    let tail = strip_relative_prefix(&normalized);
    let trimmed = tail.trim_end_matches('/');
    validate_clean_relative(trimmed, "mount point")?;
    let lower = format!("{}/", trimmed.to_ascii_lowercase());
    if !lower.starts_with(GAME_CONTENT_PREFIX_LOWER) {
        bail!(
            "pak mount point does not target the game content root: {mount_point}"
        );
    }
    if lower.starts_with("oblivionremastered/content/paks/") {
        bail!("pak mount point targets the Paks directory itself: {mount_point}");
    }
    Ok(format!("{trimmed}/"))
}

fn logical_entry_path(mount_tail: &str, name: &str) -> Result<String> {
    let normalized = normalized_slashes(name);
    validate_clean_relative(&normalized, "entry path")?;
    Ok(format!("{mount_tail}{normalized}"))
}

fn path_extension_lower(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Classifies one mounted entry path into a content plane. Only planes with
/// proven passthrough semantics may reach the guarded candidate.
pub fn classify_content_plane(logical_path: &str) -> &'static str {
    let lower = logical_path.to_ascii_lowercase();
    let extension = path_extension_lower(&lower);
    if matches!(
        extension.as_str(),
        "uasset" | "umap" | "uexp" | "ubulk" | "uptnl" | "ushaderbytecode"
    ) {
        return "cooked-asset";
    }
    if lower.starts_with(WWISE_AUDIO_PREFIX_LOWER) && matches!(extension.as_str(), "wem" | "bnk") {
        return WWISE_AUDIO_MEDIA_PLANE;
    }
    if lower.starts_with(MOVIES_PREFIX_LOWER) {
        return "movie";
    }
    "unclassified-loose-file"
}

fn inspect_mod_pak(
    bytes: &[u8],
    file_name: &str,
    source_relative_path: &str,
) -> Result<PakPassthroughPak> {
    let file_len = bytes.len() as u64;
    let tail_len = file_len.min(FOOTER_SCAN_BYTES) as usize;
    let footer = parse_footer(&bytes[bytes.len() - tail_len..], file_len)?;
    if footer.encrypted_index {
        bail!("the pak index is encrypted; encrypted paks are outside the passthrough contract");
    }
    if !(2..=7).contains(&footer.version) {
        bail!(
            "pak index version {} lists entries but does not expose per-entry payload hashes to the bounded parser; passthrough remains fail-closed",
            footer.version
        );
    }
    let index =
        &bytes[footer.index_offset as usize..(footer.index_offset + footer.index_size) as usize];
    if sha1_bytes(index) != footer.index_hash {
        bail!("the pak index failed its SHA-1 integrity check against the footer");
    }
    let (mount_point, entries) = parse_legacy_index(index, footer.version)?;
    if entries.is_empty() {
        bail!("the pak contains no entries");
    }
    let mount_tail = logical_mount_tail(&mount_point)?;
    let stem = Path::new(file_name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let patch_priority_suffix = stem.to_ascii_lowercase().ends_with("_p");
    if !patch_priority_suffix {
        bail!(
            "pak file name {file_name} lacks the _P patch-priority suffix, so mount precedence over the shipped containers is not proven"
        );
    }
    let mut report_entries = Vec::with_capacity(entries.len());
    let mut logical_paths_lower = Vec::with_capacity(entries.len());
    for entry in &entries {
        let (compression, decompressed_size_verified) =
            verify_legacy_entry(bytes, &footer, entry)?;
        let logical_path = logical_entry_path(&mount_tail, &entry.name)?;
        let content_plane = classify_content_plane(&logical_path);
        logical_paths_lower.push(logical_path.to_ascii_lowercase());
        report_entries.push(PakPassthroughEntry {
            logical_path,
            content_plane: content_plane.to_owned(),
            compression: compression.to_owned(),
            compressed_bytes: entry.compressed_size,
            uncompressed_bytes: entry.uncompressed_size,
            stored_payload_sha1_verified: true,
            decompressed_size_verified,
            current_game_media_present: false,
        });
    }
    report_entries.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    logical_paths_lower.sort();
    logical_paths_lower.dedup();
    if logical_paths_lower.len() != report_entries.len() {
        bail!("the pak index lists duplicate logical paths");
    }
    Ok(PakPassthroughPak {
        file_name: file_name.to_owned(),
        source_relative_path: source_relative_path.to_owned(),
        install_relative_path: format!("{INSTALL_RELATIVE_PREFIX}{file_name}"),
        pak_sha256: sha256_bytes(bytes),
        pak_index_version: footer.version,
        mount_point,
        index_sha1_verified: true,
        patch_priority_suffix,
        entry_count: report_entries.len(),
        entries: report_entries,
    })
}

fn read_exact_region(file: &mut File, offset: u64, size: u64, label: &str) -> Result<Vec<u8>> {
    if size > MAX_PAK_INDEX_BYTES {
        bail!("{label} region is outside the bounded parser limits");
    }
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("seeking to the {label} region"))?;
    let mut buffer = vec![0u8; size as usize];
    file.read_exact(&mut buffer)
        .with_context(|| format!("reading the {label} region"))?;
    Ok(buffer)
}

/// Reads the current game's shipped legacy pak and returns the hash-verified
/// Wwise audio listing. Only the footer, primary index, and directory index
/// regions are read; asset payloads are never touched.
pub fn read_current_game_wwise_index(game_root: &Path) -> Result<CurrentGameAudioIndex> {
    let pak_path = game_root.join(GAME_MAIN_PAK_RELATIVE);
    let mut file = File::open(&pak_path).with_context(|| {
        format!(
            "the current game's shipped pak is required to prove audio targets: {}",
            pak_path.display()
        )
    })?;
    let file_len = file.metadata()?.len();
    let tail_len = file_len.min(FOOTER_SCAN_BYTES);
    let tail = read_exact_region(&mut file, file_len - tail_len, tail_len, "pak footer")?;
    let footer = parse_footer(&tail, file_len)?;
    if footer.encrypted_index {
        bail!("the current game pak index is encrypted");
    }
    let index = read_exact_region(
        &mut file,
        footer.index_offset,
        footer.index_size,
        "primary index",
    )?;
    if sha1_bytes(&index) != footer.index_hash {
        bail!("the current game pak primary index failed its SHA-1 integrity check");
    }
    let mut wwise_paths_lower = BTreeSet::new();
    let directory_index_sha1_verified;
    if footer.version >= 10 {
        let mut cursor = 0usize;
        let mount_point = read_fstring(&index, &mut cursor)?;
        let _entry_count = read_i32(&index, &mut cursor)?;
        let _path_hash_seed = read_u64(&index, &mut cursor)?;
        let has_path_hash_index = read_i32(&index, &mut cursor)?;
        if has_path_hash_index != 0 {
            let _offset = read_u64(&index, &mut cursor)?;
            let _size = read_u64(&index, &mut cursor)?;
            let _hash = read_bytes(&index, &mut cursor, 20)?;
        }
        let has_directory_index = read_i32(&index, &mut cursor)?;
        if has_directory_index == 0 {
            bail!("the current game pak has no full directory index to prove audio targets");
        }
        let directory_offset = read_i64_non_negative(&index, &mut cursor, "directory index offset")?;
        let directory_size = read_i64_non_negative(&index, &mut cursor, "directory index size")?;
        let directory_hash: [u8; 20] = read_bytes(&index, &mut cursor, 20)?.try_into()?;
        let directory = read_exact_region(
            &mut file,
            directory_offset,
            directory_size,
            "full directory index",
        )?;
        if sha1_bytes(&directory) != directory_hash {
            bail!("the current game pak directory index failed its SHA-1 integrity check");
        }
        directory_index_sha1_verified = true;
        let mount_tail = strip_relative_prefix(&normalized_slashes(&mount_point));
        let mut directory_cursor = 0usize;
        let directory_count = read_i32(&directory, &mut directory_cursor)?;
        if directory_count < 0 {
            bail!("the current game pak directory index is inconsistent");
        }
        for _ in 0..directory_count {
            let directory_name = read_fstring(&directory, &mut directory_cursor)?;
            let file_count = read_i32(&directory, &mut directory_cursor)?;
            if file_count < 0 {
                bail!("the current game pak directory index is inconsistent");
            }
            let directory_full = format!(
                "{mount_tail}{}",
                strip_relative_prefix(&normalized_slashes(&directory_name))
            );
            let directory_lower = directory_full.to_ascii_lowercase();
            let wwise_directory = directory_lower.starts_with(WWISE_AUDIO_PREFIX_LOWER);
            for _ in 0..file_count {
                let file_name = read_fstring(&directory, &mut directory_cursor)?;
                let _entry_location = read_u32(&directory, &mut directory_cursor)?;
                if wwise_directory {
                    wwise_paths_lower
                        .insert(format!("{directory_lower}{}", file_name.to_ascii_lowercase()));
                }
            }
        }
    } else {
        let (mount_point, entries) = parse_legacy_index(&index, footer.version)?;
        directory_index_sha1_verified = true;
        let mount_tail = strip_relative_prefix(&normalized_slashes(&mount_point));
        for entry in entries {
            let full = format!(
                "{mount_tail}{}",
                strip_relative_prefix(&normalized_slashes(&entry.name))
            )
            .to_ascii_lowercase();
            if full.starts_with(WWISE_AUDIO_PREFIX_LOWER) {
                wwise_paths_lower.insert(full);
            }
        }
    }
    if wwise_paths_lower.is_empty() {
        bail!("the current game pak lists no Wwise audio media; audio targets cannot be proven");
    }
    Ok(CurrentGameAudioIndex {
        pak_file_name: pak_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_owned(),
        pak_index_version: footer.version,
        primary_index_sha1_verified: true,
        directory_index_sha1_verified,
        wwise_media_file_count: wwise_paths_lower.len(),
        wwise_paths_lower,
    })
}

/// Fail-closed probe for the legacy pak passthrough lane. Every check that
/// does not pass exactly aborts with a precise reason; a returned summary
/// means the payload is a proven byte-preserving passthrough candidate.
pub fn probe_legacy_pak_passthrough_input(
    mod_input: &Path,
    game_root: &Path,
) -> Result<PakPassthroughProbeSummary> {
    let temporary = tempfile::Builder::new()
        .prefix("obr-pak-passthrough-")
        .tempdir()?;
    let staged = temporary.path().join("staged");
    stage_input(mod_input, &staged).context("staging the selected source for pak inspection")?;
    let mut pak_relative_paths = Vec::new();
    for entry in WalkDir::new(&staged).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&staged)?
            .to_string_lossy()
            .replace('\\', "/");
        match path_extension_lower(&relative).as_str() {
            "utoc" | "ucas" => bail!(
                "the input bundles IoStore containers; the legacy pak passthrough lane covers legacy .pak payloads only"
            ),
            "pak" => pak_relative_paths.push(relative),
            _ => {}
        }
    }
    if pak_relative_paths.is_empty() {
        bail!("the input contains no .pak payload");
    }
    if pak_relative_paths.len() > MAX_MOD_PAK_FILES {
        bail!(
            "the input contains {} pak files, outside the bounded passthrough limits",
            pak_relative_paths.len()
        );
    }
    let mut seen_names = BTreeMap::new();
    let mut inspected = Vec::new();
    for relative in &pak_relative_paths {
        let absolute = staged.join(relative.replace('/', "\\"));
        let declared = absolute.metadata()?.len();
        if declared > MAX_MOD_PAK_BYTES {
            bail!("pak file {relative} is larger than the bounded passthrough limit");
        }
        let bytes = fs::read(&absolute)?;
        let file_name = Path::new(relative)
            .file_name()
            .and_then(|value| value.to_str())
            .context("pak file has no name")?
            .to_owned();
        if let Some(previous) = seen_names.insert(file_name.to_ascii_lowercase(), relative.clone())
        {
            bail!(
                "two pak files share the install name {file_name} ({previous} and {relative}); the ~mods install plan would collide"
            );
        }
        let result = inspect_mod_pak(&bytes, &file_name, relative)
            .with_context(|| format!("validating pak {relative}"))?;
        inspected.push(result);
    }
    let mut planes = BTreeSet::new();
    for pak in &inspected {
        for entry in &pak.entries {
            planes.insert(entry.content_plane.clone());
        }
    }
    if planes.iter().any(|plane| plane != WWISE_AUDIO_MEDIA_PLANE) {
        let offending = inspected
            .iter()
            .flat_map(|pak| pak.entries.iter())
            .find(|entry| entry.content_plane != WWISE_AUDIO_MEDIA_PLANE)
            .context("offending entry")?;
        bail!(
            "entry {} is on the {} content plane; the proven passthrough contract covers the {} plane only",
            offending.logical_path,
            offending.content_plane,
            WWISE_AUDIO_MEDIA_PLANE
        );
    }
    let current_game = read_current_game_wwise_index(game_root)?;
    let mut matched_current_media_count = 0usize;
    let mut missing = Vec::new();
    for pak in &mut inspected {
        for entry in &mut pak.entries {
            if current_game
                .wwise_paths_lower
                .contains(&entry.logical_path.to_ascii_lowercase())
            {
                entry.current_game_media_present = true;
                matched_current_media_count += 1;
            } else {
                missing.push(entry.logical_path.clone());
            }
        }
    }
    if !missing.is_empty() {
        missing.sort();
        bail!(
            "{} audio media entr(ies) are not present in the current game's shipped pak index (first: {}); the replacement would target retired content",
            missing.len(),
            missing[0]
        );
    }
    let mut paks = inspected;
    paks.sort_by(|left, right| {
        left.file_name
            .to_ascii_lowercase()
            .cmp(&right.file_name.to_ascii_lowercase())
    });
    let entry_count = paks.iter().map(|pak| pak.entry_count).sum();
    Ok(PakPassthroughProbeSummary {
        api: LEGACY_PAK_PASSTHROUGH_PROBE_API.to_owned(),
        pak_count: paks.len(),
        entry_count,
        content_planes: planes.into_iter().collect(),
        current_game,
        matched_current_media_count,
        paks,
        disclosures: vec![
            "The candidate pak payload is version-passthrough: source bytes are preserved exactly and nothing is structurally rebuilt for the current game version.".to_owned(),
            "Wwise audio media entries are content-keyed by media ID; every entry was matched against the current game's hash-verified shipped pak index.".to_owned(),
            "Runtime verification in the shipping game is still required before this candidate is called compatible.".to_owned(),
        ],
    })
}

/// Copies each proven pak byte-for-byte into the canonical `~mods` install
/// layout below `destination_root` and re-verifies the published hashes.
pub fn publish_passthrough_paks(
    mod_input: &Path,
    summary: &PakPassthroughProbeSummary,
    destination_root: &Path,
) -> Result<Vec<(String, String)>> {
    let temporary = tempfile::Builder::new()
        .prefix("obr-pak-publish-")
        .tempdir()?;
    let staged = temporary.path().join("staged");
    stage_input(mod_input, &staged).context("staging the selected source for publication")?;
    let mut mappings = Vec::new();
    for pak in &summary.paks {
        let source = staged.join(pak.source_relative_path.replace('/', "\\"));
        let destination = destination_root.join(pak.install_relative_path.replace('/', "\\"));
        fs::create_dir_all(
            destination
                .parent()
                .context("install destination has no parent")?,
        )?;
        fs::copy(&source, &destination).with_context(|| {
            format!("publishing {} to the candidate", pak.source_relative_path)
        })?;
        let published_hash = sha256_file(&destination)?;
        if published_hash != pak.pak_sha256 {
            bail!(
                "published pak {} does not byte-match its verified source",
                pak.file_name
            );
        }
        mappings.push((
            pak.source_relative_path.clone(),
            pak.install_relative_path.clone(),
        ));
    }
    Ok(mappings)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::io::Write;

    fn write_fstring(buffer: &mut Vec<u8>, text: &str) {
        buffer.extend_from_slice(&(i32::try_from(text.len() + 1).unwrap()).to_le_bytes());
        buffer.extend_from_slice(text.as_bytes());
        buffer.push(0);
    }

    pub(crate) struct SyntheticEntry {
        pub name: String,
        pub payload: Vec<u8>,
        pub zlib: bool,
    }

    /// Writes a version-3 legacy pak with the given mount point and entries.
    pub(crate) fn write_legacy_pak_v3(mount_point: &str, entries: &[SyntheticEntry]) -> Vec<u8> {
        const VERSION: i32 = 3;
        let mut data = Vec::new();
        let mut records = Vec::new();
        for entry in entries {
            let data_offset = data.len() as u64;
            let (stored, method, blocks): (Vec<u8>, u32, Vec<(u64, u64)>) = if entry.zlib {
                let mut encoder = flate2::write::ZlibEncoder::new(
                    Vec::new(),
                    flate2::Compression::default(),
                );
                encoder.write_all(&entry.payload).unwrap();
                let compressed = encoder.finish().unwrap();
                let header =
                    legacy_entry_header_size(VERSION, 1, 1);
                let blocks = vec![(header, header + compressed.len() as u64)];
                (compressed, 1, blocks)
            } else {
                (entry.payload.clone(), 0, Vec::new())
            };
            let stored_hash = sha1_bytes(&stored);
            let header_size =
                legacy_entry_header_size(VERSION, method, blocks.len());
            // Duplicated local entry header: contents are not validated by the
            // bounded parser, only its size participates in payload placement.
            data.extend_from_slice(&vec![0u8; header_size as usize]);
            data.extend_from_slice(&stored);
            records.push((
                entry.name.clone(),
                data_offset,
                stored.len() as u64,
                entry.payload.len() as u64,
                method,
                stored_hash,
                blocks,
            ));
        }
        let index_offset = data.len() as u64;
        let mut index = Vec::new();
        write_fstring(&mut index, mount_point);
        index.extend_from_slice(&(records.len() as i32).to_le_bytes());
        for (name, offset, compressed, uncompressed, method, hash, blocks) in &records {
            write_fstring(&mut index, name);
            index.extend_from_slice(&(*offset as i64).to_le_bytes());
            index.extend_from_slice(&(*compressed as i64).to_le_bytes());
            index.extend_from_slice(&(*uncompressed as i64).to_le_bytes());
            index.extend_from_slice(&method.to_le_bytes());
            index.extend_from_slice(hash);
            if *method != 0 {
                index.extend_from_slice(&(blocks.len() as i32).to_le_bytes());
                for (start, end) in blocks {
                    index.extend_from_slice(&(*start as i64).to_le_bytes());
                    index.extend_from_slice(&(*end as i64).to_le_bytes());
                }
            }
            index.push(0);
            index.extend_from_slice(&0u32.to_le_bytes());
        }
        let index_hash = sha1_bytes(&index);
        let mut pak = data;
        pak.extend_from_slice(&index);
        pak.extend_from_slice(&PAK_MAGIC.to_le_bytes());
        pak.extend_from_slice(&VERSION.to_le_bytes());
        pak.extend_from_slice(&index_offset.to_le_bytes());
        pak.extend_from_slice(&(index.len() as u64).to_le_bytes());
        pak.extend_from_slice(&index_hash);
        pak
    }

    /// Writes a version-11 pak whose primary and full directory indexes list
    /// the given mounted paths. Entry payloads are not written; the listing is
    /// what the game-side reader proves.
    pub(crate) fn write_modern_listing_pak(paths: &[&str]) -> Vec<u8> {
        let mut directories: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for path in paths {
            let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
            directories
                .entry(if directory.is_empty() {
                    "/".to_owned()
                } else {
                    format!("{directory}/")
                })
                .or_default()
                .push(name.to_owned());
        }
        let mut directory_index = Vec::new();
        directory_index.extend_from_slice(&(directories.len() as i32).to_le_bytes());
        for (directory, files) in &directories {
            write_fstring(&mut directory_index, directory);
            directory_index.extend_from_slice(&(files.len() as i32).to_le_bytes());
            for file in files {
                write_fstring(&mut directory_index, file);
                directory_index.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        let directory_offset = 0u64;
        let directory_hash = sha1_bytes(&directory_index);
        let mut primary = Vec::new();
        write_fstring(&mut primary, "../../../");
        primary.extend_from_slice(&(paths.len() as i32).to_le_bytes());
        primary.extend_from_slice(&0u64.to_le_bytes());
        primary.extend_from_slice(&0i32.to_le_bytes());
        primary.extend_from_slice(&1i32.to_le_bytes());
        primary.extend_from_slice(&(directory_offset as i64).to_le_bytes());
        primary.extend_from_slice(&(directory_index.len() as i64).to_le_bytes());
        primary.extend_from_slice(&directory_hash);
        let index_offset = directory_index.len() as u64;
        let index_size = primary.len() as u64;
        let index_hash = sha1_bytes(&primary);
        let mut pak = directory_index;
        pak.extend_from_slice(&primary);
        pak.extend_from_slice(&[0u8; 16]);
        pak.push(0);
        pak.extend_from_slice(&PAK_MAGIC.to_le_bytes());
        pak.extend_from_slice(&11i32.to_le_bytes());
        pak.extend_from_slice(&index_offset.to_le_bytes());
        pak.extend_from_slice(&index_size.to_le_bytes());
        pak.extend_from_slice(&index_hash);
        pak.extend_from_slice(&[0u8; 160]);
        pak
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{SyntheticEntry, write_legacy_pak_v3, write_modern_listing_pak};
    use super::*;

    const MOUNT: &str = "../../../OblivionRemastered/Content/WwiseAudio/Media/";

    fn sound_entries() -> Vec<SyntheticEntry> {
        vec![
            SyntheticEntry {
                name: "1020757059.wem".to_owned(),
                payload: b"plain wwise payload".to_vec(),
                zlib: false,
            },
            SyntheticEntry {
                name: "240112521.wem".to_owned(),
                payload: b"zlib wwise payload zlib wwise payload".to_vec(),
                zlib: true,
            },
        ]
    }

    #[test]
    fn verifies_a_valid_v3_sound_pak_end_to_end() {
        let pak = write_legacy_pak_v3(MOUNT, &sound_entries());
        let inspected = inspect_mod_pak(&pak, "Fixture_P.pak", "Fixture_P.pak").unwrap();
        assert_eq!(inspected.pak_index_version, 3);
        assert_eq!(inspected.entry_count, 2);
        assert!(inspected.index_sha1_verified);
        assert!(inspected.patch_priority_suffix);
        assert_eq!(
            inspected.entries[0].logical_path,
            "OblivionRemastered/Content/WwiseAudio/Media/1020757059.wem"
        );
        assert!(
            inspected
                .entries
                .iter()
                .all(|entry| entry.content_plane == WWISE_AUDIO_MEDIA_PLANE
                    && entry.stored_payload_sha1_verified
                    && entry.decompressed_size_verified)
        );
        assert_eq!(inspected.entries[0].compression, "none");
        assert_eq!(inspected.entries[1].compression, "zlib");
    }

    #[test]
    fn rejects_a_tampered_payload_byte() {
        let mut pak = write_legacy_pak_v3(MOUNT, &sound_entries());
        // Flip one byte inside the first entry's stored payload region.
        let header = legacy_entry_header_size(3, 0, 0) as usize;
        pak[header] ^= 0xFF;
        let error = inspect_mod_pak(&pak, "Fixture_P.pak", "Fixture_P.pak").unwrap_err();
        assert!(error.to_string().contains("SHA-1"), "{error:#}");
    }

    #[test]
    fn rejects_a_tampered_index() {
        let mut pak = write_legacy_pak_v3(MOUNT, &sound_entries());
        let tampered_position = pak.len() - LEGACY_FOOTER_TAIL_BYTES - 3;
        pak[tampered_position] ^= 0xFF;
        let error = inspect_mod_pak(&pak, "Fixture_P.pak", "Fixture_P.pak").unwrap_err();
        assert!(error.to_string().contains("integrity"), "{error:#}");
    }

    #[test]
    fn rejects_a_mount_point_outside_the_game_content_root() {
        let pak = write_legacy_pak_v3("../../../Engine/Content/", &sound_entries());
        let error = inspect_mod_pak(&pak, "Fixture_P.pak", "Fixture_P.pak").unwrap_err();
        assert!(error.to_string().contains("content root"), "{error:#}");
    }

    #[test]
    fn rejects_a_pak_without_the_patch_priority_suffix() {
        let pak = write_legacy_pak_v3(MOUNT, &sound_entries());
        let error = inspect_mod_pak(&pak, "Fixture.pak", "Fixture.pak").unwrap_err();
        assert!(error.to_string().contains("_P"), "{error:#}");
    }

    #[test]
    fn classifies_cooked_assets_and_foreign_planes() {
        assert_eq!(
            classify_content_plane("OblivionRemastered/Content/Art/SK_Armor.uasset"),
            "cooked-asset"
        );
        assert_eq!(
            classify_content_plane("OblivionRemastered/Content/WwiseAudio/Media/1.wem"),
            WWISE_AUDIO_MEDIA_PLANE
        );
        assert_eq!(
            classify_content_plane("OblivionRemastered/Content/Movies/intro.bk2"),
            "movie"
        );
        assert_eq!(
            classify_content_plane("OblivionRemastered/Content/WwiseAudio/Media/readme.txt"),
            "unclassified-loose-file"
        );
    }

    #[test]
    fn reads_a_modern_listing_pak_for_the_current_game() {
        let listing = write_modern_listing_pak(&[
            "OblivionRemastered/Content/WwiseAudio/Media/1020757059.wem",
            "OblivionRemastered/Content/WwiseAudio/Media/240112521.wem",
            "OblivionRemastered/Content/Paks/pakchunk0.pak",
        ]);
        let root = tempfile::tempdir().unwrap();
        let pak_path = root.path().join(GAME_MAIN_PAK_RELATIVE);
        fs::create_dir_all(pak_path.parent().unwrap()).unwrap();
        fs::write(&pak_path, listing).unwrap();
        let index = read_current_game_wwise_index(root.path()).unwrap();
        assert_eq!(index.pak_index_version, 11);
        assert!(index.primary_index_sha1_verified);
        assert!(index.directory_index_sha1_verified);
        assert_eq!(index.wwise_media_file_count, 2);
        assert!(
            index
                .wwise_paths_lower
                .contains("oblivionremastered/content/wwiseaudio/media/1020757059.wem")
        );
    }

    #[test]
    fn probes_a_pak_only_mod_against_a_synthetic_current_game() {
        let mod_root = tempfile::tempdir().unwrap();
        let pak = write_legacy_pak_v3(MOUNT, &sound_entries());
        fs::write(mod_root.path().join("Fixture_P.pak"), pak).unwrap();
        let game_root = tempfile::tempdir().unwrap();
        let listing = write_modern_listing_pak(&[
            "OblivionRemastered/Content/WwiseAudio/Media/1020757059.wem",
            "OblivionRemastered/Content/WwiseAudio/Media/240112521.wem",
        ]);
        let pak_path = game_root.path().join(GAME_MAIN_PAK_RELATIVE);
        fs::create_dir_all(pak_path.parent().unwrap()).unwrap();
        fs::write(&pak_path, listing).unwrap();
        let summary =
            probe_legacy_pak_passthrough_input(mod_root.path(), game_root.path()).unwrap();
        assert_eq!(summary.pak_count, 1);
        assert_eq!(summary.entry_count, 2);
        assert_eq!(summary.matched_current_media_count, 2);
        assert_eq!(summary.content_planes, vec![WWISE_AUDIO_MEDIA_PLANE]);
        assert_eq!(
            summary.paks[0].install_relative_path,
            "OblivionRemastered/Content/Paks/~mods/Fixture_P.pak"
        );
    }

    #[test]
    fn probe_fails_closed_when_media_is_missing_from_the_current_game() {
        let mod_root = tempfile::tempdir().unwrap();
        let pak = write_legacy_pak_v3(MOUNT, &sound_entries());
        fs::write(mod_root.path().join("Fixture_P.pak"), pak).unwrap();
        let game_root = tempfile::tempdir().unwrap();
        let listing = write_modern_listing_pak(&[
            "OblivionRemastered/Content/WwiseAudio/Media/1020757059.wem",
        ]);
        let pak_path = game_root.path().join(GAME_MAIN_PAK_RELATIVE);
        fs::create_dir_all(pak_path.parent().unwrap()).unwrap();
        fs::write(&pak_path, listing).unwrap();
        let error =
            probe_legacy_pak_passthrough_input(mod_root.path(), game_root.path()).unwrap_err();
        assert!(error.to_string().contains("not present"), "{error:#}");
    }
}
