use anyhow::{Context, Result, bail};
use flate2::read::ZlibDecoder;
use flate2::{Compression, write::ZlibEncoder};
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const COMPRESSED_RECORD: u32 = 0x0004_0000;
pub const DELETED_RECORD: u32 = 0x0000_0020;
pub const INITIALLY_DISABLED_RECORD: u32 = 0x0000_0800;
pub const MASTER_FILE: u32 = 0x0000_0001;
pub const LIGHT_PLUGIN: u32 = 0x0000_0200;
pub const GROUP_CELL_CHILDREN: u32 = 6;
pub const GROUP_CELL_PERSISTENT_CHILDREN: u32 = 8;
pub const GROUP_CELL_TEMPORARY_CHILDREN: u32 = 9;
/// The Z position every undeleted-and-disabled reference is parked at, matching the
/// industry-standard "undelete and disable references" pattern.
pub const UNDELETE_DISABLED_Z: f32 = -30000.0;
/// XESP flag 0x1: set enable state to the opposite of the parent reference.
pub const ENABLE_STATE_OPPOSITE_OF_PARENT: u32 = 0x0000_0001;
const MAX_EXPANDED_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_EXPANDED_PLUGIN_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Subrecord {
    pub kind: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Record {
    pub kind: String,
    pub form_id: u32,
    pub flags: u32,
    pub subrecords: Vec<Subrecord>,
}

#[derive(Clone, Debug)]
pub struct Plugin {
    pub header_flags: u32,
    pub masters: Vec<String>,
    pub declared_record_count: u32,
    pub next_object_id: u32,
    pub group_count: usize,
    /// GRUP headers that declared a zero byte size and were recovered as
    /// header-only empty groups. Disclosed by structural analysis; the
    /// byte-splicing rewrite path still refuses such plugins.
    pub recovered_zero_size_group_count: usize,
    pub records: Vec<Record>,
}

pub const SELF_SLOT_BASIS_NO_SOURCE_RECORDS: &str = "no-source-records";
pub const SELF_SLOT_BASIS_MASTER_COUNT: &str = "master-count";
pub const SELF_SLOT_BASIS_PRESERVED_OUT_OF_RANGE: &str = "preserved-out-of-range";

/// Unique-only self-slot inference ported from the Unblivion TES lineage
/// scanner: the slot that holds a plugin's own records is provable only when
/// the record headers use at most one distinct FormID master-index at or
/// beyond the declared master count. No such index means the conventional
/// master-count slot; exactly one distinct value is the plugin's own slot
/// (retail AltarDeluxe preserves slot 13 while declaring twelve masters);
/// two or more distinct undeclared slots are ambiguous and fail closed with
/// every candidate disclosed instead of guessing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelfSlotInference {
    Inferred { self_index: u8, basis: &'static str },
    Ambiguous { candidates: Vec<u8> },
}

impl SelfSlotInference {
    pub fn self_index(&self) -> Option<u8> {
        match self {
            Self::Inferred { self_index, .. } => Some(*self_index),
            Self::Ambiguous { .. } => None,
        }
    }
}

pub fn infer_self_slot(master_count: u8, records: &[Record]) -> SelfSlotInference {
    let mut candidates = records
        .iter()
        .map(|record| (record.form_id >> 24) as u8)
        .filter(|index| *index >= master_count)
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.as_slice() {
        [] => SelfSlotInference::Inferred {
            self_index: master_count,
            basis: SELF_SLOT_BASIS_NO_SOURCE_RECORDS,
        },
        [single] if *single == master_count => SelfSlotInference::Inferred {
            self_index: *single,
            basis: SELF_SLOT_BASIS_MASTER_COUNT,
        },
        [single] => SelfSlotInference::Inferred {
            self_index: *single,
            basis: SELF_SLOT_BASIS_PRESERVED_OUT_OF_RANGE,
        },
        _ if candidates.contains(&master_count) => SelfSlotInference::Inferred {
            self_index: master_count,
            basis: "master-count-with-out-of-range-siblings",
        },
        _ => SelfSlotInference::Ambiguous { candidates },
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddedInventoryEntry {
    pub item_form_id: String,
    pub count: i32,
    pub reference_scope: String,
    pub reference_validated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideResult {
    pub form_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub compatible_with_current_master: bool,
    pub allowed_presentation_changes: Vec<String>,
    pub added_inventory_entries: Vec<AddedInventoryEntry>,
    pub preserved_current_master_entries: Vec<AddedInventoryEntry>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncMapEntry {
    pub key: String,
    pub local_form_id: String,
    pub object_path: String,
    pub package_path: String,
}

fn read_u16(reader: &mut impl Read) -> Result<u16> {
    let mut bytes = [0; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(reader: &mut impl Read) -> Result<u32> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_fourcc(reader: &mut impl Read) -> Result<String> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn expand_record_data_with_budget(
    raw: Vec<u8>,
    flags: u32,
    remaining_budget: &mut usize,
) -> Result<Vec<u8>> {
    if flags & COMPRESSED_RECORD == 0 {
        *remaining_budget = remaining_budget
            .checked_sub(raw.len())
            .context("TES4 plugin exceeds the total expanded-data safety limit")?;
        return Ok(raw);
    }
    if raw.len() < 4 {
        bail!("compressed TES4 record payload is truncated");
    }
    let expected = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
    if expected > MAX_EXPANDED_RECORD_BYTES {
        bail!(
            "compressed TES4 record declares {expected} expanded bytes; limit is {MAX_EXPANDED_RECORD_BYTES}"
        );
    }
    if expected > *remaining_budget {
        bail!(
            "TES4 plugin exceeds the {MAX_TOTAL_EXPANDED_PLUGIN_BYTES} byte total expanded-data safety limit"
        );
    }
    let mut decoder = ZlibDecoder::new(&raw[4..]);
    let mut output = Vec::with_capacity(expected);
    decoder
        .by_ref()
        .take(expected.saturating_add(1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > expected {
        bail!("compressed TES4 record output exceeds its declared size of {expected} bytes");
    }
    if output.len() != expected {
        bail!(
            "compressed TES4 record size mismatch: expected {expected}, got {}",
            output.len()
        );
    }
    *remaining_budget -= output.len();
    Ok(output)
}

#[cfg(test)]
fn expand_record_data(raw: Vec<u8>, flags: u32) -> Result<Vec<u8>> {
    let mut budget = MAX_TOTAL_EXPANDED_PLUGIN_BYTES;
    expand_record_data_with_budget(raw, flags, &mut budget)
}

fn read_subrecords(data: &[u8]) -> Result<Vec<Subrecord>> {
    let mut cursor = Cursor::new(data);
    let mut rows = Vec::new();
    let mut extended_size = None;
    while cursor.position() as usize + 6 <= data.len() {
        let kind = read_fourcc(&mut cursor)?;
        let size16 = read_u16(&mut cursor)?;
        if kind == "XXXX" && size16 == 4 {
            extended_size = Some(read_u32(&mut cursor)?);
            continue;
        }
        let size = extended_size.take().unwrap_or(size16 as u32) as usize;
        if cursor.position() as usize + size > data.len() {
            bail!("truncated {kind} subrecord: size={size}");
        }
        let mut payload = vec![0; size];
        cursor.read_exact(&mut payload)?;
        rows.push(Subrecord {
            kind,
            data: payload,
        });
    }
    if cursor.position() as usize != data.len() {
        bail!(
            "TES4 subrecord stream has {} trailing bytes",
            data.len() - cursor.position() as usize
        );
    }
    Ok(rows)
}

fn subrecord_string(subrecord: &Subrecord) -> String {
    let end = subrecord
        .data
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|index| index + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&subrecord.data[..end]).into_owned()
}

// Editor IDs give us a content identity that does not depend on an author's folder layout.
pub fn record_editor_id(record: &Record) -> Option<String> {
    let mut values = record
        .subrecords
        .iter()
        .filter(|subrecord| subrecord.kind == "EDID")
        .map(subrecord_string);
    let value = values.next()?;
    if value.is_empty() || values.next().is_some() {
        return None;
    }
    Some(value)
}

pub fn read_plugin_bytes(bytes: &[u8], source: &str) -> Result<Plugin> {
    let mut reader = Cursor::new(bytes);
    let mut expanded_budget = MAX_TOTAL_EXPANDED_PLUGIN_BYTES;
    if read_fourcc(&mut reader)? != "TES4" {
        bail!("not a TES4 plugin: {source}");
    }
    let header_size = read_u32(&mut reader)? as usize;
    let header_flags = read_u32(&mut reader)?;
    let _header_form_id = read_u32(&mut reader)?;
    let _header_version_control = read_u32(&mut reader)?;
    if header_size > bytes.len().saturating_sub(reader.position() as usize) {
        bail!("truncated TES4 header in {source}: size={header_size}");
    }
    let mut header_raw = vec![0; header_size];
    reader.read_exact(&mut header_raw)?;
    let header_data =
        expand_record_data_with_budget(header_raw, header_flags, &mut expanded_budget)?;
    let header_subs = read_subrecords(&header_data)?;
    let masters = header_subs
        .iter()
        .filter(|sub| sub.kind == "MAST")
        .map(subrecord_string)
        .collect::<Vec<_>>();
    let hedr = header_subs
        .iter()
        .find(|sub| sub.kind == "HEDR" && sub.data.len() >= 12)
        .context("TES4 header has no valid HEDR")?;
    let declared_record_count = u32::from_le_bytes(hedr.data[4..8].try_into().unwrap());
    let next_object_id = u32::from_le_bytes(hedr.data[8..12].try_into().unwrap());
    let mut group_count = 0_usize;
    let mut recovered_zero_size_group_count = 0_usize;
    let mut records = Vec::new();
    while reader.position() as usize + 20 <= bytes.len() {
        let start = reader.position();
        let kind = read_fourcc(&mut reader)?;
        if kind == "GRUP" {
            let group_size = read_u32(&mut reader)? as u64;
            if group_size == 0 {
                // Some author tools write a zero byte size into an otherwise
                // well-formed GRUP header. Every child that follows must still
                // parse as complete records/groups, so the header is recovered
                // as an empty group and the recovery is counted for disclosure.
                recovered_zero_size_group_count += 1;
                group_count += 1;
                reader.seek(SeekFrom::Current(12))?;
                continue;
            }
            if group_size < 20 || start + group_size > bytes.len() as u64 {
                bail!("invalid GRUP at 0x{start:X} in {source}");
            }
            group_count += 1;
            reader.seek(SeekFrom::Current(12))?;
            continue;
        }
        let data_size = read_u32(&mut reader)? as usize;
        let flags = read_u32(&mut reader)?;
        let form_id = read_u32(&mut reader)?;
        let _version_control = read_u32(&mut reader)?;
        if reader.position() as usize + data_size > bytes.len() {
            bail!("truncated {kind} record 0x{form_id:08X}");
        }
        let mut raw = vec![0; data_size];
        reader.read_exact(&mut raw)?;
        let data = expand_record_data_with_budget(raw, flags, &mut expanded_budget)?;
        records.push(Record {
            kind,
            form_id,
            flags,
            subrecords: read_subrecords(&data)?,
        });
    }
    if reader.position() as usize != bytes.len() {
        bail!(
            "TES4 plugin has {} trailing bytes after the last complete record: {source}",
            bytes.len() - reader.position() as usize
        );
    }
    Ok(Plugin {
        header_flags,
        masters,
        declared_record_count,
        next_object_id,
        group_count,
        recovered_zero_size_group_count,
        records,
    })
}

pub fn read_plugin(path: &Path) -> Result<Plugin> {
    let bytes = fs::read(path).with_context(|| format!("reading plugin {}", path.display()))?;
    let source = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("plugin");
    read_plugin_bytes(&bytes, source).with_context(|| format!("parsing plugin {}", path.display()))
}

pub fn read_target_records(path: &Path, form_ids: &[u32]) -> Result<HashMap<u32, Record>> {
    let wanted = form_ids.iter().copied().collect::<HashSet<_>>();
    let mut found = HashMap::new();
    let mut reader = File::open(path).with_context(|| format!("opening ESM {}", path.display()))?;
    let length = reader.metadata()?.len();
    let mut expanded_budget = MAX_TOTAL_EXPANDED_PLUGIN_BYTES;
    while reader.stream_position()? + 20 <= length && found.len() < wanted.len() {
        let start = reader.stream_position()?;
        let kind = read_fourcc(&mut reader)?;
        if kind == "GRUP" {
            let group_size = read_u32(&mut reader)? as u64;
            if group_size < 20 || start + group_size > length {
                bail!("invalid ESM GRUP at 0x{start:X}");
            }
            reader.seek(SeekFrom::Current(12))?;
            continue;
        }
        let data_size = read_u32(&mut reader)? as usize;
        let flags = read_u32(&mut reader)?;
        let form_id = read_u32(&mut reader)?;
        let _version_control = read_u32(&mut reader)?;
        if reader.stream_position()? + data_size as u64 > length {
            bail!("truncated ESM record {kind} 0x{form_id:08X}");
        }
        if wanted.contains(&form_id) {
            let mut raw = vec![0; data_size];
            reader.read_exact(&mut raw)?;
            let data = expand_record_data_with_budget(raw, flags, &mut expanded_budget)?;
            found.insert(
                form_id,
                Record {
                    kind,
                    form_id,
                    flags,
                    subrecords: read_subrecords(&data)?,
                },
            );
        } else {
            reader.seek(SeekFrom::Current(data_size as i64))?;
        }
    }
    Ok(found)
}

fn token(subrecord: &Subrecord) -> Vec<u8> {
    let mut value = subrecord.kind.as_bytes().to_vec();
    value.push(b':');
    value.extend_from_slice(&subrecord.data);
    value
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct InventoryToken {
    item_form_id: u32,
    count: i32,
    extra_data: Vec<Vec<u8>>,
}

struct InventoryRecordParts {
    non_inventory_tokens: Vec<Vec<u8>>,
    inventory: Vec<InventoryToken>,
    declared_inventory_count: Option<u32>,
}

pub fn supports_additive_inventory_record(kind: &str) -> bool {
    matches!(kind, "CONT" | "CREA" | "NPC_")
}

fn split_inventory_record(
    record: &Record,
    plugin_index: Option<u8>,
) -> Result<InventoryRecordParts> {
    if !supports_additive_inventory_record(&record.kind) {
        bail!(
            "{} 0x{:08X} is not a supported inventory-bearing record",
            record.kind,
            record.form_id
        );
    }
    let mut non_inventory_tokens = Vec::new();
    let mut inventory = Vec::new();
    let mut declared_inventory_count = None;
    let mut index = 0;
    while index < record.subrecords.len() {
        let subrecord = &record.subrecords[index];
        match subrecord.kind.as_str() {
            "COCT" => {
                if declared_inventory_count.is_some() || subrecord.data.len() != 4 {
                    bail!(
                        "{} 0x{:08X} has an invalid or duplicate COCT subrecord",
                        record.kind,
                        record.form_id
                    );
                }
                declared_inventory_count =
                    Some(u32::from_le_bytes(subrecord.data[..4].try_into().unwrap()));
            }
            "CNTO" => {
                if subrecord.data.len() != 8 {
                    bail!(
                        "{} 0x{:08X} has a CNTO subrecord with {} bytes instead of 8",
                        record.kind,
                        record.form_id,
                        subrecord.data.len()
                    );
                }
                let item_form_id = u32::from_le_bytes(subrecord.data[..4].try_into().unwrap());
                let count = i32::from_le_bytes(subrecord.data[4..8].try_into().unwrap());
                if let Some(plugin_index) = plugin_index
                    && (item_form_id >> 24) as u8 > plugin_index
                {
                    bail!(
                        "{} 0x{:08X} references inventory item 0x{item_form_id:08X} beyond plugin index {plugin_index}",
                        record.kind,
                        record.form_id
                    );
                }
                let mut extra_data = Vec::new();
                while index + 1 < record.subrecords.len()
                    && record.subrecords[index + 1].kind == "COED"
                {
                    index += 1;
                    extra_data.push(token(&record.subrecords[index]));
                }
                inventory.push(InventoryToken {
                    item_form_id,
                    count,
                    extra_data,
                });
            }
            "COED" => bail!(
                "{} 0x{:08X} has an orphan COED inventory extension",
                record.kind,
                record.form_id
            ),
            _ => non_inventory_tokens.push(token(subrecord)),
        }
        index += 1;
    }
    inventory.sort();
    Ok(InventoryRecordParts {
        non_inventory_tokens,
        inventory,
        declared_inventory_count,
    })
}

pub fn container_inventory_form_ids(record: &Record) -> Result<Vec<u32>> {
    let mut ids = split_inventory_record(record, None)?
        .inventory
        .into_iter()
        .map(|entry| entry.item_form_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

fn additions_against_current(
    override_inventory: &[InventoryToken],
    current_inventory: &[InventoryToken],
) -> Option<Vec<InventoryToken>> {
    let mut remaining = override_inventory.to_vec();
    for current in current_inventory {
        let index = remaining
            .iter()
            .position(|candidate| candidate == current)?;
        remaining.remove(index);
    }
    Some(remaining)
}
fn inventory_evidence(entries: &[InventoryToken]) -> String {
    entries
        .iter()
        .map(|entry| {
            format!(
                "0x{:08X}:{}:{}",
                entry.item_form_id,
                entry.count,
                entry.extra_data.len()
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}
#[derive(Debug, Eq, PartialEq)]
struct FunctionalSemantics {
    ordered_tokens: Vec<Vec<u8>>,
    sorted_factions: Vec<Vec<u8>>,
    sorted_spells: Vec<Vec<u8>>,
    sorted_model_paths: Vec<Vec<u8>>,
}

fn normalized_model_paths(token: &[u8], record: &Record) -> Result<Vec<Vec<u8>>> {
    let data = token.get(5..).unwrap_or_default();
    if !data.is_empty() && !data.ends_with(&[0]) {
        bail!(
            "{} 0x{:08X} has a malformed NIFZ model list",
            record.kind,
            record.form_id
        );
    }
    let mut paths = data
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| path.to_ascii_lowercase())
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn functional_semantics(record: &Record, tokens: &[Vec<u8>]) -> Result<FunctionalSemantics> {
    let actor = matches!(record.kind.as_str(), "CREA" | "NPC_");
    let mut semantics = FunctionalSemantics {
        ordered_tokens: Vec::new(),
        sorted_factions: Vec::new(),
        sorted_spells: Vec::new(),
        sorted_model_paths: Vec::new(),
    };
    for value in tokens {
        if value.starts_with(b"FULL:") {
            continue;
        }
        if actor && value.starts_with(b"SNAM:") {
            semantics.sorted_factions.push(value.clone());
        } else if actor && value.starts_with(b"SPLO:") {
            semantics.sorted_spells.push(value.clone());
        } else if record.kind == "CREA" && value.starts_with(b"NIFZ:") {
            semantics
                .sorted_model_paths
                .extend(normalized_model_paths(value, record)?);
        } else if record.kind == "CREA"
            && value.starts_with(b"NIFT:")
            && value.get(5..) == Some([0, 0, 0, 0].as_slice())
        {
            // TES4 represents an empty creature model-texture list both as an omitted NIFT and as
            // a four-byte zero count. Treat only that exact empty encoding as equivalent.
        } else {
            semantics.ordered_tokens.push(value.clone());
        }
    }
    semantics.sorted_factions.sort();
    semantics.sorted_spells.sort();
    semantics.sorted_model_paths.sort();
    Ok(semantics)
}

fn presentation_tokens(tokens: &[Vec<u8>]) -> Vec<&Vec<u8>> {
    tokens
        .iter()
        .filter(|value| value.starts_with(b"FULL:"))
        .collect()
}
fn token_evidence(tokens: &[Vec<u8>]) -> String {
    tokens
        .iter()
        .map(|value| {
            let kind = String::from_utf8_lossy(&value[..value.len().min(4)]);
            let data = value.get(5..).unwrap_or_default();
            let prefix = data
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            format!("{kind}:{}:{prefix}", data.len())
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn compare_inventory_record_fields(
    override_record: &Record,
    current: &Record,
    plugin_index: u8,
) -> Result<(InventoryRecordParts, InventoryRecordParts, Vec<String>)> {
    if !supports_additive_inventory_record(&override_record.kind)
        || override_record.kind != current.kind
    {
        bail!(
            "only matching additive inventory-bearing master overrides are supported; 0x{:08X} is {}/{}",
            override_record.form_id,
            override_record.kind,
            current.kind
        );
    }
    if override_record.form_id != current.form_id {
        bail!(
            "{} override identity mismatch: 0x{:08X} versus current 0x{:08X}",
            override_record.kind,
            override_record.form_id,
            current.form_id
        );
    }
    let override_parts = split_inventory_record(override_record, Some(plugin_index))?;
    let current_parts = split_inventory_record(current, None)?;
    if override_parts
        .declared_inventory_count
        .is_some_and(|value| value as usize != override_parts.inventory.len())
    {
        bail!(
            "{} override 0x{:08X} declares an inventory count that does not match its CNTO entries",
            override_record.kind,
            override_record.form_id
        );
    }
    if current_parts
        .declared_inventory_count
        .is_some_and(|value| value as usize != current_parts.inventory.len())
    {
        bail!(
            "current {} 0x{:08X} declares an inventory count that does not match its CNTO entries",
            current.kind,
            current.form_id
        );
    }
    if functional_semantics(override_record, &override_parts.non_inventory_tokens)?
        != functional_semantics(current, &current_parts.non_inventory_tokens)?
    {
        bail!(
            "{} override 0x{:08X} changes functional non-inventory fields relative to the current master (override [{}], current [{}])",
            override_record.kind,
            override_record.form_id,
            token_evidence(&override_parts.non_inventory_tokens),
            token_evidence(&current_parts.non_inventory_tokens)
        );
    }
    if override_record.flags & !COMPRESSED_RECORD != current.flags & !COMPRESSED_RECORD {
        bail!(
            "{} override 0x{:08X} changes record flags relative to the current master",
            override_record.kind,
            override_record.form_id
        );
    }
    let mut allowed_presentation_changes = Vec::new();
    if presentation_tokens(&override_parts.non_inventory_tokens)
        != presentation_tokens(&current_parts.non_inventory_tokens)
    {
        allowed_presentation_changes.push("FULL".to_owned());
    }
    Ok((override_parts, current_parts, allowed_presentation_changes))
}

fn reported_inventory_entry(entry: InventoryToken, plugin_index: u8) -> AddedInventoryEntry {
    AddedInventoryEntry {
        item_form_id: format!("0x{:08X}", entry.item_form_id),
        count: entry.count,
        reference_scope: if (entry.item_form_id >> 24) as u8 == plugin_index {
            "plugin-owned"
        } else {
            "current-master"
        }
        .to_owned(),
        reference_validated: false,
    }
}

pub fn validate_inventory_addition(
    override_record: &Record,
    current: &Record,
    plugin_index: u8,
) -> Result<OverrideResult> {
    // Compare inventory-bearing records by meaning: authors may reorder inventory rows or retain
    // an old display name, but every current item and every functional field still has to survive.
    let (override_parts, current_parts, allowed_presentation_changes) =
        compare_inventory_record_fields(override_record, current, plugin_index)?;
    let additions = additions_against_current(
        &override_parts.inventory,
        &current_parts.inventory,
    )
    .with_context(|| {
        format!(
            "{} override 0x{:08X} removes or changes current-master inventory (override [{}], current [{}])",
            override_record.kind, override_record.form_id,
            inventory_evidence(&override_parts.inventory),
            inventory_evidence(&current_parts.inventory)
        )
    })?;
    if additions.is_empty() {
        bail!(
            "{} override 0x{:08X} has no inventory additions",
            override_record.kind,
            override_record.form_id
        );
    }
    Ok(OverrideResult {
        form_id: format!("0x{:08X}", override_record.form_id),
        kind: override_record.kind.clone(),
        compatible_with_current_master: true,
        allowed_presentation_changes,
        added_inventory_entries: additions
            .into_iter()
            .map(|entry| reported_inventory_entry(entry, plugin_index))
            .collect(),
        preserved_current_master_entries: Vec::new(),
    })
}

fn subrecord_from_token(value: &[u8]) -> Result<Subrecord> {
    if value.len() < 5 || value[4] != b':' {
        bail!("invalid inventory extension token");
    }
    Ok(Subrecord {
        kind: String::from_utf8_lossy(&value[..4]).into_owned(),
        data: value[5..].to_vec(),
    })
}

fn inventory_subrecords(entry: &InventoryToken) -> Result<Vec<Subrecord>> {
    let mut data = entry.item_form_id.to_le_bytes().to_vec();
    data.extend_from_slice(&entry.count.to_le_bytes());
    let mut rows = vec![Subrecord {
        kind: "CNTO".to_owned(),
        data,
    }];
    for extra in &entry.extra_data {
        rows.push(subrecord_from_token(extra)?);
    }
    Ok(rows)
}

/// Produces a strict additive three-way merge. Functional fields and conflicting inventory rows
/// still fail closed; exact rows added by a newer installed master are restored into the override.
pub fn merge_inventory_addition(
    override_record: &Record,
    current: &Record,
    plugin_index: u8,
) -> Result<(Record, OverrideResult)> {
    let (override_parts, current_parts, allowed_presentation_changes) =
        compare_inventory_record_fields(override_record, current, plugin_index)?;
    let mut remaining = override_parts.inventory.clone();
    let mut missing_current = Vec::new();
    for current_entry in &current_parts.inventory {
        if let Some(index) = remaining
            .iter()
            .position(|candidate| candidate == current_entry)
        {
            remaining.remove(index);
        } else if remaining
            .iter()
            .any(|candidate| candidate.item_form_id == current_entry.item_form_id)
        {
            bail!(
                "{} override 0x{:08X} changes a current-master inventory row for 0x{:08X}",
                override_record.kind,
                override_record.form_id,
                current_entry.item_form_id
            );
        } else {
            missing_current.push(current_entry.clone());
        }
    }
    if remaining.is_empty() {
        bail!(
            "{} override 0x{:08X} has no inventory additions",
            override_record.kind,
            override_record.form_id
        );
    }

    let mut merged = override_record.clone();
    if !missing_current.is_empty() {
        let insertion = merged
            .subrecords
            .iter()
            .rposition(|row| matches!(row.kind.as_str(), "CNTO" | "COED"))
            .map(|index| index + 1)
            .context("inventory override has no CNTO insertion anchor")?;
        let mut restored_rows = Vec::new();
        for entry in &missing_current {
            restored_rows.extend(inventory_subrecords(entry)?);
        }
        merged
            .subrecords
            .splice(insertion..insertion, restored_rows);
        if let Some(count) = merged.subrecords.iter_mut().find(|row| row.kind == "COCT") {
            count.data = u32::try_from(override_parts.inventory.len() + missing_current.len())?
                .to_le_bytes()
                .to_vec();
        }
    }
    // Re-validate the synthesized record with the stricter no-removal rule.
    let mut result = validate_inventory_addition(&merged, current, plugin_index)?;
    result.allowed_presentation_changes = allowed_presentation_changes;
    result.preserved_current_master_entries = missing_current
        .into_iter()
        .map(|entry| reported_inventory_entry(entry, plugin_index))
        .collect();
    Ok((merged, result))
}

pub fn validate_container_addition(
    override_record: &Record,
    current: &Record,
    plugin_index: u8,
) -> Result<OverrideResult> {
    validate_inventory_addition(override_record, current, plugin_index)
}

fn encode_subrecords(subrecords: &[Subrecord]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for subrecord in subrecords {
        let kind = subrecord.kind.as_bytes();
        if kind.len() != 4 {
            bail!("invalid TES4 subrecord type {}", subrecord.kind);
        }
        if subrecord.data.len() > u32::MAX as usize {
            bail!("TES4 subrecord {} is too large", subrecord.kind);
        }
        if subrecord.data.len() > u16::MAX as usize {
            output.extend_from_slice(b"XXXX");
            output.extend_from_slice(&4_u16.to_le_bytes());
            output.extend_from_slice(&(subrecord.data.len() as u32).to_le_bytes());
        }
        output.extend_from_slice(kind);
        output
            .extend_from_slice(&(subrecord.data.len().min(u16::MAX as usize) as u16).to_le_bytes());
        output.extend_from_slice(&subrecord.data);
    }
    Ok(output)
}

fn encoded_record_payload(record: &Record) -> Result<Vec<u8>> {
    let expanded = encode_subrecords(&record.subrecords)?;
    if expanded.len() > MAX_EXPANDED_RECORD_BYTES {
        bail!("rewritten TES4 record exceeds the expanded record safety limit");
    }
    if record.flags & COMPRESSED_RECORD == 0 {
        return Ok(expanded);
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&expanded)?;
    let compressed = encoder.finish()?;
    let mut output = Vec::with_capacity(compressed.len() + 4);
    output.extend_from_slice(&u32::try_from(expanded.len())?.to_le_bytes());
    output.extend_from_slice(&compressed);
    Ok(output)
}

/// Structural placement evidence for one record: the enclosing GRUP-type chain
/// (outermost first) and the nearest enclosing cell-children group label.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordGroupContext {
    pub kind: String,
    pub flags: u32,
    pub data_size: u32,
    pub group_types: Vec<u32>,
    pub enclosing_cell_form_id: Option<u32>,
}

fn collect_group_contexts(
    bytes: &[u8],
    start: usize,
    end: usize,
    group_stack: &mut Vec<(u32, u32)>,
    contexts: &mut HashMap<u32, Vec<RecordGroupContext>>,
) -> Result<()> {
    let mut offset = start;
    while offset < end {
        if offset
            .checked_add(20)
            .is_none_or(|header_end| header_end > end)
        {
            bail!("TES4 group scan encountered a truncated record header");
        }
        let header = &bytes[offset..offset + 20];
        let kind = &header[..4];
        let declared_size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if kind == b"GRUP" {
            if declared_size == 0 {
                // Mirror the tolerant parse: a zero-size GRUP header is an
                // empty group, so it contributes no placement context.
                offset += 20;
                continue;
            }
            if declared_size < 20
                || offset
                    .checked_add(declared_size)
                    .is_none_or(|group_end| group_end > end)
            {
                bail!("TES4 group scan encountered an invalid GRUP");
            }
            let label = u32::from_le_bytes(header[8..12].try_into().unwrap());
            let group_type = u32::from_le_bytes(header[12..16].try_into().unwrap());
            group_stack.push((group_type, label));
            collect_group_contexts(bytes, offset + 20, offset + declared_size, group_stack, contexts)?;
            group_stack.pop();
            offset += declared_size;
            continue;
        }
        let record_end = offset
            .checked_add(20)
            .and_then(|value| value.checked_add(declared_size))
            .context("TES4 group scan record size overflow")?;
        if record_end > end {
            bail!("TES4 group scan encountered a truncated record");
        }
        let flags = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let form_id = u32::from_le_bytes(header[12..16].try_into().unwrap());
        let enclosing_cell_form_id = group_stack
            .iter()
            .rev()
            .find(|(group_type, _)| *group_type == GROUP_CELL_CHILDREN)
            .map(|(_, label)| *label);
        contexts
            .entry(form_id)
            .or_default()
            .push(RecordGroupContext {
                kind: String::from_utf8_lossy(kind).into_owned(),
                flags,
                data_size: declared_size as u32,
                group_types: group_stack
                    .iter()
                    .map(|(group_type, _)| *group_type)
                    .collect(),
                enclosing_cell_form_id,
            });
        offset = record_end;
    }
    Ok(())
}

/// Maps every record FormID to its structural GRUP placement evidence. The plugin is
/// structurally validated first so the raw walk cannot be fooled by truncation.
pub fn record_group_contexts(
    bytes: &[u8],
    source: &str,
) -> Result<HashMap<u32, Vec<RecordGroupContext>>> {
    read_plugin_bytes(bytes, source)?;
    let mut contexts = HashMap::new();
    let mut group_stack = Vec::new();
    collect_group_contexts(bytes, 0, bytes.len(), &mut group_stack, &mut contexts)?;
    Ok(contexts)
}

/// Fail-closed disclosure of one undelete-and-disable rewrite.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UndeleteDisableEvidence {
    pub form_id: String,
    pub winner_flags: String,
    pub rewritten_flags: String,
    pub original_z: f32,
    pub disabled_z: f32,
    pub enable_parent_form_id: String,
    pub enable_parent_policy: String,
    pub subrecord_kinds: Vec<String>,
    pub remapped_form_id_fields: Vec<String>,
}

fn remap_embedded_form_id(
    value: u32,
    winner_space_to_plugin_space: &HashMap<u8, u8>,
    field: &str,
) -> Result<u32> {
    let source_index = (value >> 24) as u8;
    let mapped = winner_space_to_plugin_space
        .get(&source_index)
        .with_context(|| {
            format!(
                "winner subrecord {field} references master index {source_index} that the staged plugin does not declare"
            )
        })?;
    Ok((u32::from(*mapped) << 24) | (value & 0x00ff_ffff))
}

/// Rewrites one zero-body REFR deletion stub as a full current-winner override that is
/// undeleted, initially disabled, parked at the disabled Z depth, and enable-parented to
/// the opposite of the always-enabled player reference (the industry-standard
/// undelete-and-disable pattern). Every input outside the proven witness shape fails closed.
pub fn undelete_and_disable_refr(
    stub: &Record,
    winner: &Record,
    winner_space_to_plugin_space: &HashMap<u8, u8>,
    player_form_id_in_plugin_space: u32,
) -> Result<(Record, UndeleteDisableEvidence)> {
    if stub.kind != "REFR" {
        bail!(
            "undelete-and-disable accepts only REFR deletion stubs; found {}",
            stub.kind
        );
    }
    if stub.flags != DELETED_RECORD {
        bail!(
            "undelete-and-disable accepts only pure deletion stubs with flags 0x{:08X}; found 0x{:08X}",
            DELETED_RECORD,
            stub.flags
        );
    }
    if !stub.subrecords.is_empty() {
        bail!(
            "undelete-and-disable accepts only zero-body deletion stubs; 0x{:08X} carries {} subrecord(s)",
            stub.form_id,
            stub.subrecords.len()
        );
    }
    if winner.kind != "REFR" {
        bail!(
            "undelete-and-disable winner for 0x{:08X} is {}, not REFR",
            stub.form_id,
            winner.kind
        );
    }
    if winner.flags & DELETED_RECORD != 0 {
        bail!(
            "undelete-and-disable winner for 0x{:08X} is itself deleted",
            stub.form_id
        );
    }
    let mut name_count = 0_usize;
    let mut data_count = 0_usize;
    for sub in &winner.subrecords {
        match sub.kind.as_str() {
            "NAME" => {
                if sub.data.len() != 4 {
                    bail!("winner NAME subrecord for 0x{:08X} is not 4 bytes", stub.form_id);
                }
                name_count += 1;
            }
            "DATA" => {
                if sub.data.len() != 24 {
                    bail!("winner DATA subrecord for 0x{:08X} is not 24 bytes", stub.form_id);
                }
                data_count += 1;
            }
            "XLOC" => {
                if sub.data.len() != 12 {
                    bail!("winner XLOC subrecord for 0x{:08X} is not 12 bytes", stub.form_id);
                }
            }
            "XSCL" => {
                if sub.data.len() != 4 {
                    bail!("winner XSCL subrecord for 0x{:08X} is not 4 bytes", stub.form_id);
                }
            }
            "XAAG" => {
                if sub.data.len() != 16 {
                    bail!("winner XAAG subrecord for 0x{:08X} is not 16 bytes", stub.form_id);
                }
            }
            "XACN" => {}
            "XESP" => bail!(
                "winner for 0x{:08X} already declares an enable parent; the undelete-and-disable witness shape excludes it",
                stub.form_id
            ),
            other => bail!(
                "winner subrecord {other} for 0x{:08X} is outside the proven undelete-and-disable witness set",
                stub.form_id
            ),
        }
    }
    if name_count != 1 || data_count != 1 {
        bail!(
            "undelete-and-disable winner for 0x{:08X} must carry exactly one NAME and one DATA subrecord; found {name_count}/{data_count}",
            stub.form_id
        );
    }

    let mut subrecords = Vec::with_capacity(winner.subrecords.len() + 1);
    let mut remapped_fields = Vec::new();
    let mut original_z = 0.0_f32;
    for sub in &winner.subrecords {
        let mut rewritten = sub.clone();
        match sub.kind.as_str() {
            "NAME" => {
                let source = u32::from_le_bytes(sub.data[..4].try_into().unwrap());
                let mapped =
                    remap_embedded_form_id(source, winner_space_to_plugin_space, "NAME")?;
                rewritten.data = mapped.to_le_bytes().to_vec();
                if mapped != source {
                    remapped_fields.push(format!("NAME:0x{source:08X}->0x{mapped:08X}"));
                }
            }
            "XLOC" => {
                let key = u32::from_le_bytes(sub.data[4..8].try_into().unwrap());
                if key != 0 {
                    let mapped =
                        remap_embedded_form_id(key, winner_space_to_plugin_space, "XLOC")?;
                    rewritten.data[4..8].copy_from_slice(&mapped.to_le_bytes());
                    if mapped != key {
                        remapped_fields.push(format!("XLOC:0x{key:08X}->0x{mapped:08X}"));
                    }
                }
            }
            "DATA" => {
                original_z = f32::from_le_bytes(sub.data[8..12].try_into().unwrap());
                rewritten.data[8..12].copy_from_slice(&UNDELETE_DISABLED_Z.to_le_bytes());
            }
            _ => {}
        }
        let insert_enable_parent = rewritten.kind == "NAME";
        subrecords.push(rewritten);
        if insert_enable_parent {
            let mut xesp = player_form_id_in_plugin_space.to_le_bytes().to_vec();
            xesp.extend_from_slice(&ENABLE_STATE_OPPOSITE_OF_PARENT.to_le_bytes());
            subrecords.push(Subrecord {
                kind: "XESP".to_owned(),
                data: xesp,
            });
        }
    }
    let flags = (winner.flags & !COMPRESSED_RECORD) | INITIALLY_DISABLED_RECORD;
    let record = Record {
        kind: "REFR".to_owned(),
        form_id: stub.form_id,
        flags,
        subrecords,
    };
    let evidence = UndeleteDisableEvidence {
        form_id: format!("0x{:08X}", stub.form_id),
        winner_flags: format!("0x{:08X}", winner.flags),
        rewritten_flags: format!("0x{flags:08X}"),
        original_z,
        disabled_z: UNDELETE_DISABLED_Z,
        enable_parent_form_id: format!("0x{player_form_id_in_plugin_space:08X}"),
        enable_parent_policy: "initially-disabled-opposite-of-player".to_owned(),
        subrecord_kinds: record
            .subrecords
            .iter()
            .map(|sub| sub.kind.clone())
            .collect(),
        remapped_form_id_fields: remapped_fields,
    };
    Ok((record, evidence))
}

fn rewrite_plugin_sequence(
    bytes: &[u8],
    start: usize,
    end: usize,
    replacements: &HashMap<u32, Record>,
    flag_updates: &HashSet<u32>,
    replaced: &mut HashSet<u32>,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut offset = start;
    while offset < end {
        if offset
            .checked_add(20)
            .is_none_or(|header_end| header_end > end)
        {
            bail!("TES4 rewrite encountered a truncated record header");
        }
        let header = &bytes[offset..offset + 20];
        let kind = &header[..4];
        let declared_size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if kind == b"GRUP" {
            if declared_size < 20
                || offset
                    .checked_add(declared_size)
                    .is_none_or(|group_end| group_end > end)
            {
                bail!("TES4 rewrite encountered an invalid GRUP");
            }
            let group_end = offset + declared_size;
            let children = rewrite_plugin_sequence(
                bytes,
                offset + 20,
                group_end,
                replacements,
                flag_updates,
                replaced,
            )?;
            let rebuilt_size = 20_usize
                .checked_add(children.len())
                .context("rewritten GRUP size overflow")?;
            let mut rebuilt_header = header.to_vec();
            rebuilt_header[4..8].copy_from_slice(&u32::try_from(rebuilt_size)?.to_le_bytes());
            output.extend_from_slice(&rebuilt_header);
            output.extend_from_slice(&children);
            offset = group_end;
            continue;
        }
        let record_end = offset
            .checked_add(20)
            .and_then(|value| value.checked_add(declared_size))
            .context("TES4 record size overflow")?;
        if record_end > end {
            bail!("TES4 rewrite encountered a truncated record");
        }
        let form_id = u32::from_le_bytes(header[12..16].try_into().unwrap());
        if let Some(record) = replacements.get(&form_id) {
            let source_flags = u32::from_le_bytes(header[8..12].try_into().unwrap());
            if record.kind.as_bytes() != kind
                || record.form_id != form_id
                || (record.flags != source_flags && !flag_updates.contains(&form_id))
            {
                bail!("TES4 replacement record identity or flags do not match the source");
            }
            if !replaced.insert(form_id) {
                bail!("TES4 source contains a duplicate replacement FormID 0x{form_id:08X}");
            }
            let payload = encoded_record_payload(record)?;
            let mut rebuilt_header = header.to_vec();
            rebuilt_header[4..8].copy_from_slice(&u32::try_from(payload.len())?.to_le_bytes());
            rebuilt_header[8..12].copy_from_slice(&record.flags.to_le_bytes());
            output.extend_from_slice(&rebuilt_header);
            output.extend_from_slice(&payload);
        } else {
            output.extend_from_slice(&bytes[offset..record_end]);
        }
        offset = record_end;
    }
    Ok(output)
}

/// Rewrites only explicitly supplied records, preserving every other record and GRUP header byte.
pub fn rewrite_plugin_records(
    bytes: &[u8],
    replacements: &HashMap<u32, Record>,
    source: &str,
) -> Result<Vec<u8>> {
    rewrite_plugin_records_with_flag_updates(bytes, replacements, &HashSet::new(), source)
}

/// Same as [`rewrite_plugin_records`], but FormIDs in `flag_updates` may change their
/// record-header flags to the replacement's declared flags (used by the disclosed
/// undelete-and-disable transform); every other record still requires exact flag identity.
pub fn rewrite_plugin_records_with_flag_updates(
    bytes: &[u8],
    replacements: &HashMap<u32, Record>,
    flag_updates: &HashSet<u32>,
    source: &str,
) -> Result<Vec<u8>> {
    read_plugin_bytes(bytes, source)?;
    let mut replaced = HashSet::new();
    let output = rewrite_plugin_sequence(
        bytes,
        0,
        bytes.len(),
        replacements,
        flag_updates,
        &mut replaced,
    )?;
    if replaced.len() != replacements.len() {
        let mut missing = replacements
            .keys()
            .filter(|form_id| !replaced.contains(form_id))
            .map(|form_id| format!("0x{form_id:08X}"))
            .collect::<Vec<_>>();
        missing.sort();
        bail!(
            "TES4 replacement records were not found: {}",
            missing.join(", ")
        );
    }
    read_plugin_bytes(&output, source).context("reparsing rewritten TES4 plugin")?;
    Ok(output)
}

pub fn package_to_game_path(package: &str) -> Result<String> {
    let mut normalized = package.replace('\\', "/");
    for extension in [".uasset", ".umap"] {
        if normalized.to_ascii_lowercase().ends_with(extension) {
            normalized.truncate(normalized.len() - extension.len());
        }
    }
    if let Some(mounted) = normalized.strip_prefix('/') {
        let components = mounted.split('/').collect::<Vec<_>>();
        if normalized.starts_with("//")
            || components.len() < 2
            || components.iter().any(|component| {
                component.is_empty()
                    || matches!(*component, "." | "..")
                    || component.contains(':')
                    || component.chars().any(char::is_control)
            })
        {
            bail!("invalid mounted Unreal package path: {package}");
        }
        return Ok(normalized);
    }
    let lower = normalized.to_ascii_lowercase();
    let marker = "/content/";
    let index = lower
        .find(marker)
        .with_context(|| format!("cannot normalize Unreal package path: {package}"))?;
    let project = normalized[..index]
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("cannot determine Unreal mount point: {package}"))?;
    let mount =
        if project.eq_ignore_ascii_case("OblivionRemastered") || matches!(project, "." | "..") {
            "Game"
        } else {
            project
        };
    let relative = normalized[index + marker.len()..].to_owned();
    Ok(format!("/{mount}/{}", relative.trim_start_matches('/')))
}

pub fn read_sync_map_bytes(bytes: &[u8], source: &str) -> Result<Vec<SyncMapEntry>> {
    let text = std::str::from_utf8(bytes)
        .with_context(|| format!("SyncMap is not valid UTF-8: {source}"))?;
    let section_re = Regex::new(r"^\[(.+)\]$")?;
    let entry_re = Regex::new(r"^([0-9A-Fa-f]{6,8})\s*=\s*(\S.+?)\s*$")?;
    let mut section = String::new();
    let mut entries = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(capture) = section_re.captures(trimmed) {
            section = capture[1].to_owned();
            continue;
        }
        if section != "Meshes" {
            continue;
        }
        let Some(capture) = entry_re.captures(trimmed) else {
            continue;
        };
        let key = capture[1].to_ascii_uppercase();
        let local_id = u32::from_str_radix(&capture[1], 16)? & 0x00FF_FFFF;
        let object_path = capture[2].to_owned();
        let package_path = object_path
            .rfind('.')
            .map(|index| object_path[..index].to_owned())
            .unwrap_or_else(|| object_path.clone());
        entries.push(SyncMapEntry {
            key,
            local_form_id: format!("0x{local_id:06X}"),
            object_path,
            package_path,
        });
    }
    Ok(entries)
}

pub fn read_sync_map(path: &Path) -> Result<Vec<SyncMapEntry>> {
    let bytes = fs::read(path).with_context(|| format!("reading SyncMap {}", path.display()))?;
    let source = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("SyncMap.ini");
    read_sync_map_bytes(&bytes, source)
}

pub fn sorted_form_ids(records: impl Iterator<Item = u32>) -> Vec<String> {
    let mut values = records.map(|id| format!("0x{id:08X}")).collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    fn compressed_record_payload(declared_size: u32, expanded: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(expanded).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut raw = declared_size.to_le_bytes().to_vec();
        raw.extend_from_slice(&compressed);
        raw
    }

    fn bare_record(kind: &str, form_id: u32) -> Record {
        Record {
            kind: kind.to_owned(),
            form_id,
            flags: 0,
            subrecords: Vec::new(),
        }
    }

    #[test]
    fn infers_the_conventional_self_slot_without_source_records() {
        let records = vec![bare_record("CONT", 0x0000_1000)];
        assert_eq!(
            infer_self_slot(1, &records),
            SelfSlotInference::Inferred {
                self_index: 1,
                basis: SELF_SLOT_BASIS_NO_SOURCE_RECORDS
            }
        );
    }

    #[test]
    fn infers_the_declared_master_count_self_slot() {
        let records = vec![
            bare_record("CONT", 0x0000_1000),
            bare_record("WEAP", 0x0100_0800),
        ];
        assert_eq!(
            infer_self_slot(1, &records),
            SelfSlotInference::Inferred {
                self_index: 1,
                basis: SELF_SLOT_BASIS_MASTER_COUNT
            }
        );
    }

    #[test]
    fn infers_a_unique_preserved_out_of_range_self_slot() {
        let records = vec![
            bare_record("CELL", 0x0004_9E28),
            bare_record("WEAP", 0x0200_0ED4),
            bare_record("REFR", 0x0200_30F7),
        ];
        assert_eq!(
            infer_self_slot(1, &records),
            SelfSlotInference::Inferred {
                self_index: 2,
                basis: SELF_SLOT_BASIS_PRESERVED_OUT_OF_RANGE
            }
        );
    }

    #[test]
    fn resolves_ambiguous_self_slot_when_master_count_is_a_candidate() {
        let records = vec![
            bare_record("WEAP", 0x0100_0800),
            bare_record("REFR", 0x0200_0801),
        ];
        assert_eq!(
            infer_self_slot(1, &records),
            SelfSlotInference::Inferred {
                self_index: 1,
                basis: "master-count-with-out-of-range-siblings",
            }
        );
        let records_no_master_count = vec![
            bare_record("WEAP", 0x0200_0800),
            bare_record("REFR", 0x0300_0801),
        ];
        assert_eq!(
            infer_self_slot(1, &records_no_master_count),
            SelfSlotInference::Ambiguous {
                candidates: vec![2, 3]
            }
        );
    }

    fn zero_size_group_plugin_bytes() -> Vec<u8> {
        let mut hedr = 0.8_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&3_u32.to_le_bytes());
        hedr.extend_from_slice(&0x0900_u32.to_le_bytes());
        let mut header_data = Vec::new();
        for (kind, data) in [
            ("HEDR", hedr.as_slice()),
            ("MAST", b"Oblivion.esm\0".as_slice()),
            ("DATA", [0_u8; 8].as_slice()),
        ] {
            header_data.extend_from_slice(kind.as_bytes());
            header_data.extend_from_slice(&(data.len() as u16).to_le_bytes());
            header_data.extend_from_slice(data);
        }
        let mut bytes = b"TES4".to_vec();
        bytes.extend_from_slice(&(header_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&[0; 12]);
        bytes.extend_from_slice(&header_data);
        // A zero-size top GRUP written by a buggy author tool, followed by a
        // well-formed WEAP top group holding one record.
        bytes.extend_from_slice(b"GRUP");
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(b"CELL");
        bytes.extend_from_slice(&[0; 8]);
        let record_payload = {
            let mut payload = b"EDID".to_vec();
            payload.extend_from_slice(&8_u16.to_le_bytes());
            payload.extend_from_slice(b"Fixture\0");
            payload
        };
        bytes.extend_from_slice(b"GRUP");
        bytes.extend_from_slice(&((20 + 20 + record_payload.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(b"WEAP");
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(b"WEAP");
        bytes.extend_from_slice(&(record_payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0x0100_0800_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&record_payload);
        bytes
    }

    #[test]
    fn recovers_a_zero_size_group_header_and_discloses_the_recovery() {
        let bytes = zero_size_group_plugin_bytes();
        let plugin = read_plugin_bytes(&bytes, "fixture.esp").unwrap();
        assert_eq!(plugin.group_count, 2);
        assert_eq!(plugin.recovered_zero_size_group_count, 1);
        assert_eq!(plugin.records.len(), 1);
        assert_eq!(plugin.records[0].kind, "WEAP");
        // The byte-splicing rewrite path must still refuse the recovered shape.
        let mut replacements = HashMap::new();
        replacements.insert(0x0100_0800, plugin.records[0].clone());
        let error = rewrite_plugin_records(&bytes, &replacements, "fixture.esp").unwrap_err();
        assert!(error.to_string().contains("invalid GRUP"));
    }

    #[test]
    fn refuses_compressed_record_with_unbounded_declared_size() {
        let raw = compressed_record_payload(u32::MAX, b"");
        let error = expand_record_data(raw, COMPRESSED_RECORD).unwrap_err();
        assert!(error.to_string().contains("expanded bytes; limit"));
    }

    #[test]
    fn refuses_compressed_record_that_overproduces_declared_output() {
        let raw = compressed_record_payload(4, b"12345678");
        let error = expand_record_data(raw, COMPRESSED_RECORD).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("output exceeds its declared size")
        );
    }

    #[test]
    fn refuses_compressed_record_beyond_remaining_plugin_budget() {
        let raw = compressed_record_payload(8, b"12345678");
        let mut remaining = 4;
        let error =
            expand_record_data_with_budget(raw, COMPRESSED_RECORD, &mut remaining).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("total expanded-data safety limit")
        );
        assert_eq!(remaining, 4);
    }

    fn subrecord(kind: &str, data: impl Into<Vec<u8>>) -> Subrecord {
        Subrecord {
            kind: kind.to_owned(),
            data: data.into(),
        }
    }

    fn inventory(item_form_id: u32, count: i32) -> Subrecord {
        let mut data = item_form_id.to_le_bytes().to_vec();
        data.extend_from_slice(&count.to_le_bytes());
        subrecord("CNTO", data)
    }

    fn container(subrecords: Vec<Subrecord>) -> Record {
        inventory_record("CONT", subrecords)
    }

    fn inventory_record(kind: &str, subrecords: Vec<Subrecord>) -> Record {
        Record {
            kind: kind.to_owned(),
            form_id: 0x0009_2285,
            flags: 0,
            subrecords,
        }
    }

    #[test]
    fn accepts_field_aware_container_inventory_additions() {
        let current = container(vec![
            subrecord("EDID", b"ArenaChest\0".to_vec()),
            subrecord("FULL", b"Raiment Cabinet\0".to_vec()),
            subrecord("COCT", 1_u32.to_le_bytes()),
            inventory(0x0001_0000, 1),
            subrecord("DATA", [0, 0, 0, 0]),
        ]);
        let override_record = container(vec![
            subrecord("EDID", b"ArenaChest\0".to_vec()),
            subrecord("FULL", 0x0003_9087_u32.to_le_bytes()),
            subrecord("COCT", 3_u32.to_le_bytes()),
            inventory(0x0100_0800, 1),
            inventory(0x0002_0000, 5),
            inventory(0x0001_0000, 1),
            subrecord("DATA", [0, 0, 0, 0]),
        ]);
        let result = validate_container_addition(&override_record, &current, 1).unwrap();
        assert_eq!(result.allowed_presentation_changes, ["FULL"]);
        assert_eq!(result.added_inventory_entries.len(), 2);
        assert!(result.added_inventory_entries.iter().any(|entry| {
            entry.item_form_id == "0x01000800" && entry.reference_scope == "plugin-owned"
        }));
        assert!(result.added_inventory_entries.iter().any(|entry| {
            entry.item_form_id == "0x00020000" && entry.reference_scope == "current-master"
        }));
    }

    #[test]
    fn accepts_field_aware_actor_inventory_additions() {
        for kind in ["CREA", "NPC_"] {
            let current = inventory_record(
                kind,
                vec![
                    subrecord("EDID", b"InventoryOwner\0".to_vec()),
                    inventory(0x0001_0000, 1),
                ],
            );
            let override_record = inventory_record(
                kind,
                vec![
                    subrecord("EDID", b"InventoryOwner\0".to_vec()),
                    inventory(0x0001_0000, 1),
                    inventory(0x0100_0800, 1),
                ],
            );
            let result = validate_inventory_addition(&override_record, &current, 1).unwrap();
            assert_eq!(result.kind, kind);
            assert_eq!(result.added_inventory_entries.len(), 1);
            assert_eq!(result.added_inventory_entries[0].item_form_id, "0x01000800");
            assert_eq!(
                result.added_inventory_entries[0].reference_scope,
                "plugin-owned"
            );
        }
    }

    #[test]
    fn canonicalizes_documented_actor_set_fields_without_hiding_changes() {
        let current = inventory_record(
            "CREA",
            vec![
                subrecord("EDID", b"InventoryOwner\0".to_vec()),
                subrecord(
                    "NIFZ",
                    b"Creatures\\Skellie.NIF\0Creatures\\Skull.NIF\0".to_vec(),
                ),
                subrecord("SNAM", [1, 0, 0, 0, 0, 0, 0, 0]),
                subrecord("SNAM", [2, 0, 0, 0, 1, 0, 0, 0]),
                subrecord("SPLO", 0x0001_0001_u32.to_le_bytes()),
                subrecord("SPLO", 0x0001_0002_u32.to_le_bytes()),
                inventory(0x0001_0000, 1),
            ],
        );
        let override_record = inventory_record(
            "CREA",
            vec![
                subrecord("EDID", b"InventoryOwner\0".to_vec()),
                subrecord(
                    "NIFZ",
                    b"creatures\\skull.nif\0creatures\\skellie.nif\0".to_vec(),
                ),
                subrecord("NIFT", [0, 0, 0, 0]),
                subrecord("SNAM", [2, 0, 0, 0, 1, 0, 0, 0]),
                subrecord("SNAM", [1, 0, 0, 0, 0, 0, 0, 0]),
                subrecord("SPLO", 0x0001_0002_u32.to_le_bytes()),
                subrecord("SPLO", 0x0001_0001_u32.to_le_bytes()),
                inventory(0x0001_0000, 1),
                inventory(0x0100_0800, 1),
            ],
        );
        validate_inventory_addition(&override_record, &current, 1).unwrap();

        let mut changed_model = override_record.clone();
        changed_model
            .subrecords
            .iter_mut()
            .find(|subrecord| subrecord.kind == "NIFZ")
            .unwrap()
            .data = b"creatures\\different.nif\0".to_vec();
        assert!(validate_inventory_addition(&changed_model, &current, 1).is_err());

        let mut nonempty_model_info = override_record.clone();
        nonempty_model_info
            .subrecords
            .iter_mut()
            .find(|subrecord| subrecord.kind == "NIFT")
            .unwrap()
            .data = [1, 0, 0, 0].to_vec();
        assert!(validate_inventory_addition(&nonempty_model_info, &current, 1).is_err());
    }

    #[test]
    fn merges_new_current_master_rows_without_accepting_conflicting_changes() {
        let current = inventory_record(
            "CREA",
            vec![
                subrecord("EDID", b"InventoryOwner\0".to_vec()),
                inventory(0x0001_0000, 1),
                inventory(0x0100_0100, 1),
            ],
        );
        let old_override = inventory_record(
            "CREA",
            vec![
                subrecord("EDID", b"InventoryOwner\0".to_vec()),
                inventory(0x0001_0000, 1),
                inventory(0x0200_0800, 1),
            ],
        );
        let (merged, result) = merge_inventory_addition(&old_override, &current, 2).unwrap();
        assert_eq!(result.added_inventory_entries.len(), 1);
        assert_eq!(result.preserved_current_master_entries.len(), 1);
        assert_eq!(
            container_inventory_form_ids(&merged).unwrap(),
            [0x0001_0000, 0x0100_0100, 0x0200_0800]
        );
        validate_inventory_addition(&merged, &current, 2).unwrap();

        let mut conflict = old_override;
        conflict.subrecords.insert(2, inventory(0x0100_0100, 2));
        assert!(merge_inventory_addition(&conflict, &current, 2).is_err());
    }

    #[test]
    fn refuses_inventory_semantics_for_unsupported_or_mismatched_record_types() {
        let container = inventory_record("CONT", vec![inventory(0x0001_0000, 1)]);
        let creature = inventory_record(
            "CREA",
            vec![inventory(0x0001_0000, 1), inventory(0x0100_0800, 1)],
        );
        assert!(validate_inventory_addition(&creature, &container, 1).is_err());
        let weapon = inventory_record("WEAP", vec![inventory(0x0100_0800, 1)]);
        assert!(validate_inventory_addition(&weapon, &weapon, 1).is_err());
    }

    #[test]
    fn refuses_container_non_inventory_changes() {
        let current = container(vec![
            subrecord("EDID", b"ArenaChest\0".to_vec()),
            inventory(0x0001_0000, 1),
        ]);
        let override_record = container(vec![
            subrecord("EDID", b"ChangedChest\0".to_vec()),
            inventory(0x0001_0000, 1),
            inventory(0x0100_0800, 1),
        ]);
        let error = validate_container_addition(&override_record, &current, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("functional non-inventory fields")
        );
    }

    #[test]
    fn refuses_changes_to_current_container_inventory() {
        let current = container(vec![inventory(0x0001_0000, 1)]);
        let override_record = container(vec![inventory(0x0001_0000, 2), inventory(0x0100_0800, 1)]);
        let error = validate_container_addition(&override_record, &current, 1).unwrap_err();
        assert!(error.to_string().contains("current-master inventory"));
    }
    #[test]
    fn normalizes_package_path() {
        assert_eq!(
            package_to_game_path("../../../OblivionRemastered/Content/Forms/Foo.uasset").unwrap(),
            "/Game/Forms/Foo"
        );
        assert_eq!(
            package_to_game_path("../../../Content/Forms/Foo.uasset").unwrap(),
            "/Game/Forms/Foo"
        );
        assert_eq!(
            package_to_game_path("../../../Arena/Content/Art/Armor/Foo.uasset").unwrap(),
            "/Arena/Art/Armor/Foo"
        );
        assert_eq!(
            package_to_game_path("/Game/Forms/items/armor/Offhand_Weapon").unwrap(),
            "/Game/Forms/items/armor/Offhand_Weapon"
        );
        assert_eq!(
            package_to_game_path(r"\Game\Forms\items\armor\Offhand_Weapon.uasset").unwrap(),
            "/Game/Forms/items/armor/Offhand_Weapon"
        );
        assert!(package_to_game_path("/Game/../Engine/Foo").is_err());
        assert!(package_to_game_path("//Game/Forms/Foo").is_err());
    }

    fn raw_record(kind: &str, form_id: u32, flags: u32, data: &[u8]) -> Vec<u8> {
        let mut out = kind.as_bytes().to_vec();
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&form_id.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    fn raw_subrecord(kind: &str, data: &[u8]) -> Vec<u8> {
        let mut out = kind.as_bytes().to_vec();
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    fn raw_group(label: &[u8; 4], group_type: u32, children: &[u8]) -> Vec<u8> {
        let mut out = b"GRUP".to_vec();
        out.extend_from_slice(&((children.len() + 20) as u32).to_le_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(&group_type.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(children);
        out
    }

    /// TES4 header with Oblivion.esm + Knights.esp masters, one WRLD top group holding a
    /// cell-children/cell-temporary chain around one zero-body deleted REFR stub.
    fn deletion_stub_plugin_bytes(stub_flags: u32, stub_data: &[u8]) -> Vec<u8> {
        let mut header_data = Vec::new();
        let mut hedr = 1.0_f32.to_le_bytes().to_vec();
        hedr.extend_from_slice(&5_u32.to_le_bytes());
        hedr.extend_from_slice(&0x0800_u32.to_le_bytes());
        header_data.extend_from_slice(&raw_subrecord("HEDR", &hedr));
        for master in ["Oblivion.esm", "Knights.esp"] {
            let mut name = master.as_bytes().to_vec();
            name.push(0);
            header_data.extend_from_slice(&raw_subrecord("MAST", &name));
            header_data.extend_from_slice(&raw_subrecord("DATA", &0_u64.to_le_bytes()));
        }
        let mut plugin = raw_record("TES4", 0, 0, &header_data);
        let stub = raw_record("REFR", 0x0000_47D3, stub_flags, stub_data);
        let temporary = raw_group(&0x0000_4499_u32.to_le_bytes(), GROUP_CELL_TEMPORARY_CHILDREN, &stub);
        let mut cell_children_payload = Vec::new();
        cell_children_payload.extend_from_slice(&temporary);
        let cell_record = raw_record("CELL", 0x0000_4499, 0, &raw_subrecord("EDID", b"cell\0"));
        let mut children = cell_record;
        children.extend_from_slice(&raw_group(
            &0x0000_4499_u32.to_le_bytes(),
            GROUP_CELL_CHILDREN,
            &cell_children_payload,
        ));
        let wrld_record = raw_record("WRLD", 0x0000_003C, 0, &raw_subrecord("EDID", b"tam\0"));
        let mut wrld_children = wrld_record;
        wrld_children.extend_from_slice(&raw_group(&0x0000_003C_u32.to_le_bytes(), 1, &children));
        plugin.extend_from_slice(&raw_group(b"WRLD", 0, &wrld_children));
        plugin
    }

    fn witness_winner() -> Record {
        let mut data = Vec::new();
        data.extend_from_slice(&100.0_f32.to_le_bytes());
        data.extend_from_slice(&200.0_f32.to_le_bytes());
        data.extend_from_slice(&300.0_f32.to_le_bytes());
        data.extend_from_slice(&0.0_f32.to_le_bytes());
        data.extend_from_slice(&0.0_f32.to_le_bytes());
        data.extend_from_slice(&1.5_f32.to_le_bytes());
        Record {
            kind: "REFR".to_owned(),
            form_id: 0x0100_47D3,
            flags: 0,
            subrecords: vec![
                subrecord("NAME", 0x0100_1234_u32.to_le_bytes().to_vec()),
                subrecord("XACN", b"0.06.0-19.00.0\0".to_vec()),
                subrecord("DATA", data),
            ],
        }
    }

    fn witness_stub() -> Record {
        Record {
            kind: "REFR".to_owned(),
            form_id: 0x0A00_47D3,
            flags: DELETED_RECORD,
            subrecords: Vec::new(),
        }
    }

    fn witness_remap() -> HashMap<u8, u8> {
        // Winner plugin space: 0 => Oblivion.esm, 1 => the winner itself, which the
        // staged plugin declares at master index 10.
        HashMap::from([(0_u8, 0_u8), (1_u8, 10_u8)])
    }

    #[test]
    fn undelete_and_disable_rewrites_witness_shaped_stub() {
        let (record, evidence) = undelete_and_disable_refr(
            &witness_stub(),
            &witness_winner(),
            &witness_remap(),
            0x0000_0014,
        )
        .unwrap();
        assert_eq!(record.kind, "REFR");
        assert_eq!(record.form_id, 0x0A00_47D3);
        assert_eq!(record.flags, INITIALLY_DISABLED_RECORD);
        let kinds = record
            .subrecords
            .iter()
            .map(|sub| sub.kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(kinds, vec!["NAME", "XESP", "XACN", "DATA"]);
        assert_eq!(
            record.subrecords[0].data,
            0x0A00_1234_u32.to_le_bytes().to_vec()
        );
        let mut xesp = 0x0000_0014_u32.to_le_bytes().to_vec();
        xesp.extend_from_slice(&1_u32.to_le_bytes());
        assert_eq!(record.subrecords[1].data, xesp);
        let data = &record.subrecords[3].data;
        assert_eq!(
            f32::from_le_bytes(data[8..12].try_into().unwrap()),
            UNDELETE_DISABLED_Z
        );
        assert_eq!(f32::from_le_bytes(data[0..4].try_into().unwrap()), 100.0);
        assert_eq!(f32::from_le_bytes(data[20..24].try_into().unwrap()), 1.5);
        assert_eq!(evidence.original_z, 300.0);
        assert_eq!(evidence.remapped_form_id_fields.len(), 1);
        assert!(evidence.remapped_form_id_fields[0].starts_with("NAME:0x01001234->0x0A001234"));
    }

    #[test]
    fn undelete_and_disable_fails_closed_outside_the_witness_shape() {
        let winner = witness_winner();
        let remap = witness_remap();

        let mut stub = witness_stub();
        stub.subrecords.push(subrecord("EDID", b"x\0".to_vec()));
        assert!(
            undelete_and_disable_refr(&stub, &winner, &remap, 0x14)
                .unwrap_err()
                .to_string()
                .contains("zero-body")
        );

        let mut stub = witness_stub();
        stub.flags = DELETED_RECORD | INITIALLY_DISABLED_RECORD;
        assert!(
            undelete_and_disable_refr(&stub, &winner, &remap, 0x14)
                .unwrap_err()
                .to_string()
                .contains("pure deletion stubs")
        );

        let mut stub = witness_stub();
        stub.kind = "ACHR".to_owned();
        assert!(
            undelete_and_disable_refr(&stub, &winner, &remap, 0x14)
                .unwrap_err()
                .to_string()
                .contains("only REFR")
        );

        let mut deleted_winner = witness_winner();
        deleted_winner.flags = DELETED_RECORD;
        assert!(
            undelete_and_disable_refr(&witness_stub(), &deleted_winner, &remap, 0x14)
                .unwrap_err()
                .to_string()
                .contains("itself deleted")
        );

        let mut parented_winner = witness_winner();
        parented_winner
            .subrecords
            .insert(1, subrecord("XESP", vec![0; 8]));
        assert!(
            undelete_and_disable_refr(&witness_stub(), &parented_winner, &remap, 0x14)
                .unwrap_err()
                .to_string()
                .contains("already declares an enable parent")
        );

        let mut foreign_winner = witness_winner();
        foreign_winner
            .subrecords
            .insert(1, subrecord("XOWN", vec![0; 4]));
        assert!(
            undelete_and_disable_refr(&witness_stub(), &foreign_winner, &remap, 0x14)
                .unwrap_err()
                .to_string()
                .contains("outside the proven undelete-and-disable witness set")
        );

        let mut unmapped_winner = witness_winner();
        unmapped_winner.subrecords[0] = subrecord("NAME", 0x0500_1234_u32.to_le_bytes().to_vec());
        assert!(
            undelete_and_disable_refr(&witness_stub(), &unmapped_winner, &remap, 0x14)
                .unwrap_err()
                .to_string()
                .contains("does not declare")
        );

        let mut bodyless_winner = witness_winner();
        bodyless_winner.subrecords.retain(|sub| sub.kind != "DATA");
        assert!(
            undelete_and_disable_refr(&witness_stub(), &bodyless_winner, &remap, 0x14)
                .unwrap_err()
                .to_string()
                .contains("exactly one NAME and one DATA")
        );
    }

    #[test]
    fn record_group_contexts_report_cell_temporary_placement() {
        let bytes = deletion_stub_plugin_bytes(DELETED_RECORD, &[]);
        let contexts = record_group_contexts(&bytes, "test.esp").unwrap();
        let stub = &contexts[&0x0000_47D3];
        assert_eq!(stub.len(), 1);
        assert_eq!(stub[0].kind, "REFR");
        assert_eq!(stub[0].flags, DELETED_RECORD);
        assert_eq!(stub[0].data_size, 0);
        assert_eq!(
            stub[0].group_types,
            vec![0, 1, GROUP_CELL_CHILDREN, GROUP_CELL_TEMPORARY_CHILDREN]
        );
        assert_eq!(stub[0].enclosing_cell_form_id, Some(0x0000_4499));
        let cell = &contexts[&0x0000_4499];
        assert_eq!(cell[0].kind, "CELL");
        assert_eq!(cell[0].group_types, vec![0, 1]);
    }

    #[test]
    fn rewrite_with_flag_updates_round_trips_the_undelete_transform() {
        let source = deletion_stub_plugin_bytes(DELETED_RECORD, &[]);
        let parsed = read_plugin_bytes(&source, "test.esp").unwrap();
        let stub = parsed
            .records
            .iter()
            .find(|record| record.form_id == 0x0000_47D3)
            .unwrap()
            .clone();
        let mut winner = witness_winner();
        winner.form_id = 0x0100_47D3;
        let remap = HashMap::from([(0_u8, 0_u8), (1_u8, 0_u8)]);
        let (rewritten, _) =
            undelete_and_disable_refr(&stub, &winner, &remap, 0x0000_0014).unwrap();
        let flag_updates = HashSet::from([0x0000_47D3_u32]);
        let candidate = rewrite_plugin_records_with_flag_updates(
            &source,
            &HashMap::from([(0x0000_47D3_u32, rewritten.clone())]),
            &flag_updates,
            "test.esp",
        )
        .unwrap();
        let reparsed = read_plugin_bytes(&candidate, "test.esp").unwrap();
        let transformed = reparsed
            .records
            .iter()
            .find(|record| record.form_id == 0x0000_47D3)
            .unwrap();
        assert_eq!(transformed.flags, INITIALLY_DISABLED_RECORD);
        assert_eq!(transformed.subrecords.len(), 4);

        // Byte-roundtrip proof: applying the inverse replacement restores the source exactly.
        let restored = rewrite_plugin_records_with_flag_updates(
            &candidate,
            &HashMap::from([(0x0000_47D3_u32, stub)]),
            &flag_updates,
            "test.esp",
        )
        .unwrap();
        assert_eq!(restored, source);
    }

    #[test]
    fn rewrite_refuses_flag_changes_without_the_explicit_allowlist() {
        let source = deletion_stub_plugin_bytes(DELETED_RECORD, &[]);
        let replacement = Record {
            kind: "REFR".to_owned(),
            form_id: 0x0000_47D3,
            flags: INITIALLY_DISABLED_RECORD,
            subrecords: Vec::new(),
        };
        let error = rewrite_plugin_records(
            &source,
            &HashMap::from([(0x0000_47D3_u32, replacement)]),
            "test.esp",
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("identity or flags do not match")
        );
    }
}
