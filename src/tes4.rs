use anyhow::{Context, Result, bail};
use flate2::read::ZlibDecoder;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

const COMPRESSED_RECORD: u32 = 0x0004_0000;

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
    pub masters: Vec<String>,
    pub declared_record_count: u32,
    pub next_object_id: u32,
    pub records: Vec<Record>,
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

fn expand_record_data(raw: Vec<u8>, flags: u32) -> Result<Vec<u8>> {
    if flags & COMPRESSED_RECORD == 0 {
        return Ok(raw);
    }
    if raw.len() < 4 {
        bail!("compressed TES4 record payload is truncated");
    }
    let expected = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
    let mut decoder = ZlibDecoder::new(&raw[4..]);
    let mut output = Vec::with_capacity(expected);
    decoder.read_to_end(&mut output)?;
    if output.len() != expected {
        bail!(
            "compressed TES4 record size mismatch: expected {expected}, got {}",
            output.len()
        );
    }
    Ok(output)
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

pub fn read_plugin(path: &Path) -> Result<Plugin> {
    let bytes = fs::read(path).with_context(|| format!("reading plugin {}", path.display()))?;
    let mut reader = Cursor::new(bytes.as_slice());
    if read_fourcc(&mut reader)? != "TES4" {
        bail!("not a TES4 plugin: {}", path.display());
    }
    let header_size = read_u32(&mut reader)? as usize;
    let header_flags = read_u32(&mut reader)?;
    let _header_form_id = read_u32(&mut reader)?;
    let _header_version_control = read_u32(&mut reader)?;
    let mut header_raw = vec![0; header_size];
    reader.read_exact(&mut header_raw)?;
    let header_data = expand_record_data(header_raw, header_flags)?;
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
    let mut records = Vec::new();
    while reader.position() as usize + 20 <= bytes.len() {
        let start = reader.position();
        let kind = read_fourcc(&mut reader)?;
        if kind == "GRUP" {
            let group_size = read_u32(&mut reader)? as u64;
            if group_size < 20 || start + group_size > bytes.len() as u64 {
                bail!("invalid GRUP at 0x{start:X} in {}", path.display());
            }
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
        let data = expand_record_data(raw, flags)?;
        records.push(Record {
            kind,
            form_id,
            flags,
            subrecords: read_subrecords(&data)?,
        });
    }
    Ok(Plugin {
        masters,
        declared_record_count,
        next_object_id,
        records,
    })
}

pub fn read_target_records(path: &Path, form_ids: &[u32]) -> Result<HashMap<u32, Record>> {
    let wanted = form_ids.iter().copied().collect::<HashSet<_>>();
    let mut found = HashMap::new();
    let mut reader = File::open(path).with_context(|| format!("opening ESM {}", path.display()))?;
    let length = reader.metadata()?.len();
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
            let data = expand_record_data(raw, flags)?;
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

struct ContainerParts {
    non_inventory_tokens: Vec<Vec<u8>>,
    inventory: Vec<InventoryToken>,
    declared_inventory_count: Option<u32>,
}

fn split_container_record(record: &Record, plugin_index: Option<u8>) -> Result<ContainerParts> {
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
                        "CONT 0x{:08X} has an invalid or duplicate COCT subrecord",
                        record.form_id
                    );
                }
                declared_inventory_count =
                    Some(u32::from_le_bytes(subrecord.data[..4].try_into().unwrap()));
            }
            "CNTO" => {
                if subrecord.data.len() != 8 {
                    bail!(
                        "CONT 0x{:08X} has a CNTO subrecord with {} bytes instead of 8",
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
                        "CONT 0x{:08X} references inventory item 0x{item_form_id:08X} beyond plugin index {plugin_index}",
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
                "CONT 0x{:08X} has an orphan COED inventory extension",
                record.form_id
            ),
            _ => non_inventory_tokens.push(token(subrecord)),
        }
        index += 1;
    }
    inventory.sort();
    Ok(ContainerParts {
        non_inventory_tokens,
        inventory,
        declared_inventory_count,
    })
}

pub fn container_inventory_form_ids(record: &Record) -> Result<Vec<u32>> {
    let mut ids = split_container_record(record, None)?
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
fn tokens_without_presentation_fields(tokens: &[Vec<u8>]) -> Vec<&Vec<u8>> {
    tokens
        .iter()
        .filter(|value| !value.starts_with(b"FULL:"))
        .collect()
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
pub fn validate_container_addition(
    override_record: &Record,
    current: &Record,
    plugin_index: u8,
) -> Result<OverrideResult> {
    if override_record.kind != "CONT" || current.kind != "CONT" {
        bail!(
            "only additive CONT master overrides are supported; 0x{:08X} is {}/{}",
            override_record.form_id,
            override_record.kind,
            current.kind
        );
    }
    if override_record.form_id != current.form_id {
        bail!(
            "CONT override identity mismatch: 0x{:08X} versus current 0x{:08X}",
            override_record.form_id,
            current.form_id
        );
    }
    // Compare the container by meaning: authors may reorder inventory rows or retain an old
    // display name, but every current item and every functional field still has to survive.
    let override_parts = split_container_record(override_record, Some(plugin_index))?;
    let current_parts = split_container_record(current, None)?;
    if override_parts
        .declared_inventory_count
        .is_some_and(|value| value as usize != override_parts.inventory.len())
    {
        bail!(
            "CONT override 0x{:08X} declares an inventory count that does not match its CNTO entries",
            override_record.form_id
        );
    }
    if current_parts
        .declared_inventory_count
        .is_some_and(|value| value as usize != current_parts.inventory.len())
    {
        bail!(
            "current CONT 0x{:08X} declares an inventory count that does not match its CNTO entries",
            current.form_id
        );
    }
    if tokens_without_presentation_fields(&override_parts.non_inventory_tokens)
        != tokens_without_presentation_fields(&current_parts.non_inventory_tokens)
    {
        bail!(
            "CONT override 0x{:08X} changes functional non-inventory fields relative to the current Oblivion.esm (override [{}], current [{}])",
            override_record.form_id,
            token_evidence(&override_parts.non_inventory_tokens),
            token_evidence(&current_parts.non_inventory_tokens)
        );
    }
    let mut allowed_presentation_changes = Vec::new();
    if presentation_tokens(&override_parts.non_inventory_tokens)
        != presentation_tokens(&current_parts.non_inventory_tokens)
    {
        allowed_presentation_changes.push("FULL".to_owned());
    }
    let additions = additions_against_current(
        &override_parts.inventory,
        &current_parts.inventory,
    )
    .with_context(|| {
        format!(
            "CONT override 0x{:08X} removes or changes current-master inventory (override [{}], current [{}])",
            override_record.form_id,
            inventory_evidence(&override_parts.inventory),
            inventory_evidence(&current_parts.inventory)
        )
    })?;
    if additions.is_empty() {
        bail!(
            "CONT override 0x{:08X} has no inventory additions",
            override_record.form_id
        );
    }
    if override_record.flags & !COMPRESSED_RECORD != current.flags & !COMPRESSED_RECORD {
        bail!(
            "CONT override 0x{:08X} changes record flags relative to the current Oblivion.esm",
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
            .map(|entry| AddedInventoryEntry {
                item_form_id: format!("0x{:08X}", entry.item_form_id),
                count: entry.count,
                reference_scope: if (entry.item_form_id >> 24) as u8 == plugin_index {
                    "plugin-owned"
                } else {
                    "current-master"
                }
                .to_owned(),
                reference_validated: false,
            })
            .collect(),
    })
}
pub fn package_to_game_path(package: &str) -> Result<String> {
    let normalized = package.replace('\\', "/");
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
    let mut relative = normalized[index + marker.len()..].to_owned();
    for extension in [".uasset", ".umap"] {
        if relative.to_ascii_lowercase().ends_with(extension) {
            relative.truncate(relative.len() - extension.len());
        }
    }
    Ok(format!("/{mount}/{}", relative.trim_start_matches('/')))
}

pub fn read_sync_map(path: &Path) -> Result<Vec<SyncMapEntry>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("reading SyncMap {}", path.display()))?;
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

pub fn sorted_form_ids(records: impl Iterator<Item = u32>) -> Vec<String> {
    let mut values = records.map(|id| format!("0x{id:08X}")).collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use super::*;

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
        Record {
            kind: "CONT".to_owned(),
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
    }
}
