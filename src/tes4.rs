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
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideResult {
    pub form_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub compatible_with_current_master: bool,
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
    let mut additions = Vec::new();
    let mut base_tokens = Vec::new();
    for sub in &override_record.subrecords {
        if sub.kind == "CNTO" && sub.data.len() == 8 {
            let item = u32::from_le_bytes(sub.data[..4].try_into().unwrap());
            if (item >> 24) as u8 == plugin_index {
                additions.push(AddedInventoryEntry {
                    item_form_id: format!("0x{item:08X}"),
                    count: i32::from_le_bytes(sub.data[4..8].try_into().unwrap()),
                });
                continue;
            }
        }
        base_tokens.push(token(sub));
    }
    if additions.is_empty() {
        bail!(
            "CONT override 0x{:08X} has no plugin-owned CNTO additions",
            override_record.form_id
        );
    }
    let current_tokens = current.subrecords.iter().map(token).collect::<Vec<_>>();
    if base_tokens != current_tokens {
        bail!(
            "CONT override 0x{:08X} is not a pure addition relative to the current Oblivion.esm",
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
        added_inventory_entries: additions,
    })
}

pub fn package_to_game_path(package: &str) -> Result<String> {
    let normalized = package.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let marker = "/content/";
    let index = lower
        .find(marker)
        .with_context(|| format!("cannot normalize Unreal package path: {package}"))?;
    let mut relative = normalized[index + marker.len()..].to_owned();
    for extension in [".uasset", ".umap"] {
        if relative.to_ascii_lowercase().ends_with(extension) {
            relative.truncate(relative.len() - extension.len());
        }
    }
    Ok(format!("/Game/{}", relative.trim_start_matches('/')))
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

    #[test]
    fn normalizes_package_path() {
        assert_eq!(
            package_to_game_path("../../../OblivionRemastered/Content/Forms/Foo.uasset").unwrap(),
            "/Game/Forms/Foo"
        );
    }
}
