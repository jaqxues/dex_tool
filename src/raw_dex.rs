use std::io::{BufReader, Read, Seek};
use std::fs::{File, read};
use std::io::SeekFrom::Start;
use crate::m_utf8;
use crate::m_utf8::read_byte;

// Bytes [4..7] specify Dex Format Version
// In string format: "dex\n035\0" with 035 being the Dex Format Version
const DEX_FILE_MAGIC: [u8; 8] = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00];
const ENDIAN_CONSTANT: u32 = 0x12345678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

pub fn read_u16(reader: &mut BufReader<File>) -> u16 {
    let mut buf = [0u8; 2];
    reader.read(&mut buf).unwrap();
    u16::from_le_bytes(buf)
}

pub fn read_u32(reader: &mut BufReader<File>) -> u32 {
    let mut buf = [0u8; 4];
    reader.read(&mut buf).unwrap();
    u32::from_le_bytes(buf)
}

pub fn parse_strings(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<String> {
    reader.seek(Start(dex_header.string_ids_off.into())).unwrap();

    let mut string_ids = Vec::with_capacity(dex_header.string_ids_size as usize);
    for _ in 0..dex_header.string_ids_size {
        string_ids.push(read_u32(reader));
    }

    let mut strings = Vec::with_capacity(dex_header.string_ids_size as usize);

    // TODO https://github.com/rust-lang/rust/issues/31100
    // Switch to relative seeking for BufReader
    for string_data_off in string_ids {
        debug_assert!({
                          let data_end = dex_header.data_off + dex_header.data_size;
                          dex_header.data_off < string_data_off && string_data_off < data_end
                      }, "Offset location was not in data section");
        reader.seek(Start(string_data_off.into())).unwrap();

        let size = leb128::read::unsigned(reader).unwrap();
        // let mut v = vec![0u8; size as usize];
        // reader.read_exact(&mut v).unwrap();
        // let string = String::from_utf8(v).unwrap_or(String::new());
        let string = m_utf8::to_string(reader, size).unwrap();
        strings.push(string);
    }

    strings
}

pub fn parse_types(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<u32> {
    reader.seek(Start(dex_header.type_ids_off.into())).unwrap();

    let mut type_ids: Vec<u32> = Vec::with_capacity(dex_header.type_ids_size as usize);
    for _ in 0..dex_header.type_ids_size {
        type_ids.push(read_u32(reader));
    }
    type_ids
}

pub fn parse_protos(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<ProtoIdItem> {
    reader.seek(Start(dex_header.proto_ids_off.into())).unwrap();

    let mut v = Vec::with_capacity(dex_header.proto_ids_size as usize);
    for _ in 0..dex_header.proto_ids_size {
        v.push(ProtoIdItem {
            shorty_idx: read_u32(reader),
            return_type_idx: read_u32(reader),
            parameters_off: read_u32(reader),
        });
    }
    v
}

pub fn parse_fields(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<FieldId> {
    let size = dex_header.field_ids_size as usize;
    if size == 0 { return Vec::new() }
    let mut v = Vec::with_capacity(size);
    reader.seek(Start(dex_header.field_ids_off.into())).unwrap();
    for _ in 0..size {
        v.push(FieldId {
            class_idx: read_u16(reader),
            type_idx: read_u16(reader),
            name_idx: read_u32(reader),
        });
    }
    v
}

pub fn parse_methods(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<MethodId> {
    let size = dex_header.method_ids_size as usize;
    if size == 0 { return Vec::new() }
    let mut v = Vec::with_capacity(size);
    reader.seek(Start(dex_header.method_ids_off.into())).unwrap();
    for _ in 0..size {
        v.push(MethodId {
            class_idx: read_u16(reader),
            proto_idx: read_u16(reader),
            name_idx: read_u32(reader),
        });
    }
    v
}

pub fn parse_classes(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<ClassDef> {
    let size = dex_header.class_defs_size as usize;
    if size == 0 { return Vec::new() }
    let mut v = Vec::with_capacity(size);
    reader.seek(Start(dex_header.class_defs_off.into())).unwrap();

    for _ in 0..size {
        v.push(ClassDef {
            class_idx: read_u32(reader),
            access_flags: read_u32(reader),
            superclass_idx: read_u32(reader),
            interfaces_off: read_u32(reader),
            source_file_idx: read_u32(reader),
            annotations_off: read_u32(reader),
            class_data_off: read_u32(reader),
            static_values_off: read_u32(reader)
        });
    }
    v
}

#[derive(Debug)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug)]
pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32
}

#[derive(Debug)]
pub struct MapItem {
    pub item_type: u16,
    pub size: u32,
    pub offset: u32,
}


impl MapItem {
    pub fn parse_map_list(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<MapItem> {
        reader.seek(Start(dex_header.map_off.into())).unwrap();

        let size = read_u32(reader);
        let mut v = Vec::with_capacity(size as usize);
        for _ in 0..size {
            let item_type = read_u16(reader);
            read_u16(reader); // unused
            let size = read_u32(reader);
            let offset = read_u32(reader);
            v.push(MapItem { item_type, size, offset })
        }
        v
    }
}

#[derive(Debug)]
pub struct ProtoIdItem {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}


#[derive(Debug)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl DexHeader {
    pub fn verify_magic(buf: &[u8; DEX_FILE_MAGIC.len()]) -> u16 {
        if !(buf.starts_with(&DEX_FILE_MAGIC[0..5]) && buf.ends_with(&DEX_FILE_MAGIC[7..8])) {
            panic!("Given file does not contain correct file signature");
        }

        let version = String::from_utf8_lossy(&buf[4..7]);
        let version: u16 = version.parse().expect("Could not parse Version number");

        version
    }

    pub fn verify_endian(val: u32) -> bool {
        match val {
            ENDIAN_CONSTANT => false,
            REVERSE_ENDIAN_CONSTANT => true,
            _ => panic!("Bytes do not match valid constants")
        }
    }

    pub fn from_reader(reader: &mut BufReader<File>) -> DexHeader {
        DexHeader {
            magic: {
                let mut magic = [0u8; DEX_FILE_MAGIC.len()];
                reader.read(&mut magic).unwrap();
                DexHeader::verify_magic(&magic);
                magic
            },
            checksum: read_u32(reader),
            signature: {
                let mut signature = [0u8; 20];
                reader.read(&mut signature).unwrap();
                signature
            },
            file_size: read_u32(reader),
            header_size: read_u32(reader),
            endian_tag: {
                let tag = read_u32(reader);
                DexHeader::verify_endian(tag);
                tag
            },
            link_size: read_u32(reader),
            link_off: read_u32(reader),
            map_off: read_u32(reader),
            string_ids_size: read_u32(reader),
            string_ids_off: read_u32(reader),
            type_ids_size: read_u32(reader),
            type_ids_off: read_u32(reader),
            proto_ids_size: read_u32(reader),
            proto_ids_off: read_u32(reader),
            field_ids_size: read_u32(reader),
            field_ids_off: read_u32(reader),
            method_ids_size: read_u32(reader),
            method_ids_off: read_u32(reader),
            class_defs_size: read_u32(reader),
            class_defs_off: read_u32(reader),
            data_size: read_u32(reader),
            data_off: read_u32(reader),
        }
    }
}