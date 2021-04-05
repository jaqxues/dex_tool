use std::any::Any;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::io::SeekFrom::Start;

use crate::m_utf8;

// Bytes [4..7] specify Dex Format Version
// In string format: "dex\n035\0" with 035 being the Dex Format Version
const DEX_FILE_MAGIC: [u8; 8] = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00];
const ENDIAN_CONSTANT: u32 = 0x12345678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

pub fn read_u8(reader: &mut dyn Read, buf: &mut [u8; 1]) -> u8 {
    reader.read_exact(buf).unwrap();
    buf[0]
}

pub fn read_u16(reader: &mut dyn Read) -> u16 {
    let mut buf = [0u8; 2];
    reader.read(&mut buf).unwrap();
    u16::from_le_bytes(buf)
}

pub fn read_u32(reader: &mut dyn Read) -> u32 {
    let mut buf = [0u8; 4];
    reader.read(&mut buf).unwrap();
    u32::from_le_bytes(buf)
}

pub fn parse_string_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<u32> {
    reader.seek(Start(dex_header.string_ids_off.into())).unwrap();

    let mut offsets = Vec::with_capacity(dex_header.string_ids_size as usize);
    for _ in 0..dex_header.string_ids_size {
        offsets.push(read_u32(reader));
    }
    offsets
}

pub fn parse_string_data(string_data_offs: Vec<u32>, reader: &mut BufReader<File>) -> Vec<String> {
    let mut strings = Vec::with_capacity(string_data_offs.len());

    for off in string_data_offs {
        reader.seek(Start(off.into())).unwrap();

        let size = leb128::read::unsigned(reader).unwrap();

        // UTF-8 Encoding
        let mut v = vec![0u8; size as usize];
        reader.read_exact(&mut v).unwrap();
        let string = String::from_utf8(v).unwrap_or(String::new());

        // MUTF-8 Encoding
        // let string = m_utf8::to_string(reader, size).unwrap();
        strings.push(string);
    }

    strings
}

pub fn parse_type_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<u32> {
    reader.seek(Start(dex_header.type_ids_off.into())).unwrap();

    let mut type_ids: Vec<u32> = Vec::with_capacity(dex_header.type_ids_size as usize);
    for _ in 0..dex_header.type_ids_size {
        type_ids.push(read_u32(reader));
    }
    type_ids
}

pub fn parse_proto_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<ProtoIdItem> {
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

pub fn parse_field_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<FieldId> {
    reader.seek(Start(dex_header.field_ids_off.into())).unwrap();

    let mut v = Vec::with_capacity(dex_header.field_ids_size as usize);
    for _ in 0..dex_header.field_ids_size {
        v.push(FieldId {
            class_idx: read_u16(reader),
            type_idx: read_u16(reader),
            name_idx: read_u32(reader),
        });
    }
    v
}

pub fn parse_method_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<MethodId> {
    reader.seek(Start(dex_header.method_ids_off.into())).unwrap();

    let mut v = Vec::with_capacity(dex_header.method_ids_size as usize);
    for _ in 0..dex_header.method_ids_size {
        v.push(MethodId {
            class_idx: read_u16(reader),
            proto_idx: read_u16(reader),
            name_idx: read_u32(reader),
        });
    }
    v
}

pub fn parse_class_defs(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Vec<ClassDef> {
    reader.seek(Start(dex_header.class_defs_off.into())).unwrap();

    let mut v = Vec::with_capacity(dex_header.class_defs_size as usize);
    for _ in 0..dex_header.class_defs_size {
        v.push(ClassDef {
            class_idx: read_u32(reader),
            access_flags: read_u32(reader),
            superclass_idx: read_u32(reader),
            interfaces_off: read_u32(reader),
            source_file_idx: read_u32(reader),
            annotations_off: read_u32(reader),
            class_data_off: read_u32(reader),
            static_values_off: read_u32(reader),
        });
    }
    v
}

pub fn parse_call_side_ids(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Vec<u32> {
    let item = find_type_in_map(map_list, 0x07).unwrap();
    reader.seek(Start(item.offset.into())).unwrap();

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        v.push(read_u32(reader));
    }
    v
}

/** TODO Not Done */
pub fn parse_call_side_item(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) {
    let item = find_type_in_map(map_list, 0x07);

    if item.is_some() {
        panic!("Call Site Id Item was not null!");
    }
    // let item = item.unwrap();
    //
    // reader.seek(Start(item.offset.into())).unwrap();
    //
    // let mut offsets = Vec::with_capacity(item.size as usize);
    // for _ in 0..item.size {
    //     offsets.push(read_u32(reader));
    // }
    // let mut buf = [0u8; 1];
    // reader.seek(Start(offset.into())).unwrap();
    //
    // let size = leb128::read::unsigned(reader).unwrap();
    // let method_handle = raw_encoded_value_u32(reader, 0x16, &mut buf);
    // let method_name = raw_encoded_value_u32(reader, 0x17, &mut buf);
    // let method_type = raw_encoded_value_u32(reader, 0x15, &mut buf);
    // for _ in 0..size - 3 {
    //     parse_encoded_value(reader, &mut buf);
    // }
    // fn raw_encoded_value_u32(reader: &mut BufReader<File>, expected_type: u8, buf: &mut [u8; 1]) -> u32 {
    //     let (value_arg, value_type) = raw_encoded_value_pre(reader, buf);
    //
    //     // debug_assert!(value_type == 0x15 || value_type == 0x16 || value_type == 0x17);
    //     assert_eq!(value_type, expected_type);
    //
    //     let mut v = vec![0u8; value_arg as usize + 1];
    //     reader.read_exact(v.as_mut_slice()).unwrap();
    //     u32::from_le_bytes(v.as_slice().try_into().unwrap())
    // }
    //
    // fn parse_encoded_value(reader: &mut BufReader<File>, buf: &mut [u8; 1]) -> EncodedValue {
    //     let (value_type, value_arg) = raw_encoded_value_pre(reader, buf);
    //     println!("Encoded Value: {:?}", (value_type, value_arg));
    //     match value_type {
    //         _ => panic!()
    //     }
    // }
    //
    // /// Returns the first byte of an encoded value (value_arg, value_type) as tuple
    // fn raw_encoded_value_pre(reader: &mut BufReader<File>, buf: &mut [u8; 1]) -> (u8, u8) {
    //     let byte = read_u8(reader, buf);
    //     let value_arg = (byte & 0xe0) >> 5;
    //     let value_type = byte & 0x1f;
    //
    //     debug_assert!(match value_type {
    //         0x00 | 0x1c..=0x1e => value_arg == 0,
    //         0x02 | 0x03 | 0x1f => value_arg == 0 || value_arg == 1,
    //         0x04 | 0x10 | 0x15..=0x1b => value_arg <= 3,
    //         0x06 | 0x11 => 0 <= value_arg && value_arg <= 7,
    //         _ => panic!("Unmatched Value Type after exhaustively checking every listed format")
    //     });
    //
    //     (value_arg, value_type)
    // }
}

pub fn parse_method_handles(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Vec<MethodHandle> {
    let item = find_type_in_map(map_list, 0x08).unwrap();
    reader.seek(Start(item.offset.into()));

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        v.push(MethodHandle {
            method_handle_type: read_u16(reader),
            field_or_method_id: {
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf).unwrap(); // Unused
                let used = read_u16(reader);
                reader.read_exact(&mut buf).unwrap(); // Unused
                used
            },
        });
    }
    v
}

pub fn parse_class_data(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Vec<ClassData> {
    let item = find_type_in_map(map_list, 0x2000);
    if item.is_none() { panic!("No Class Data Offset Found"); }
    let item = item.unwrap();
    reader.seek(Start(item.offset.into())).unwrap();

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        let static_fields_size = leb128::read::unsigned(reader).unwrap();
        let instance_fields_size = leb128::read::unsigned(reader).unwrap();
        let direct_methods_size = leb128::read::unsigned(reader).unwrap();
        let virtual_methods_size = leb128::read::unsigned(reader).unwrap();

        let mut static_fields = Vec::with_capacity(static_fields_size as usize);
        let mut instance_fields = Vec::with_capacity(instance_fields_size as usize);
        let mut direct_methods = Vec::with_capacity(direct_methods_size as usize);
        let mut virtual_methods = Vec::with_capacity(virtual_methods_size as usize);

        fn read_encoded_field(reader: &mut BufReader<File>) -> EncodedField {
            EncodedField {
                field_idx_diff: leb128::read::unsigned(reader).unwrap(),
                access_flags: leb128::read::unsigned(reader).unwrap(),
            }
        }
        fn read_encoded_method(reader: &mut BufReader<File>) -> EncodedMethod {
            EncodedMethod {
                method_idx_diff: leb128::read::unsigned(reader).unwrap(),
                access_flags: leb128::read::unsigned(reader).unwrap(),
                code_off: leb128::read::unsigned(reader).unwrap(),
            }
        }
        for _ in 0..static_fields_size {
            static_fields.push(read_encoded_field(reader));
        }
        for _ in 0..instance_fields_size {
            instance_fields.push(read_encoded_field(reader));
        }
        for _ in 0..direct_methods_size {
            direct_methods.push(read_encoded_method(reader));
        }
        for _ in 0..virtual_methods_size {
            virtual_methods.push(read_encoded_method(reader));
        }
        v.push(ClassData { static_fields, instance_fields, direct_methods, virtual_methods });
    }
    v
}

/// Returns a Vec of TypeLists (Vector of u16 as indices into the type_ids list)
pub fn parse_type_lists(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Vec<Vec<u16>> {
    let item = find_type_in_map(map_list, 0x1001).unwrap();
    reader.seek(Start(item.offset.into())).unwrap();

    let mut v = Vec::with_capacity(item.size as usize);
    let mut buf = [0u8; 2];

    for _ in 0..item.size {
        let size = read_u32(reader);
        let mut type_list = Vec::with_capacity(size as usize);
        for _ in 0..size {
            type_list.push(read_u16(reader));
        }
        // alignment: 4 bytes --> ignore last 2 bytes if needed
        if size % 2 == 1 { reader.read_exact(&mut buf).unwrap(); }
        v.push(type_list);
    }
    v
}

pub fn parse_code_items(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Vec<CodeItem> {
    let item = find_type_in_map(map_list, 0x2001).unwrap();
    reader.seek(Start(item.offset.into())).unwrap();

    let mut v = Vec::with_capacity(item.size as usize);
    let mut buf = [0u8; 2];
    for _ in 0..item.size {
        let registers_size = read_u16(reader);
        let ins_size = read_u16(reader);
        let outs_size = read_u16(reader);
        let tries_size = read_u16(reader);
        let debug_info_off = read_u32(reader);
        let insns_size = read_u32(reader);
        v.push(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            debug_info_off,
            insns: {
                let mut v = Vec::with_capacity(insns_size as usize);
                for _ in 0..insns_size {
                    v.push(read_u16(reader));
                }
                // Padding
                if tries_size != 0 && insns_size % 2 == 1 {
                    reader.read_exact(&buf).unwrap();
                }
                v
            },
            tries: {
                let mut v = Vec::with_capacity(tries_size as usize);
                for _ in 0..tries_size {
                    v.push(TryItem {
                        start_addr: read_u32(reader),
                        insn_count: read_u16(reader),
                        handler_off: read_u16(reader),
                    });
                }
                v
            },
            handlers: {
                if tries_size == 0 { Vec::new() } else {
                    let size = leb128::read::unsigned(reader).unwrap();
                    let mut v = Vec::with_capacity(size as usize);
                    for _ in 0..size {
                        let size = leb128::read::signed(reader).unwrap();
                        v.push(EncodedCatchHandler {
                            handlers: {
                                let abs_size = size.abs();
                                let mut v = Vec::with_capacity(abs_size as usize);
                                for _ in 0..abs_size {
                                    v.push(
                                        EncodedTypeAddrPair {
                                            type_idx: leb128::read::unsigned(reader).unwrap(),
                                            addr: leb128::read::unsigned(reader).unwrap(),
                                        });
                                }
                                v
                            },
                            catch_all_addr: {
                                if size < 0 { None } else { Some(leb128::read::unsigned(reader).unwrap()) }
                            },
                        })
                    }
                }
            },
        })
    }
    v
}


pub fn parse_debug_info(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) {
    let item = find_type_in_map(map_list, 0x2003);
    if item.is_none() { panic!("No Debug Info Found") }
    let item = item.unwrap();

    reader.seek(Start(item.offset.into())).unwrap();
    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        let line_start = leb128::read::unsigned(reader).unwrap();
        let parameters_size = leb128::read::unsigned(reader).unwrap();

        let mut parameter_names = Vec::with_capacity(parameters_size as usize);
        for _ in 0..parameters_size {
            parameter_names.push(i64::try_from(leb128::read::unsigned(reader).unwrap()).unwrap() - 1);
        }
        loop {
            let mut buf = [0u8];
            reader.read_exact(&mut buf).unwrap();
            if buf[0] == 0x00 {
                break;
            }
        }
        v.push((line_start, parameter_names));
    }
}

pub fn parse_annotation_set_ref_list(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Vec<Vec<u32>> {
    let item = find_type_in_map(map_list, 0x1002);
    if item.is_none() { panic!("No AnnotationSetRefList Found"); }
    let item = item.unwrap();

    reader.seek(Start(item.offset.into())).unwrap();
    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        let size = read_u32(reader);
        let mut list = Vec::with_capacity(size as usize);
        for _ in 0..size {
            list.push(read_u32(reader));
        }
        v.push(list);
    }
    v
}

pub fn parse_annotation_set_item(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Vec<Vec<u32>> {
    let item = find_type_in_map(map_list, 0x1003);
    if item.is_none() { panic!("No Annotation Set Item Found") }
    let item = item.unwrap();

    reader.seek(Start(item.offset.into())).unwrap();
    let mut offsets = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        let size = read_u32(reader);
        let mut entries = Vec::with_capacity(size as usize);
        for _ in 0..size {
            entries.push(read_u32(reader));
        }
        offsets.push(entries);
    }
    offsets
}

pub fn parse_annotation_item(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) {
    let item = find_type_in_map(map_list, 0x2004);
    if item.is_none() { panic!("Annotation Item Not Found"); }
    let item = item.unwrap();

    reader.seek(Start(item.offset.into())).unwrap();
}


#[derive(Debug)]
enum EncodedValue {
    Byte(u8),
    Short(i16),
    Char(u16),
    Int(i16),
    Long(i64),
    Float(f32),
    Double(f64),
    MethodType(u32),
    MethodHandle(u32),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array,
    Annotation,
    Null,
    Boolean(bool),
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
    /// Verify Magic bytes of DexHeader and return parsed version
    pub fn verify_magic(buf: &[u8; DEX_FILE_MAGIC.len()]) -> u16 {
        if !(buf.starts_with(&DEX_FILE_MAGIC[0..5]) && buf.ends_with(&DEX_FILE_MAGIC[7..8])) {
            panic!("Given file does not contain correct file signature");
        }

        let version = String::from_utf8_lossy(&buf[4..7]);
        let version: u16 = version.parse().expect("Version number could not be parsed");

        version
    }

    /// Check endian constant, returns true if it corresponds to the REVERSE_ENDIAN_CONSTANT
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
                reader.read_exact(&mut magic).unwrap();
                DexHeader::verify_magic(&magic);
                magic
            },
            checksum: read_u32(reader),
            signature: {
                let mut signature = [0u8; 20];
                reader.read_exact(&mut signature).unwrap();
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


struct StringData {
    utf16_size: u64,
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct ProtoIdItem {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
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
    pub static_values_off: u32,
}

#[derive(Debug)]
pub struct MethodHandle {
    pub method_handle_type: u16,
    pub field_or_method_id: u16,
}

#[derive(Debug)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

#[derive(Debug)]
pub struct EncodedField {
    pub field_idx_diff: u64,
    pub access_flags: u64,
}

#[derive(Debug)]
pub struct EncodedMethod {
    pub method_idx_diff: u64,
    pub access_flags: u64,
    pub code_off: u64,
}

#[derive(Debug)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
    pub handlers: Vec<EncodedCatchHandler>,
}

#[derive(Debug)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

#[derive(Debug)]
pub struct EncodedCatchHandler {
    /// EncodedTypeAddrPair as tuple
    pub handlers: Vec<EncodedTypeAddrPair>,
    pub catch_all_addr: Option<u64>,
}

#[derive(Debug)]
pub struct EncodedTypeAddrPair {
    pub type_idx: u64,
    pub addr: u64,
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

pub fn find_type_in_map(map_list: &Vec<MapItem>, item_type: u16) -> Option<&MapItem> {
    let mut item = None;
    for it in map_list {
        if it.item_type == item_type {
            item = Some(it);
            break;
        }
    }
    item
}