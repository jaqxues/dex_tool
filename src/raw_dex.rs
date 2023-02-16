use std::convert::TryFrom;
use std::fs::{File, read};
use std::io::{BufReader, Read, Seek};
use std::io::SeekFrom::{Current, Start};

use memmap::Mmap;
use scroll::{ctx, Endian, Pread};
use scroll::ctx::TryFromCtx;

use crate::m_utf8;
use crate::raw_dex::EncodedValue::Boolean;
use crate::raw_dex::Visibility::{VisibilityBuild, VisibilityRuntime, VisibilitySystem};

// Bytes [4..7] specify Dex Format Version
// In string format: "dex\n035\0" with 035 being the Dex Format Version
const DEX_FILE_MAGIC: [u8; 8] = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00];
const ENDIAN_CONSTANT: u32 = 0x12345678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

pub fn read_u8(reader: &mut dyn Read, buf: &mut [u8; 1]) -> Result<u8, std::io::Error> {
    reader.read_exact(buf)?;
    Ok(buf[0])
}

pub fn read_u16(reader: &mut dyn Read) -> Result<u16, std::io::Error> {
    let mut buf = [0u8; 2];
    reader.read(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

pub fn read_u32(reader: &mut dyn Read) -> Result<u32, std::io::Error> {
    let mut buf = [0u8; 4];
    reader.read(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub fn parse_string_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Result<Vec<u32>, std::io::Error> {
    reader.seek(Start(dex_header.string_ids_off.into()))?;

    let mut offsets = Vec::with_capacity(dex_header.string_ids_size as usize);
    for _ in 0..dex_header.string_ids_size {
        offsets.push(read_u32(reader)?);
    }
    Ok(offsets)
}

pub fn parse_string_data(string_data_offs: Vec<u32>, reader: &mut BufReader<File>) -> Result<Vec<String>, std::io::Error> {
    let mut strings = Vec::with_capacity(string_data_offs.len());

    for off in string_data_offs {
        reader.seek(Start(off.into()))?;

        let size = leb128::read::unsigned(reader).unwrap();

        // UTF-8 Encoding ("" if it fails)
        // let mut v = vec![0u8; size as usize];
        // reader.read_exact(&mut v).unwrap();
        // let string = String::from_utf8(v).unwrap_or(String::new());

        // MUTF-8 Encoding
        strings.push(m_utf8::to_string(reader, size).map_err(| it | std::io::Error::new(std::io::ErrorKind::Other, it.to_string()))?);
    }

    Ok(strings)
}

pub fn parse_type_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Result<Vec<u32>, std::io::Error> {
    reader.seek(Start(dex_header.type_ids_off.into()))?;

    let mut type_ids: Vec<u32> = Vec::with_capacity(dex_header.type_ids_size as usize);
    for _ in 0..dex_header.type_ids_size {
        type_ids.push(read_u32(reader)?);
    }
    Ok(type_ids)
}

pub fn parse_proto_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Result<Vec<ProtoIdItem>, std::io::Error> {
    reader.seek(Start(dex_header.proto_ids_off.into()))?;

    let mut v = Vec::with_capacity(dex_header.proto_ids_size as usize);
    for _ in 0..dex_header.proto_ids_size {
        v.push(ProtoIdItem {
            shorty_idx: read_u32(reader)?,
            return_type_idx: read_u32(reader)?,
            parameters_off: read_u32(reader)?,
        });
    }
    Ok(v)
}

pub fn parse_field_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Result<Vec<FieldId>, std::io::Error> {
    reader.seek(Start(dex_header.field_ids_off.into()))?;

    let mut v = Vec::with_capacity(dex_header.field_ids_size as usize);
    for _ in 0..dex_header.field_ids_size {
        v.push(FieldId {
            class_idx: read_u16(reader)?,
            type_idx: read_u16(reader)?,
            name_idx: read_u32(reader)?,
        });
    }
    Ok(v)
}

pub fn parse_method_ids(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Result<Vec<MethodId>, std::io::Error> {
    reader.seek(Start(dex_header.method_ids_off.into()))?;

    let mut v = Vec::with_capacity(dex_header.method_ids_size as usize);
    for _ in 0..dex_header.method_ids_size {
        v.push(MethodId {
            class_idx: read_u16(reader)?,
            proto_idx: read_u16(reader)?,
            name_idx: read_u32(reader)?,
        });
    }
    Ok(v)
}

pub fn parse_class_defs(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Result<Vec<ClassDef>, std::io::Error> {
    reader.seek(Start(dex_header.class_defs_off.into()))?;

    let mut v = Vec::with_capacity(dex_header.class_defs_size as usize);
    for _ in 0..dex_header.class_defs_size {
        v.push(ClassDef {
            class_idx: read_u32(reader)?,
            access_flags: read_u32(reader)?,
            superclass_idx: read_u32(reader)?,
            interfaces_off: read_u32(reader)?,
            source_file_idx: read_u32(reader)?,
            annotations_off: read_u32(reader)?,
            class_data_off: read_u32(reader)?,
            static_values_off: read_u32(reader)?,
        });
    }
    Ok(v)
}

// TODO Untested
pub fn parse_call_side_ids(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<u32>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x07);
    if item.is_none() { return Ok(Vec::new()); }
    let item = item.unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        v.push(read_u32(reader)?);
    }
    Ok(v)
}

// TODO Untested
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

// TODO Untested
pub fn parse_method_handles(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<MethodHandle>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x08);
    if item.is_none() { return Ok(Vec::new()); }
    let item = item.unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        v.push(MethodHandle {
            method_handle_type: read_u16(reader)?,
            field_or_method_id: {
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?; // Unused
                let used = read_u16(reader)?;
                reader.read_exact(&mut buf)?; // Unused
                used
            },
        });
    }
    Ok(v)
}

pub fn parse_class_data(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<ClassData>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x2000);
    if item.is_none() { panic!("No Class Data Offset Found"); }
    let item = item.unwrap();
    reader.seek(Start(item.offset.into()))?;

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
    Ok(v)
}

/// Returns a Vec of TypeLists (Vector of u16 as indices into the type_ids list)
pub fn parse_type_lists(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<Vec<u16>>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x1001).unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    let mut buf = [0u8; 2];

    for _ in 0..item.size {
        let size = read_u32(reader)?;
        let mut type_list = Vec::with_capacity(size as usize);
        for _ in 0..size {
            type_list.push(read_u16(reader)?);
        }
        // alignment: 4 bytes --> ignore last 2 bytes if needed
        if size % 2 == 1 { reader.read_exact(&mut buf)?; }
        v.push(type_list);
    }
    Ok(v)
}

pub fn parse_code_items(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<CodeItem>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x2001).unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    let mut buf = [0u8; 2];
    for _ in 0..item.size {
        let registers_size = read_u16(reader)?;
        let ins_size = read_u16(reader)?;
        let outs_size = read_u16(reader)?;
        let tries_size = read_u16(reader)?;
        let debug_info_off = read_u32(reader)?;
        let insns_size = read_u32(reader)?;

        let mut current_pos = reader.seek(Current(0))?;
        v.push(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            debug_info_off,
            insns: {
                let mut v = Vec::with_capacity(insns_size as usize);
                for _ in 0..insns_size {
                    v.push(read_u16(reader)?);
                }
                // Padding
                if tries_size != 0 && insns_size % 2 == 1 {
                    reader.read_exact(&mut buf)?;
                }
                v
            },
            tries: {
                let mut v = Vec::with_capacity(tries_size as usize);
                for _ in 0..tries_size {
                    v.push(TryItem {
                        start_addr: read_u32(reader)?,
                        insn_count: read_u16(reader)?,
                        handler_off: read_u16(reader)?,
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
                                if size > 0 { None } else { Some(leb128::read::unsigned(reader).unwrap()) }
                            },
                        })
                    }
                    v
                }
            },
        });
        current_pos = reader.seek(Current(0))? - current_pos;
        if current_pos % 4 != 0 {
            let mut v = vec![0u8; (4 - current_pos % 4) as usize];
            reader.read_exact(v.as_mut_slice())?;
        }
    }
    Ok(v)
}


pub fn parse_debug_info(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<DebugInfoItem>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x2003);
    if item.is_none() { panic!("No Debug Info Found") }
    let item = item.unwrap();

    reader.seek(Start(item.offset.into()))?;
    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        v.push(DebugInfoItem {
            line_start: leb128::read::unsigned(reader).unwrap(),
            parameter_names: {
                let size = leb128::read::unsigned(reader).unwrap();

                let mut v = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    v.push(i64::try_from(leb128::read::unsigned(reader).unwrap()).unwrap() - 1);
                }
                v
            },
            state_machine_bytes: {
                let mut buf = [0u8];
                let mut v = Vec::new();
                loop {
                    reader.read_exact(&mut buf)?;
                    if buf[0] == 0x00 {
                        break;
                    }
                    v.push(buf[0]);
                }
                v
            },
        });
    }
    Ok(v)
}

pub fn parse_annotations_directories(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<AnnotationsDirectory>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x2006).unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        let class_annotations_off = read_u32(reader)?;
        let fields_size = read_u32(reader)?;
        let annotated_methods_size = read_u32(reader)?;
        let annotated_parameters_size = read_u32(reader)?;

        v.push(AnnotationsDirectory {
            class_annotations_off,
            field_annotations: {
                let mut v = Vec::with_capacity(fields_size as usize);
                for _ in 0..fields_size {
                    v.push(FieldAnnotation {
                        field_idx: read_u32(reader)?,
                        annotations_off: read_u32(reader)?,
                    });
                }
                v
            },
            method_annotations: {
                let mut v = Vec::with_capacity(annotated_methods_size as usize);
                for _ in 0..annotated_methods_size {
                    v.push(MethodAnnotation {
                        method_idx: read_u32(reader)?,
                        annotations_off: read_u32(reader)?,
                    });
                }
                v
            },
            parameter_annotations: {
                let mut v = Vec::with_capacity(annotated_parameters_size as usize);
                for _ in 0..annotated_parameters_size {
                    v.push(ParameterAnnotation {
                        method_idx: read_u32(reader)?,
                        annotations_off: read_u32(reader)?,
                    });
                }
                v
            },
        })
    }
    Ok(v)
}

pub fn parse_annotation_set_ref_list(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<Vec<u32>>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x1002).unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        let size = read_u32(reader)?;
        let mut list = Vec::with_capacity(size as usize);
        for _ in 0..size {
            list.push(read_u32(reader)?);
        }
        v.push(list);
    }
    Ok(v)
}

pub fn parse_annotation_set_item(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<Vec<u32>>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x1003).unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        let size = read_u32(reader)?;
        let mut list = Vec::with_capacity(size as usize);
        for _ in 0..size {
            list.push(read_u32(reader)?);
        }
        v.push(list);
    }
    Ok(v)
}

pub fn parse_annotation_item(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<AnnotationItem>, std::io::Error> {
    let item = find_type_in_map(map_list, 0x2004).unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    let mut buf = [0u8];
    for _ in 0..item.size {
        v.push(AnnotationItem {
            visibility: match read_u8(reader, &mut buf)? {
                0x00 => VisibilityBuild,
                0x01 => VisibilityRuntime,
                0x02 => VisibilitySystem,
                _ => panic!("Unknown visibility byte")
            },
            annotation: EncodedAnnotation::from_reader(reader)?,
        });
    }
    Ok(v)
}

impl EncodedAnnotation {
    fn from_reader(reader: &mut BufReader<File>) -> Result<EncodedAnnotation, std::io::Error> {
        Ok(EncodedAnnotation {
            type_idx: leb128::read::unsigned(reader).unwrap(),
            elements: {
                let size = leb128::read::unsigned(reader).unwrap();
                let mut v = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    v.push(AnnotationElement {
                        name_idx: leb128::read::unsigned(reader).unwrap(),
                        value: EncodedValue::from_reader(reader)?,
                    });
                }
                v
            },
        })
    }
}

// TODO Untested
pub fn parse_hiddenapi_class_data(map_list: &Vec<MapItem>, reader: &mut BufReader<File>) -> Result<Vec<HiddenApiClassData>, std::io::Error> {
    let item = find_type_in_map(map_list, 0xF000);
    if item.is_none() { return Ok(Vec::new()); }
    let item = item.unwrap();
    reader.seek(Start(item.offset.into()))?;

    let mut v = Vec::with_capacity(item.size as usize);
    for _ in 0..item.size {
        let size = read_u32(reader)?;
        v.push(HiddenApiClassData {
            size,
            offsets: {
                let mut v = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    v.push(read_u32(reader)?);
                }
                v
            },
            flags: {
                let mut v = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    v.push(leb128::read::unsigned(reader).unwrap());
                }
                v
            },
        })
    }
    Ok(v)
}


#[derive(Debug)]
pub enum EncodedValue {
    Byte(u8),
    Short(i16),
    Char(u16),
    Int(i32),
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
    Array(Vec<EncodedValue>),
    Annotation(EncodedAnnotation),
    Null,
    Boolean(bool),
}

impl EncodedValue {
    pub fn from_reader(reader: &mut BufReader<File>) -> Result<EncodedValue, std::io::Error> {
        let byte = read_u8(reader, &mut [0u8])?;
        let value_arg = (byte & 0xe0) >> 5;
        let value_type = byte & 0x1f;
        Ok(match value_type {
            0x00 => EncodedValue::Byte(read_u8(reader, &mut [0u8])?),
            0x02 => {
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                EncodedValue::Short(i16::from_le_bytes(buf))
            },
            0x03 => EncodedValue::Char(read_u16(reader)?),
            0x04 => {
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf)?;
                EncodedValue::Int(i32::from_le_bytes(buf))
            }
            0x06 => {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                EncodedValue::Long(i64::from_le_bytes(buf))
            }
            0x10 => {
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf)?;
                EncodedValue::Float(f32::from_le_bytes(buf))
            }
            0x11 => {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                EncodedValue::Double(f64::from_le_bytes(buf))
            }
            0x15 => EncodedValue::MethodType(read_u32(reader)?),
            0x16 => EncodedValue::MethodHandle(read_u32(reader)?),
            0x17 => EncodedValue::String(read_u32(reader)?),
            0x18 => EncodedValue::Type(read_u32(reader)?),
            0x19 => EncodedValue::Field(read_u32(reader)?),
            0x1a => EncodedValue::Method(read_u32(reader)?),
            0x1b => EncodedValue::Enum(read_u32(reader)?),
            0x1c => EncodedValue::Array({
                let size = leb128::read::unsigned(reader).unwrap();
                let mut v = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    v.push(EncodedValue::from_reader(reader)?)
                }
                v
            }),
            0x1d => EncodedValue::Annotation(EncodedAnnotation::from_reader(reader)?),
            0x1e => EncodedValue::Null,
            0x1f => EncodedValue::Boolean(value_arg != 0),
            _ => panic!("Unknown value bits for encoded value")
        })
    }
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
    pub fn verify_endian(val: u32) -> scroll::Endian {
        match val {
            ENDIAN_CONSTANT => scroll::LE,
            REVERSE_ENDIAN_CONSTANT => scroll::BE,
            _ => panic!("Bytes do not match valid constants")
        }
    }

    pub fn from_reader(reader: &mut BufReader<File>) -> Result<DexHeader, std::io::Error> {
        Ok(DexHeader {
            magic: {
                let mut magic = [0u8; DEX_FILE_MAGIC.len()];
                reader.read_exact(&mut magic)?;
                DexHeader::verify_magic(&magic);
                magic
            },
            checksum: read_u32(reader)?,
            signature: {
                let mut signature = [0u8; 20];
                reader.read_exact(&mut signature)?;
                signature
            },
            file_size: read_u32(reader)?,
            header_size: read_u32(reader)?,
            endian_tag: {
                let tag = read_u32(reader)?;
                DexHeader::verify_endian(tag);
                tag
            },
            link_size: read_u32(reader)?,
            link_off: read_u32(reader)?,
            map_off: read_u32(reader)?,
            string_ids_size: read_u32(reader)?,
            string_ids_off: read_u32(reader)?,
            type_ids_size: read_u32(reader)?,
            type_ids_off: read_u32(reader)?,
            proto_ids_size: read_u32(reader)?,
            proto_ids_off: read_u32(reader)?,
            field_ids_size: read_u32(reader)?,
            field_ids_off: read_u32(reader)?,
            method_ids_size: read_u32(reader)?,
            method_ids_off: read_u32(reader)?,
            class_defs_size: read_u32(reader)?,
            class_defs_off: read_u32(reader)?,
            data_size: read_u32(reader)?,
            data_off: read_u32(reader)?,
        })
    }

    pub fn get_endian(mmap: &Mmap) -> Endian {
        const ENDIAN_OFFSET: usize = 0x28;
        DexHeader::verify_endian(mmap.pread_with(ENDIAN_OFFSET, scroll::LE).unwrap())
    }
}

#[derive(Copy, Clone)]
pub struct EndianContext(pub(crate) Endian);

#[derive(Copy, Clone)]
pub struct TableContext<'a, 'b> {
    pub endian: Endian,
    pub header: &'a DexHeader,
    pub map: &'b Vec<MapItem>,
}

impl<'a> ctx::TryFromCtx<'a, EndianContext> for DexHeader {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], ctx: EndianContext) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        Ok((DexHeader {
            magic: {
                const MAGIC_SIZE: usize = 8;
                let mut magic = [0u8; MAGIC_SIZE];
                magic.clone_from_slice(&src[*offset..*offset + MAGIC_SIZE]);
                *offset += MAGIC_SIZE;
                DexHeader::verify_magic(&magic);
                magic
            },
            checksum: src.gread_with(offset, ctx.0)?,
            signature: {
                const SIGNATURE_SIZE: usize = 20;
                let mut signature = [0u8; SIGNATURE_SIZE];
                signature.clone_from_slice(&src[*offset..*offset + SIGNATURE_SIZE]);
                *offset += SIGNATURE_SIZE;
                signature
            },
            file_size: src.gread_with(offset, ctx.0)?,
            header_size: src.gread_with(offset, ctx.0)?,
            endian_tag: {
                let tag = src.gread_with(offset, ctx.0)?;
                DexHeader::verify_endian(tag);
                tag
            },
            link_size: src.gread_with(offset, ctx.0)?,
            link_off: src.gread_with(offset, ctx.0)?,
            map_off: src.gread_with(offset, ctx.0)?,
            string_ids_size: src.gread_with(offset, ctx.0)?,
            string_ids_off: src.gread_with(offset, ctx.0)?,
            type_ids_size: src.gread_with(offset, ctx.0)?,
            type_ids_off: src.gread_with(offset, ctx.0)?,
            proto_ids_size: src.gread_with(offset, ctx.0)?,
            proto_ids_off: src.gread_with(offset, ctx.0)?,
            field_ids_size: src.gread_with(offset, ctx.0)?,
            field_ids_off: src.gread_with(offset, ctx.0)?,
            method_ids_size: src.gread_with(offset, ctx.0)?,
            method_ids_off: src.gread_with(offset, ctx.0)?,
            class_defs_size: src.gread_with(offset, ctx.0)?,
            class_defs_off: src.gread_with(offset, ctx.0)?,
            data_size: src.gread_with(offset, ctx.0)?,
            data_off: src.gread_with(offset, ctx.0)?,
        }, *offset))
    }
}

impl<'a> ctx::TryFromCtx<'a, EndianContext> for Vec<MapItem> {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], ctx: EndianContext) -> Result<(Self, usize), Self::Error> {
        let mut offset = &mut 0;
        let size: u32 = src.gread_with(offset, ctx.0)?;
        let mut v = Vec::with_capacity(size as usize);
        for _ in 0..size {
            v.push(MapItem {
                item_type: src.gread_with(offset, ctx.0)?,
                size: {
                    *offset += 2;
                    src.gread_with(offset, ctx.0)?
                },
                offset: src.gread_with(offset, ctx.0)?,
            })
        }
        Ok((v, *offset))
    }
}

pub type StringIds = Vec<u32>;

impl<'a> TryFromCtx<'a, TableContext<'_, '_>> for StringIds {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], ctx: TableContext) -> Result<(Self, usize), Self::Error> {
        let size = ctx.header.string_ids_size as usize;
        let offset = &mut (ctx.header.string_ids_off.to_owned() as usize);
        let mut v = Vec::with_capacity(size as usize);

        for _ in 0..size {
            v.push(src.gread_with(offset, ctx.endian)?)
        }
        Ok((v, 4 * size))
    }
}

impl<'a> TryFromCtx<'a, TableContext<'_, '_>> for Vec<u32> {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], ctx: TableContext) -> Result<(Self, usize), Self::Error> {
        let size = ctx.header.type_ids_size as usize;
        let offset = &mut (ctx.header.type_ids_off.to_owned() as usize);
        let mut v = Vec::with_capacity(size as usize);

        for _ in 0..size {
            v.push(src.gread_with(offset, ctx.endian)?)
        }
        Ok((v, 4 * size))
    }
}

impl<'a> TryFromCtx<'a, TableContext<'_, '_>> for ProtoIdItem {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], ctx: TableContext<'_, '_>) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        Ok((ProtoIdItem {
            shorty_idx: src.gread_with(offset, ctx.endian)?,
            return_type_idx: src.gread_with(offset, ctx.endian)?,
            parameters_off: src.gread_with(offset, ctx.endian)?
        }, 3 * 4))
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
    pub handlers: Vec<EncodedTypeAddrPair>,
    pub catch_all_addr: Option<u64>,
}

#[derive(Debug)]
pub struct EncodedTypeAddrPair {
    pub type_idx: u64,
    pub addr: u64,
}

#[derive(Debug)]
pub struct DebugInfoItem {
    pub line_start: u64,
    pub parameter_names: Vec<i64>,
    pub state_machine_bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct AnnotationsDirectory {
    pub class_annotations_off: u32,
    pub field_annotations: Vec<FieldAnnotation>,
    pub method_annotations: Vec<MethodAnnotation>,
    pub parameter_annotations: Vec<ParameterAnnotation>,
}

#[derive(Debug)]
pub struct FieldAnnotation {
    pub field_idx: u32,
    pub annotations_off: u32,
}

#[derive(Debug)]
pub struct MethodAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

#[derive(Debug)]
pub struct ParameterAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

#[derive(Debug)]
pub struct AnnotationItem {
    pub visibility: Visibility,
    pub annotation: EncodedAnnotation,
}

#[derive(Debug)]
pub enum Visibility {
    VisibilityBuild,
    VisibilityRuntime,
    VisibilitySystem,
}

#[derive(Debug)]
pub struct EncodedAnnotation {
    pub type_idx: u64,
    pub elements: Vec<AnnotationElement>,
}

#[derive(Debug)]
pub struct AnnotationElement {
    pub name_idx: u64,
    pub value: EncodedValue,
}

#[derive(Debug)]
pub struct HiddenApiClassData {
    pub size: u32,
    pub offsets: Vec<u32>,
    pub flags: Vec<u64>,
}



#[derive(Debug)]
pub struct MapItem {
    pub item_type: u16,
    pub size: u32,
    pub offset: u32,
}

impl MapItem {
    pub fn parse_map_list(dex_header: &DexHeader, reader: &mut BufReader<File>) -> Result<Vec<MapItem>, std::io::Error> {
        reader.seek(Start(dex_header.map_off.into()))?;

        let size = read_u32(reader)?;
        let mut v = Vec::with_capacity(size as usize);
        for _ in 0..size {
            let item_type = read_u16(reader)?;
            read_u16(reader)?; // unused
            let size = read_u32(reader)?;
            let offset = read_u32(reader)?;
            v.push(MapItem { item_type, size, offset })
        }
        Ok(v)
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