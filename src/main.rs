use std::fs::{File};
use std::io::{BufReader, Read};

// Bytes [4..7] specify Dex Format Version
// In string format: "dex\n035\0" with 035 being the Dex Format Version
const DEX_FILE_MAGIC: [u8; 8] = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00];
const ENDIAN_CONSTANT: u32 = 0x12345678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

const SUPPORTED_DEX_VERSIONS: [u16; 4] = [35, 37, 38, 39];

/*
References:
* https://source.android.com/devices/tech/dalvik/dex-format?hl=en
* https://cs.android.com/android/platform/superproject/+/master:dalvik/tools/dexdeps/src/com/android/dexdeps/DexData.java
* https://android.googlesource.com/platform/dalvik/+/android-4.4.2_r2/libdex/DexFile.h
* https://wiki.x10sec.org/android/basic_operating_mechanism/java_layer/dex/dex/
 */
fn main() {
    let f = File::open("mx_files/classes.dex").expect("Could not open file");
    let mut reader = BufReader::new(f);


    let dex_header = DexHeader::from_reader(&mut reader);
    let version = DexHeader::verify_magic(&dex_header.magic);

    assert!(SUPPORTED_DEX_VERSIONS.contains(&version),
            "Unsupported Dex Format Version ({})", version);

    let is_reverse_endian = DexHeader::verify_endian(dex_header.endian_tag);

    println!("File Format Version: {} - Reversed Endian: {}", version, is_reverse_endian);
    println!("{:#?}", dex_header);
}

fn read_u32(reader: &mut BufReader<File>) -> u32 {
    let mut buf = [0u8; 4];
    reader.read(&mut buf).unwrap();
    u32::from_le_bytes(buf)
}

#[derive(Debug)]
struct DexHeader {
    magic: [u8; 8],
    checksum: u32,
    signature: [u8; 20],
    file_size: u32,
    header_size: u32,
    endian_tag: u32,
    link_size: u32,
    link_off: u32,
    map_off: u32,
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
    data_size: u32,
    data_off: u32
}

impl DexHeader {
    fn verify_magic(buf: &[u8; DEX_FILE_MAGIC.len()]) -> u16 {
        if !(buf.starts_with(&DEX_FILE_MAGIC[0..5]) && buf.ends_with(&DEX_FILE_MAGIC[7..8])) {
            panic!("Given file does not contain correct file signature");
        }

        let version = String::from_utf8_lossy(&buf[4..7]);
        let version: u16 = version.parse().expect("Could not parse Version number");

        version
    }

    fn verify_endian(val: u32) -> bool {
        match val {
            ENDIAN_CONSTANT => false,
            REVERSE_ENDIAN_CONSTANT => true,
            _ => panic!("Bytes do not match valid constants")
        }
    }

    fn from_reader(reader: &mut BufReader<File>) -> DexHeader {
        let mut magic = [0u8; DEX_FILE_MAGIC.len()];
        reader.read(&mut magic).unwrap();
        DexHeader::verify_magic(&magic);

        let checksum: u32 = read_u32(reader);
        let mut signature = [0u8; 20];
        reader.read(&mut signature).unwrap();

        let header = DexHeader {
            magic,
            checksum,
            signature,
            file_size: read_u32(reader),
            header_size: read_u32(reader),
            endian_tag: read_u32(reader),
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
            data_off: read_u32(reader)
        };

        DexHeader::verify_endian(header.endian_tag);

        header
    }
}