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

    let version = verify_magic(&mut reader);
    assert!(SUPPORTED_DEX_VERSIONS.contains(&version),
            "Unsupported Dex Format Version ({})", version);

    let checksum: u32 = read_u32(&mut reader);
    let mut signature = [0u8; 20];
    reader.read(&mut signature).unwrap();
    let file_size: u32 = read_u32(&mut reader);
    let header_size: u32 = read_u32(&mut reader);
    let is_be_format = verify_endian(&mut reader);

    let data = ParsedDexHeader {
        version,
        checksum,
        signature,
        file_size,
        header_size,
        is_be_format
    };
    println!("Data: {:#?}", data);
}

fn read_u32(reader: &mut BufReader<File>) -> u32 {
    let mut buf = [0u8; 4];
    reader.read(&mut buf).unwrap();
    u32::from_le_bytes(buf)
}

fn verify_magic(reader: &mut BufReader<File>) -> u16 {
    let mut buf = [0u8; DEX_FILE_MAGIC.len()];
    reader.read(&mut buf).expect("Could not read bytes from file");

    if !(buf.starts_with(&DEX_FILE_MAGIC[0..5]) && buf.ends_with(&DEX_FILE_MAGIC[7..8])) {
        panic!("Given file does not contain correct file signature");
    }

    let version = String::from_utf8_lossy(&buf[4..7]);
    let version: u16 = version.parse().expect("Could not parse Version number");

    version
}

fn verify_endian(reader: &mut BufReader<File>) -> bool {
    let mut buf = [0u8; 4];
    reader.read(&mut buf).expect("");
    let res = u32::from_le_bytes(buf);

    match res {
        ENDIAN_CONSTANT => false,
        REVERSE_ENDIAN_CONSTANT => true,
        _ => panic!("Bytes do not match valid constants")
    }
}

#[derive(Debug)]
struct ParsedDexHeader {
    version: u16,
    checksum: u32,
    signature: [u8; 20],
    file_size: u32,
    header_size: u32,
    is_be_format: bool,
}