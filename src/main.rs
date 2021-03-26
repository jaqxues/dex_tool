use std::fs::{File};
use std::io::{BufReader, Read, Seek, SeekFrom};

// Bytes [4..7] specify Dex Format Version
// In string format: "dex\n035\0" with 035 being the Dex Format Version
const DEX_FILE_MAGIC: [u8; 8] = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00];
const ENDIAN_CONSTANT: u32 = 0x12345678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

fn main() {
    let f = File::open("mx_files/classes.dex").expect("Could not open file");
    let mut reader = BufReader::new(f);

    let version = verify_magic(&mut reader);
    reader.seek(SeekFrom::Start(8 + 4 + 20 + 4 + 4)).unwrap();
    let is_be_format = verify_endian(&mut reader);

    println!("Parsed information about dex file: \n\t* Version: {}\n\t* Big-Endian: {}", version, is_be_format);
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
        _ => panic!("Bytes do not match valid constant")
    }
}