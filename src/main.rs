use std::fs::File;
use std::io::{BufReader, Read};

// Bytes [4..7] specify Dex Format Version
// In string format: "dex\n035\0" with 035 being the Dex Format Version
const DEX_FILE_MAGIC: [u8; 8] = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00];

fn main() {
    let f = File::open("mx_files/classes.dex").expect("Could not open file");
    let mut reader = BufReader::new(f);

    let mut buf = [0u8; DEX_FILE_MAGIC.len()];
    reader.read(&mut buf).expect("Could not read bytes from file");

    if !(buf.starts_with(&DEX_FILE_MAGIC[0..5]) && buf.ends_with(&DEX_FILE_MAGIC[7..8])) {
        panic!("Given file does not contain correct file signature");
    }

    let version = String::from_utf8_lossy(&buf[4..7]);
    println!("Dex Format Version: {} (Hexadecimals: {:02X?})", version, &buf[4..7]);
    let version: u16 = version.parse().expect("Could not parse Version number");
    println!("Parsed Version: {}", version)
}
