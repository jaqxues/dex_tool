use std::fs::File;
use std::io::{BufReader, Read};

// Bytes [5..7] specify Dex Format Version
// In string format: "dex\n035\0" with 35 being the Dex Format Version
const DEX_FILE_MAGIC: [u8; 8] = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00];

fn main() {
    let f = File::open("mx_files/classes.dex").expect("");
    let mut reader = BufReader::new(f);

    let mut buf = [0u8; DEX_FILE_MAGIC.len()];
    reader.read(&mut buf);

    if !(buf.starts_with(&DEX_FILE_MAGIC[0..5]) && buf.ends_with(&DEX_FILE_MAGIC[7..8])) {
        panic!("Given file does not contain correct file signature");
    }

    let version: u8 = String::from_utf8_lossy(&buf[5..7]).parse().expect("");
    println!("Dex Format Version: {} (Hexadecimals: {:02X?})", version, &buf[5..7]);
}
