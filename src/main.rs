use std::borrow::Borrow;
use std::fs::{File, read};
use std::io::BufReader;
use std::iter::{FromIterator, Map};

use crate::raw_dex::{DexHeader, MapItem};

mod raw_dex;
mod m_utf8;

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
    assert!(!is_reverse_endian, "Dex Files with reverse endian tag are not supported");

    println!("File Format Version: {}", version);
    println!("{:#X?}", dex_header);

}