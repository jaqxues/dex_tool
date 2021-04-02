use std::fs::File;
use std::io::BufReader;

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

    let _map_list = MapItem::parse_map_list(&dex_header, &mut reader);
    let _strings = raw_dex::parse_strings(&dex_header, &mut reader);
    let _type_ids = raw_dex::parse_types(&dex_header, &mut reader);
    let _proto_ids = raw_dex::parse_protos(&dex_header, &mut reader);
    let _field_ids = raw_dex::parse_fields(&dex_header, &mut reader);
    let _method_ids = raw_dex::parse_methods(&dex_header, &mut reader);
    let _class_defs = raw_dex::parse_classes(&dex_header, &mut reader);
    raw_dex::parse_call_side_items(&_map_list, &mut reader)
}