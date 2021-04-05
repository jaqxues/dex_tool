use std::fs::File;
use std::io::BufReader;

use crate::raw_dex::DexHeader;

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

    let map = raw_dex::MapItem::parse_map_list(&dex_header, &mut reader);

    let string_ids = raw_dex::parse_string_ids(&dex_header, &mut reader);
    let string_data = raw_dex::parse_string_data(string_ids, &mut reader);
    let type_ids = raw_dex::parse_type_ids(&dex_header, &mut reader);
    let proto_ids = raw_dex::parse_proto_ids(&dex_header, &mut reader);
    let field_ids = raw_dex::parse_field_ids(&dex_header, &mut reader);
    let method_ids = raw_dex::parse_method_ids(&dex_header, &mut reader);
    let class_defs = raw_dex::parse_class_defs(&dex_header, &mut reader);
    let call_side_ids = raw_dex::parse_call_side_ids(&map, &mut reader);
    let method_handles = raw_dex::parse_method_handles(&map, &mut reader);
    let class_data = raw_dex::parse_class_data(&map, &mut reader);
    let type_list = raw_dex::parse_type_lists(&map, &mut reader);
    let code_items = raw_dex::parse_code_items(&map, &mut reader);
    let debug_info = raw_dex::parse_debug_info(&map, &mut reader);
    let annotations_directories = raw_dex::parse_annotations_directories(&map, &mut reader);
    let annotation_set_ref_list = raw_dex::parse_annotation_set_ref_list(&map, &mut reader);
    let annotation_set_item = raw_dex::parse_annotation_set_item(&map, &mut reader);
    let hiddenapi_class_data = raw_dex::parse_hiddenapi_class_data(&map, &mut reader);
}