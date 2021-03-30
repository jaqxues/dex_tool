use std::io::{BufReader, Read};
use std::fs::File;


pub fn to_string(reader: &mut BufReader<File>, size: u64) -> String {
    // https://cs.android.com/android/platform/superproject/+/master:dalvik/dx/src/com/android/dex/Mutf8.java
    let mut s = 0;
    let mut out: Vec<u16> = vec![0u16; size as usize];
    let mut buf = [0u8; 1];
    loop {
        let a = read_byte(reader, &mut buf) as u16;
        if a == 0 {
            let string = String::from_utf16(&out.as_slice()[..s]).unwrap();
            debug_assert!(s == size as usize, "Declared Length ({}) does not match decoded length ({})", size, s);
            return string;
        }
        out[s] = a as u16;

        if a < 0x80 {
            s += 1;
        } else if (a & 0xe0) == 0xc0 {
            let b = read_byte(reader, &mut buf) as u16;
            if (b & 0xc0) != 0x80 {
                panic!("Bad second byte")
            }
            out[s] = (((a & 0x1f) << 6) | (b & 0x3f)) as u16;
            s += 1;
        } else if (a & 0xf0) == 0xe0 {
            let b = read_byte(reader, &mut buf) as u16;
            let c = read_byte(reader, &mut buf) as u16;
            if ((b & 0xc0) != 0x80) || ((c & 0xc0) != 0x80) {
                panic!("Bad second or third byte")
            }
            out[s] = (((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f)) as u16;
            s += 1;
        } else {
            panic!("Bad byte")
        }
    }
}

pub fn read_byte(reader: &mut BufReader<File>, buf: &mut [u8; 1]) -> u8 {
    reader.read_exact(buf).unwrap();
    buf[0]
}