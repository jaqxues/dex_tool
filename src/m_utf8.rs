use std::io::{BufReader, Read};
use std::fs::File;
use std::fmt;
use crate::m_utf8::MUTF8Error::{BadSecondByte, BadByte, BadSecondThirdByte};

#[derive(Debug)]
pub enum MUTF8Error {
    BadByte,
    BadSecondByte,
    BadSecondThirdByte
}

impl std::error::Error for MUTF8Error {}

impl fmt::Display for MUTF8Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MUTF8Error::BadByte => write!(f, "Bad byte"),
            MUTF8Error::BadSecondByte => write!(f, "Bad second byte"),
            MUTF8Error::BadSecondThirdByte => write!(f, "Bad second or third byte"),
        }
    }
}

pub fn to_string(reader: &mut BufReader<File>, size: u64) -> Result<String, MUTF8Error> {
    // https://cs.android.com/android/platform/superproject/+/master:dalvik/dx/src/com/android/dex/Mutf8.java
    let mut s = 0;
    let mut out: Vec<u16> = vec![0u16; size as usize];
    let mut buf = [0u8; 1];
    loop {
        let a = read_byte(reader, &mut buf) as u16;
        if a == 0 {
            let string = String::from_utf16(&out.as_slice()[..s]).unwrap();
            debug_assert!(s == size as usize, "Declared Length ({}) does not match decoded length ({})", size, s);
            return Ok(string);
        }
        out[s] = a as u16;

        if a < 0x80 {
            s += 1;
        } else if (a & 0xe0) == 0xc0 {
            let b = read_byte(reader, &mut buf) as u16;
            if (b & 0xc0) != 0x80 {
                return Err(BadSecondByte)
            }
            out[s] = (((a & 0x1f) << 6) | (b & 0x3f)) as u16;
            s += 1;
        } else if (a & 0xf0) == 0xe0 {
            let b = read_byte(reader, &mut buf) as u16;
            let c = read_byte(reader, &mut buf) as u16;
            if ((b & 0xc0) != 0x80) || ((c & 0xc0) != 0x80) {
                return Err(BadSecondThirdByte)
            }
            out[s] = (((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f)) as u16;
            s += 1;
        } else {
            return Err(BadByte)
        }
    }
}

pub fn read_byte(reader: &mut BufReader<File>, buf: &mut [u8; 1]) -> u8 {
    reader.read_exact(buf).unwrap();
    buf[0]
}