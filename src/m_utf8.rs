use std::fmt;
use std::fmt::Debug;
use std::fs::File;
use std::io::BufReader;
use std::string::FromUtf16Error;
use crate::m_utf8::LoadMUtf8StringError::{DecodeError, ReadError, Utf16ToStringError};

use crate::m_utf8::MUtf8ParseError::{BadByte, BadSecondByte, BadSecondThirdByte};
use crate::raw_dex::read_u8;

#[derive(Debug)]
// fixme Possible improvement: add position of seeker (absolute or relative?)
pub enum MUtf8ParseError {
    BadByte,
    BadSecondByte,
    BadSecondThirdByte,
}

#[derive(Debug)]
pub enum LoadMUtf8StringError {
    DecodeError(MUtf8ParseError),
    ReadError(std::io::Error),
    Utf16ToStringError(FromUtf16Error),
}

impl std::error::Error for MUtf8ParseError {}
impl std::error::Error for LoadMUtf8StringError {}

impl fmt::Display for MUtf8ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BadByte => write!(f, "Bad byte"),
            BadSecondByte => write!(f, "Bad second byte"),
            BadSecondThirdByte => write!(f, "Bad second or third byte"),
        }
    }
}

impl fmt::Display for LoadMUtf8StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeError(d_err) => std::fmt::Display::fmt(&d_err, f),
            ReadError(r_err) => std::fmt::Display::fmt(&r_err, f),
            Utf16ToStringError(s_err) => std::fmt::Display::fmt(&s_err, f),
        }
    }
}

pub fn to_string(reader: &mut BufReader<File>, size: u64) -> Result<String, LoadMUtf8StringError> {
    // https://cs.android.com/android/platform/superproject/+/master:dalvik/dx/src/com/android/dex/Mutf8.java
    let mut s = 0;
    let mut out: Vec<u16> = vec![0u16; size as usize];
    let mut buf = [0u8; 1];
    loop {
        let a = read_u8(reader, &mut buf).map_err(|r_err| ReadError(r_err))? as u16;
        if a == 0 {
            let string = String::from_utf16(&out.as_slice()[..s]).map_err(|s_err| Utf16ToStringError(s_err))?;
            debug_assert!(s == size as usize,
                          "Declared Length ({}) does not match decoded length ({})", size, s);
            return Ok(string);
        }
        out[s] = a as u16;

        if a < 0x80 {
            s += 1;
        } else if (a & 0xe0) == 0xc0 {
            let b = read_u8(reader, &mut buf).map_err(|r_err| ReadError(r_err))? as u16;
            if (b & 0xc0) != 0x80 {
                return Err(DecodeError(BadSecondByte));
            }
            out[s] = (((a & 0x1f) << 6) | (b & 0x3f)) as u16;
            s += 1;
        } else if (a & 0xf0) == 0xe0 {
            let b = read_u8(reader, &mut buf).map_err(|r_err| ReadError(r_err))? as u16;
            let c = read_u8(reader, &mut buf).map_err(|r_err| ReadError(r_err))? as u16;
            if ((b & 0xc0) != 0x80) || ((c & 0xc0) != 0x80) {
                return Err(DecodeError(BadSecondThirdByte));
            }
            out[s] = (((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f)) as u16;
            s += 1;
        } else {
            return Err(DecodeError(BadByte));
        }
    }
}
