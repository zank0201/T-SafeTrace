

use std::{fmt::Write, num::ParseIntError};

///hex decoder from https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
/// Fucntion takes in string and converts to bytes
/// returns array of bytes
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
// fn main() {
//
//     let key ="006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
//     let bytes = decode_hex(key).unwrap();
//     println!("{:#04x?}",&bytes);
// }
