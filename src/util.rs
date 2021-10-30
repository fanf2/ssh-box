pub fn append_ssh_string(buffer: &mut Vec<u8>, string: &[u8]) {
    buffer.extend_from_slice(&(string.len() as u32).to_be_bytes());
    buffer.extend_from_slice(string);
}

pub mod nom {
    pub const BASE64_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                                      ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                      0123456789/+=";

    pub const LDH_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                                   ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                   0123456789-_";

    pub type NomErr<'a> = nom::Err<nom::error::Error<&'a [u8]>>;

    pub use nom::branch::*;
    pub use nom::bytes::complete::*;
    pub use nom::character::complete::*;
    pub use nom::combinator::*;
    pub use nom::multi::*;
    pub use nom::number::complete::*;
    pub use nom::sequence::*;
}

pub mod base64 {
    use super::*;
    use anyhow::{anyhow, Result};
    use sodiumoxide::base64::Variant;

    pub fn encode<B>(binary: B) -> String
    where
        B: AsRef<[u8]>,
    {
        sodiumoxide::base64::encode(binary, Variant::Original)
    }

    pub fn decode<A>(ascii: A) -> Result<Vec<u8>>
    where
        A: AsRef<[u8]>,
    {
        sodiumoxide::base64::decode(ascii, Variant::Original)
            .map_err(|_| anyhow!("could not decode base64"))
    }

    pub fn unarmor(
        ascii: &[u8],
        prefix: &[u8],
        suffix: &[u8],
    ) -> Result<Vec<u8>> {
        use crate::util::nom::*;

        let mut unarmor = delimited(
            tag(prefix),
            separated_list1(tag(b"\n"), is_a(BASE64_CHARS)),
            tuple((tag(b"\n"), tag(suffix), eof)),
        );
        let (_, base64_lines) = unarmor(ascii)
            .map_err(|_: NomErr| anyhow!("could not parse armored base64"))?;

        decode(base64_lines.concat())
    }
}
