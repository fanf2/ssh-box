pub use nom::branch::*;
pub use nom::bytes::complete::*;
pub use nom::character::complete::*;
pub use nom::combinator::*;
pub use nom::multi::*;
pub use nom::number::complete::*;
pub use nom::sequence::*;

use crate::key;

pub const BASE64_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                                      ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                      0123456789/+=";

pub const LDH_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                                   ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                   0123456789-_";

pub type NomError<'a> = nom::error::Error<&'a [u8]>;
pub type NomErr<'a> = nom::Err<NomError<'a>>;

type Result<'a, O> = nom::IResult<&'a [u8], O, NomError<'a>>;

type ResultIn<'a> = Result<'a, &'a [u8]>;

pub fn be_u32_is<'a>(wanted: u32) -> impl FnMut(&'a [u8]) -> Result<'a, u32> {
    verify(be_u32, move |&found| found == wanted)
}

pub fn len_tag<'a>(
    bytes: &'static [u8],
) -> impl FnMut(&'a [u8]) -> ResultIn<'a> {
    length_value(be_u32, tag(bytes))
}

pub fn ssh_string(input: &[u8]) -> ResultIn {
    length_data(be_u32)(input)
}

pub fn ssh_pubkey_ed25519(input: &[u8]) -> Result<key::Public> {
    map(
        consumed(preceded(len_tag(b"ssh-ed25519"), ssh_string)),
        |(all, raw)| key::Public::ed25519_from(all, raw),
    )(input)
}

pub fn ssh_pubkey_unknown(input: &[u8]) -> Result<key::Public> {
    map(consumed(terminated(ssh_string, rest)), |(all, algo)| {
        key::Public::unknown_from(all, algo)
    })(input)
}

pub fn ssh_pubkey(input: &[u8]) -> Result<key::Public> {
    alt((ssh_pubkey_ed25519, ssh_pubkey_unknown))(input)
}
