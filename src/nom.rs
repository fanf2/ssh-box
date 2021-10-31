pub use nom::branch::*;
pub use nom::bytes::complete::*;
pub use nom::character::complete::*;
pub use nom::combinator::*;
pub use nom::multi::*;
pub use nom::number::complete::*;
pub use nom::sequence::*;

use crate::base64;
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

pub fn is_utf8<'a, P>(parser: P) -> impl FnMut(&'a [u8]) -> Result<'a, &'a str>
where
    P: FnMut(&'a [u8]) -> ResultIn<'a>,
{
    map_res(parser, std::str::from_utf8)
}

pub fn is_base64(input: &[u8]) -> Result<Vec<u8>> {
    map_res(is_a(BASE64_CHARS), base64::decode)(input)
}

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

pub fn is_ldh(input: &[u8]) -> Result<&str> {
    is_utf8(is_a(LDH_CHARS))(input)
}

pub fn ssh_string_ldh(input: &[u8]) -> Result<&str> {
    length_value(be_u32, is_ldh)(input)
}

pub fn ssh_pubkey_ed25519(input: &[u8]) -> Result<key::Public> {
    map(
        consumed(preceded(len_tag(b"ssh-ed25519"), ssh_string)),
        |(all, raw)| key::Public::ed25519_from(all, raw),
    )(input)
}

pub fn ssh_pubkey_unknown(input: &[u8]) -> Result<key::Public> {
    map(consumed(terminated(ssh_string_ldh, rest)), |(all, algo)| {
        key::Public::unknown_from(all, algo)
    })(input)
}

pub fn ssh_pubkey(input: &[u8]) -> Result<key::Public> {
    alt((ssh_pubkey_ed25519, ssh_pubkey_unknown))(input)
}
