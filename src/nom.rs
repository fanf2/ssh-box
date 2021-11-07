use crate::prelude::*;

pub use nom::branch::*;
pub use nom::bytes::complete::*;
pub use nom::character::complete::*;
pub use nom::combinator::*;
pub use nom::multi::*;
pub use nom::number::complete::*;
pub use nom::sequence::*;

use nom::error::ParseError;

pub type NomError<'a> = nom::error::Error<&'a [u8]>;
pub type NomErr<'a> = nom::Err<NomError<'a>>;

type Result<'a, O> = nom::IResult<&'a [u8], O, NomError<'a>>;

fn commentary(input: &[u8]) -> Result<usize> {
    many0_count(tuple((
        space0,
        opt(pair(tag(b"#"), not_line_ending)),
        line_ending,
    )))(input)
}

fn commented_newline(input: &[u8]) -> Result<usize> {
    preceded(line_ending, commentary)(input)
}

pub fn commented_lines<'a, P, O>(
    parse_line: P,
) -> impl FnMut(&'a [u8]) -> Result<'a, Vec<O>>
where
    P: FnMut(&'a [u8]) -> Result<'a, O>,
{
    delimited(
        commentary,
        many1(terminated(parse_line, pair(line_ending, commentary))),
        eof,
    )
}

pub fn is_utf8<'a, P>(parser: P) -> impl FnMut(&'a [u8]) -> Result<'a, &'a str>
where
    P: FnMut(&'a [u8]) -> Result<'a, &'a [u8]>,
{
    map_res(parser, from_utf8)
}

// RFC 7468 `W` space: HT, LF, VT, FF, CR, SP
fn space_char(c: u8) -> bool {
    b"\x09\x0A\x0B\x0C\x0D\x20".contains(&c)
}

pub fn opt_space(input: &[u8]) -> Result<&[u8]> {
    take_while(space_char)(input)
}

pub fn is_space(input: &[u8]) -> Result<&[u8]> {
    take_while1(space_char)(input)
}

pub fn be_u32_is<'a>(wanted: u32) -> impl FnMut(&'a [u8]) -> Result<'a, u32> {
    verify(be_u32, move |&found| found == wanted)
}

// RFC 4250 section 4.6
pub fn ssh_name(input: &[u8]) -> Result<&[u8]> {
    take_while1(|ch| ch > b' ' && ch <= b'~' && ch != b',')(input)
}

pub fn ssh_string(input: &[u8]) -> Result<&[u8]> {
    length_data(be_u32)(input)
}

pub fn ssh_string_owned(input: &[u8]) -> Result<Vec<u8>> {
    map(ssh_string, |s| s.to_owned())(input)
}

pub fn ssh_record(input: &[u8]) -> Result<Record> {
    many1(ssh_string_owned)(input)
}

pub fn ssh_string_tag<'a>(
    word: &'static str,
) -> impl FnMut(&'a [u8]) -> Result<&str> {
    length_value(be_u32, is_utf8(tag(word.as_bytes())))
}

pub fn seckey_padding(input: &[u8]) -> Result<()> {
    for (i, &c) in input.iter().enumerate() {
        if c != 1 + i as u8 {
            let e = nom::error::ErrorKind::Tag;
            return Err(nom::Err::Error(NomError::from_error_kind(input, e)));
        }
    }
    Ok((&input[input.len()..], ()))
}
