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
