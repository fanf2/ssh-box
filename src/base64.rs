use crate::prelude::*;

pub fn base64_encode(binary: &[u8]) -> String {
    use sodiumoxide::base64::Variant::*;
    sodiumoxide::base64::encode(binary, Original)
}

pub fn base64_decode(ascii: &[u8]) -> Result<Vec<u8>> {
    use sodiumoxide::base64::Variant::*;
    sodiumoxide::base64::decode(ascii, Original)
        .or_else(|_| bail!("could not decode base64"))
}

pub fn ascii_armored(binary: &[u8], prefix: &str, suffix: &str) -> String {
    let oneline = base64_encode(binary);
    let mut ascii = String::new();
    ascii.push_str(prefix);
    for line in oneline.as_bytes().chunks(64) {
        ascii.push_str(std::str::from_utf8(line).unwrap());
        ascii.push('\n');
    }
    ascii.push_str(suffix);
    ascii
}

pub fn ascii_unarmor(
    ascii: &[u8],
    prefix: &str,
    suffix: &str,
) -> Result<Vec<u8>> {
    use crate::nom::*;

    let mut unarmor = delimited(
        tag(prefix.as_bytes()),
        separated_list1(tag(b"\n"), is_a(BASE64_CHARS)),
        tuple((tag(b"\n"), tag(suffix.as_bytes()), eof)),
    );
    let (_, base64_lines) = unarmor(ascii)
        .or_else(|_: NomErr| bail!("could not remove ascii armor"))?;

    base64_decode(&base64_lines.concat())
}
