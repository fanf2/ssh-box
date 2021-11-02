use crate::prelude::*;

pub fn encode(binary: &[u8]) -> String {
    use sodiumoxide::base64::Variant::*;
    sodiumoxide::base64::encode(binary, Original)
}

pub fn decode(ascii: &[u8]) -> Result<Vec<u8>> {
    use sodiumoxide::base64::Variant::*;
    sodiumoxide::base64::decode(ascii, Original)
        .map_err(|_| anyhow!("could not decode base64"))
}

pub fn armored(binary: &[u8], prefix: &str, suffix: &str) -> String {
    let oneline = encode(binary);
    let oneline = oneline.as_bytes();
    let mut ascii = String::new();
    ascii.push_str(prefix);
    const LINE_LEN: usize = 64;
    let end = oneline.len();
    let mut i = 0;
    while i < end {
        let j = i + LINE_LEN;
        let hunk = if j < end { &oneline[i..j] } else { &oneline[i..] };
        ascii.push_str(std::str::from_utf8(hunk).unwrap());
        ascii.push('\n');
        i = j;
    }
    ascii.push_str(suffix);
    ascii
}

pub fn unarmor(ascii: &[u8], prefix: &str, suffix: &str) -> Result<Vec<u8>> {
    use crate::nom::*;

    let mut unarmor = delimited(
        tag(prefix.as_bytes()),
        separated_list1(tag(b"\n"), is_a(BASE64_CHARS)),
        tuple((tag(b"\n"), tag(suffix.as_bytes()), eof)),
    );
    let (_, base64_lines) = unarmor(ascii)
        .map_err(|_: NomErr| anyhow!("could not remove ascii armor"))?;

    decode(&base64_lines.concat())
}
