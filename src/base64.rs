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

// RFC 7486 stricttextualmsg
pub fn pem_encap(binary: &[u8], prefix: &str, suffix: &str) -> String {
    let oneline = base64_encode(binary);
    let mut ascii = String::new();
    ascii.push_str(prefix);
    ascii.push('\n');
    for line in oneline.as_bytes().chunks(64) {
        ascii.push_str(std::str::from_utf8(line).unwrap());
        ascii.push('\n');
    }
    ascii.push_str(suffix);
    ascii.push('\n');
    ascii
}

// RFC 7486 laxtextualmsg
pub fn pem_decap(ascii: &[u8], prefix: &str, suffix: &str) -> Result<Vec<u8>> {
    use crate::nom::*;

    let mut decap = delimited(
        tuple((opt_space, tag(prefix.as_bytes()), opt_space)),
        separated_list1(is_space, is_a(BASE64_CHARS)),
        tuple((opt_space, tag(suffix.as_bytes()), opt_space, eof)),
    );
    let (_, base64_lines) = decap(ascii)
        .or_else(|_: NomErr| bail!("could not remove PEM encapsulation"))?;

    base64_decode(&base64_lines.concat())
}
