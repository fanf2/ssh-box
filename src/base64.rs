use crate::prelude::*;

pub const BASE64_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                                  ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                  0123456789/+=";

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
pub fn pem_encap(binary: &[u8], label: &str) -> String {
    let oneline = base64_encode(binary);
    let mut ascii = String::new();
    ascii.push_str("-----BEGIN ");
    ascii.push_str(label);
    ascii.push_str("-----\n");
    for chunk in oneline.as_bytes().chunks(64) {
        ascii.push_str(from_utf8(chunk).unwrap());
        ascii.push('\n');
    }
    ascii.push_str("-----END ");
    ascii.push_str(label);
    ascii.push_str("-----\n");
    ascii
}

// RFC 7486 laxtextualmsg
pub fn pem_decap(ascii: &[u8], label: &str) -> Result<Vec<u8>> {
    use crate::nom::*;

    let mut decap = delimited(
        tuple((
            opt_space,
            tag(b"-----BEGIN "),
            tag(label.as_bytes()),
            tag(b"-----"),
            opt_space,
        )),
        separated_list1(is_space, is_a(BASE64_CHARS)),
        tuple((
            opt_space,
            tag(b"-----END "),
            tag(label.as_bytes()),
            tag(b"-----"),
            opt_space,
            eof,
        )),
    );
    let (_, base64_lines) = decap(ascii)
        .or_else(|_: NomErr| bail!("could not remove PEM encapsulation"))?;

    base64_decode(&base64_lines.concat())
}
