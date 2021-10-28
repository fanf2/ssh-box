use anyhow::{anyhow, Context, Result};

const PREFIX: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
const SUFFIX: &[u8] = b"-----END OPENSSH PRIVATE KEY-----\n";
const BASE64: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                        ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                        0123456789/+=";

#[derive(Debug)]
pub struct SecretKey(Vec<u8>);

fn parse_secret_key(armored: &[u8]) -> Result<SecretKey> {
    use nom::bytes::complete::*;
    use nom::combinator::*;
    use nom::multi::*;
    use nom::sequence::*;
    let mut parse = complete(all_consuming(delimited(
        tag(PREFIX),
        separated_list1(tag(b"\n"), is_a(BASE64)),
        tuple((tag(b"\n"), tag(SUFFIX), eof)),
    )));
    let (_, bare) = parse(armored).map_err(
        |_: nom::Err<nom::error::VerboseError<&[u8]>>| {
            anyhow!("could not extract private key base64")
        },
    )?;
    Ok(SecretKey(base64::decode(bare.concat())?))
}

pub fn read_secret_key(key_file: &str) -> Result<SecretKey> {
    let ascii = std::fs::read(key_file)
        .with_context(|| format!("failed to read {}", key_file))?;
    parse_secret_key(&ascii)
        .map_err(|err| anyhow!("could not parse {}: {}", key_file, err))
}
