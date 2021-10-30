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
