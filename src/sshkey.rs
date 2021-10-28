use anyhow::{anyhow, Context, Result};

const PREFIX: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
const SUFFIX: &[u8] = b"-----END OPENSSH PRIVATE KEY-----\n";

const BASE64: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                        ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                        0123456789/+=";

#[derive(Debug)]
pub struct SecretKey(Vec<u8>);

#[derive(Debug)]
pub enum PublicKey {
    Ed25519([u8; 32], String),
}

impl PublicKey {
    fn ed25519_from_bytes(bytes: &[u8], comment: &str) -> Result<PublicKey> {
        let array: [u8; 32] = bytes
            .try_into()
            .with_context(|| "ed25519 public key must be 32 bytes")?;
        Ok(PublicKey::Ed25519(array, comment.to_owned()))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicKey::Ed25519(key, comment) => {
                let mut binary = Vec::new();
                let algo = "ssh-ed25519";
                binary.extend_from_slice(&u32::to_be_bytes(algo.len() as u32));
                binary.extend_from_slice(algo.as_bytes());
                binary.extend_from_slice(&u32::to_be_bytes(32));
                binary.extend_from_slice(key);
                writeln!(f, "{} {} {}", algo, base64::encode(binary), comment)
            }
        }
    }
}

type NomErr<'a> = nom::Err<nom::error::VerboseError<&'a [u8]>>;

fn parse_secret_key(ascii: &[u8]) -> Result<SecretKey> {
    use nom::bytes::complete::*;
    use nom::combinator::*;
    use nom::multi::*;
    use nom::number::complete::*;
    use nom::sequence::*;
    let mut unarmor = complete(delimited(
        tag(PREFIX),
        separated_list1(tag(b"\n"), is_a(BASE64)),
        tuple((tag(b"\n"), tag(SUFFIX), eof)),
    ));
    let (_, base64_lines) = unarmor(ascii)
        .map_err(|_: NomErr| anyhow!("could not extract private key base64"))?;
    let binary = base64::decode(base64_lines.concat())?;

    let len_tag = |bytes: &'static [u8]| length_value(be_u32, tag(bytes));
    let be_u32_is = |wanted| verify(be_u32, move |&found| found == wanted);

    let (rest, (salt, rounds, rawkey)) = map(
        tuple((
            tag(b"openssh-key-v1\0"),
            len_tag(b"aes256-ctr"),
            len_tag(b"bcrypt"),
            map_parser(length_data(be_u32), pair(length_data(be_u32), be_u32)),
            be_u32_is(1),
            map_parser(
                length_data(be_u32),
                preceded(
                    pair(len_tag(b"ssh-ed25519"), be_u32_is(32)),
                    take(32usize),
                ),
            ),
        )),
        |(_magic, _cipher, _kdf, (salt, rounds), _keys, rawkey)| {
            (salt, rounds, rawkey)
        },
    )(&binary[..])
    .map_err(|_: NomErr| anyhow!("could not parse private key"))?;

    let pubkey = PublicKey::ed25519_from_bytes(rawkey, "")?;

    dbg!(salt);
    dbg!(rounds);
    print!("{}", pubkey);
    dbg!(rest);

    /*
    ;; AUTH_MAGIC is a hard-coded, null-terminated string,
    ;; set to "openssh-key-v1".
    byte[n] AUTH_MAGIC

    ;; ciphername determines the cipher name (if any),
    ;; or is set to "none", when no encryption is used.
    string   ciphername

    ;; kdfname determines the KDF function name, which is
    ;; either "bcrypt" or "none"
    string   kdfname

    ;; kdfoptions field.
    ;; This one is actually a buffer with size determined by the
    ;; uint32 value, which preceeds it.
    ;; If no encryption was used to protect the private key,
    ;; it's contents will be the [0x00 0x00 0x00 0x00] bytes (empty string).
    ;; You should read the embedded buffer, only if it's size is
    ;; different than 0.
    uint32 (size of buffer)
        string salt
        uint32 rounds

    ;; Number of keys embedded within the blob.
    ;; This value is always set to 1, at least in the
    ;; current implementation of the private key format.
    uint32 number-of-keys

    ;; Public key section.
    ;; This one is a buffer, in which the public key is embedded.
    ;; Size of the buffer is determined by the uint32 value,
    ;; which preceeds it.
    ;; ED25519 public key components.
    uint32 (size of buffer)
        string keytype ("ssh-ed25519")

        ;; The ED25519 public key is a buffer of size 32.
        ;; The encoding follows the same rules for any
        ;; other buffer used by SSH -- the size of the
        ;; buffer preceeds the actual data.
        uint32 + byte[32]

    ;; Encrypted section
    ;; This one is a again a buffer with size
    ;; specified by the uint32 value, which preceeds it.
    ;; ED25519 private key.
    uint32 (size of buffer)
        uint32  check-int
        uint32  check-int  (must match with previous check-int value)
        string  keytype    ("ssh-ed25519")

        ;; The public key
        uint32 + byte[32]  (public key)

        ;; Secret buffer. This is a buffer with size 64 bytes.
        ;; The bytes[0..32] contain the private key and
        ;; bytes[32..64] contain the public key.
        ;; Once decoded you can extract the private key by
        ;; taking the byte[0..32] slice.
        uint32 + byte[64]  (secret buffer)

        string  comment    (Comment associated with the key)
        byte[n] padding    (Padding according to the rules above)
    */
    Ok(SecretKey(binary))
}

pub fn read_secret_key(key_file: &str) -> Result<SecretKey> {
    let ascii = std::fs::read(key_file)
        .with_context(|| format!("failed to read {}", key_file))?;
    parse_secret_key(&ascii)
        .map_err(|err| anyhow!("could not parse {}: {}", key_file, err))
}
