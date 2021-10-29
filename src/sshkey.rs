use anyhow::{anyhow, Context, Result};

const PREFIX: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
const SUFFIX: &[u8] = b"-----END OPENSSH PRIVATE KEY-----\n";

const BASE64: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                        ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                        0123456789/+=";

#[derive(Clone, Debug)]
pub enum PublicKey {
    Ed25519 { public: [u8; 32], comment: String },
}

#[derive(Clone, Debug)]
pub enum SecretKey {
    Ed25519 { secret: [u8; 32], public: [u8; 32], comment: String },
}

impl From<SecretKey> for PublicKey {
    fn from(secret: SecretKey) -> PublicKey {
        match secret {
            SecretKey::Ed25519 { secret: _, public, comment } => {
                PublicKey::Ed25519 { public, comment }
            }
        }
    }
}

fn ed25519_from_bytes(key: &[u8]) -> Result<[u8; 32]> {
    key.try_into().with_context(|| "ed25519 key must be 32 bytes")
}

impl PublicKey {
    fn ed25519_from_bytes(public: &[u8], comment: &[u8]) -> Result<PublicKey> {
        let public = ed25519_from_bytes(public)?;
        let comment = String::from_utf8(comment.to_owned())?;
        Ok(PublicKey::Ed25519 { public, comment })
    }
}

impl SecretKey {
    fn ed25519_from_bytes(
        secret: &[u8],
        public: &[u8],
        comment: &[u8],
    ) -> Result<SecretKey> {
        let secret = ed25519_from_bytes(secret)?;
        let public = ed25519_from_bytes(public)?;
        let comment = String::from_utf8(comment.to_owned())?;
        Ok(SecretKey::Ed25519 { secret, public, comment })
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicKey::Ed25519 { public, comment } => {
                let mut binary = Vec::new();
                let algo = "ssh-ed25519";
                binary.extend_from_slice(&u32::to_be_bytes(algo.len() as u32));
                binary.extend_from_slice(algo.as_bytes());
                binary.extend_from_slice(&u32::to_be_bytes(32));
                binary.extend_from_slice(public);
                writeln!(f, "{} {} {}", algo, base64::encode(binary), comment)
            }
        }
    }
}

type NomErr<'a> = nom::Err<nom::error::VerboseError<&'a [u8]>>;

fn parse_secret_key(ascii: &[u8]) -> Result<SecretKey> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::NewCipher;
    use aes::cipher::StreamCipher;
    use nom::bytes::complete::*;
    use nom::combinator::*;
    use nom::multi::*;
    use nom::number::complete::*;
    use nom::sequence::*;

    let mut unarmor = delimited(
        tag(PREFIX),
        separated_list1(tag(b"\n"), is_a(BASE64)),
        tuple((tag(b"\n"), tag(SUFFIX), eof)),
    );
    let (_, base64_lines) = unarmor(ascii)
        .map_err(|_: NomErr| anyhow!("could not find private key base64"))?;

    let binary = base64::decode(base64_lines.concat())?;

    let len_tag = |bytes: &'static [u8]| length_value(be_u32, tag(bytes));
    let be_u32_is = |wanted| verify(be_u32, move |&found| found == wanted);
    let ssh_string = || length_data(be_u32);

    let parse_preamble = tuple((
        tag(b"openssh-key-v1\0"),
        len_tag(b"aes256-ctr"),
        len_tag(b"bcrypt"),
    ));

    let parse_bcrypt_params =
        map_parser(ssh_string(), pair(ssh_string(), be_u32));

    let parse_pubkey = map_parser(
        ssh_string(),
        preceded(len_tag(b"ssh-ed25519"), ssh_string()),
    );

    let (_, (_preamble, (salt, rounds), _keycount, pubkey1, encrypted, _eof)) =
        tuple((
            parse_preamble,
            parse_bcrypt_params,
            be_u32_is(1),
            parse_pubkey,
            ssh_string(),
            eof,
        ))(&binary[..])
        .map_err(|_: NomErr| anyhow!("could not parse private key"))?;

    const KEY_LEN: usize = 32;
    const IV_LEN: usize = 16;

    let mut aes_key_iv = [0u8; KEY_LEN + IV_LEN];
    bcrypt_pbkdf::bcrypt_pbkdf("testing", salt, rounds, &mut aes_key_iv)?;

    let aes_key = GenericArray::from_slice(&aes_key_iv[0..KEY_LEN]);
    let aes_iv = GenericArray::from_slice(&aes_key_iv[KEY_LEN..]);

    let mut cipher = aes::Aes256Ctr::new(aes_key, aes_iv);
    let mut secrets = encrypted.to_owned();
    cipher.apply_keystream(&mut secrets);

    let parse_seckey =
        map_parser(ssh_string(), pair(take(32usize), take(32usize)));

    let (pad, (check1, check2, _type, pubkey2, (seckey, pubkey3), comment)) =
        tuple((
            be_u32,
            be_u32,
            len_tag(b"ssh-ed25519"),
            ssh_string(),
            parse_seckey,
            ssh_string(),
        ))(&secrets[..])
        .map_err(|_: NomErr| anyhow!("could not parse encrypted key"))?;

    if check1 != check2 {
        return Err(anyhow!("could not decrypt private key"));
    }
    if pubkey1 != pubkey2 || pubkey2 != pubkey3 {
        return Err(anyhow!("inconsistent private key"));
    }
    for (i, &e) in pad.iter().enumerate() {
        if e != 1 + i as u8 {
            return Err(anyhow!("erroneous padding in private key"));
        }
    }

    let key = SecretKey::ed25519_from_bytes(seckey, pubkey3, comment)?;

    print!("{}", PublicKey::from(key.clone()));

    Ok(key)
}

pub fn read_secret_key(key_file: &str) -> Result<SecretKey> {
    let ascii = std::fs::read(key_file)
        .with_context(|| format!("failed to read {}", key_file))?;
    parse_secret_key(&ascii)
        .map_err(|err| anyhow!("could not parse {}: {}", key_file, err))
}
