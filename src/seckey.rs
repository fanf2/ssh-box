use crate::prelude::*;

#[derive(Clone, Debug, Eq)]
pub struct SecretKey {
    pub pubkey: PublicKey,
    pub blob: Vec<u8>,
    parts: SecretParts,
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.parts == other.parts
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SecretParts {
    Ed25519(curve25519::PublicKey, curve25519::SecretKey),
    RsaOaep(Box<RsaPrivateKey>),
}

impl SecretKey {
    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let failed = || anyhow!("could not decrypt with {}", self.pubkey);
        match &self.parts {
            SecretParts::Ed25519(pubkey, seckey) => {
                sealedbox::open(message, pubkey, seckey).map_err(|_| failed())
            }
            SecretParts::RsaOaep(key) => {
                key.decrypt(rsa_oaep_padding(), message).map_err(|_| failed())
            }
        }
    }
}

pub fn read_secret_key(key_file: &str, askpass: AskPass) -> Result<SecretKey> {
    let context = || format!("reading {}", key_file);
    let ascii = std::fs::read(key_file).with_context(context)?;
    parse_secret_key(&ascii, askpass).with_context(context)
}

// See https://dnaeon.github.io/openssh-private-key-binary-format/

pub fn parse_secret_key(ascii: &[u8], askpass: AskPass) -> Result<SecretKey> {
    use crate::nom::*;

    let binary = ascii_unarmor(
        ascii,
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "-----END OPENSSH PRIVATE KEY-----\n",
    )?;

    let bcrypt_params = preceded(
        pair(ssh_string_tag("aes256-ctr"), ssh_string_tag("bcrypt")),
        map_parser(ssh_string, pair(ssh_string, be_u32)),
    );
    let none_params =
        tuple((ssh_string_tag("none"), ssh_string_tag("none"), be_u32_is(0)));
    let cipher_params =
        alt((map(bcrypt_params, Some), value(None, none_params)));

    let (_, (cipher_params, mut pubkey, enciphered)) = tuple((
        preceded(tag(b"openssh-key-v1\0"), cipher_params),
        preceded(be_u32_is(1), ssh_string_pubkey),
        terminated(ssh_string, eof),
    ))(&binary[..])
    .map_err(|_: NomErr| anyhow!("could not parse private key"))?;

    let mut secrets = enciphered.to_owned();

    let blocksize = if cipher_params.is_some() { 16 } else { 8 };
    if enciphered.len() % blocksize != 0 {
        return Err(anyhow!("bad alignment in private key"));
    }
    if let Some((salt, rounds)) = cipher_params {
        bcrypt_aes_decrypt(&mut secrets, salt, rounds, askpass)?;
    }

    type Builder = fn(&PublicKey, Vec<&[u8]>) -> Result<SecretParts>;

    let (algo, builder, part_count): (&str, Builder, usize) =
        match pubkey.algo.as_str() {
            "ssh-ed25519" => ("ssh-ed25519", new_ed25519, ED25519_PARTS),
            "ssh-rsa" => ("ssh-rsa", new_rsa_oaep, RSA_OAEP_PARTS),
            _ => return Err(anyhow!("unsupported algoritm")),
        };

    let split_parts =
        preceded(ssh_string_tag(algo), count(ssh_string, part_count + 1));
    let (pad, (check1, check2, (blob, mut secret_parts))) =
        tuple((be_u32, be_u32, consumed(split_parts)))(&secrets[..])
            .map_err(|_: NomErr| anyhow!("could not parse encrypted key"))?;

    if check1 != check2 {
        return Err(anyhow!("could not decrypt private key"));
    }
    for (i, &e) in pad.iter().enumerate() {
        if e != 1 + i as u8 {
            return Err(anyhow!("erroneous padding in private key"));
        }
    }

    pubkey.name = String::from_utf8(secret_parts.pop().unwrap().to_owned())?;
    let parts = builder(&pubkey, secret_parts)?;
    let blob = blob.to_owned();

    Ok(SecretKey { pubkey, blob, parts })
}

fn bcrypt_aes_decrypt(
    secrets: &mut [u8],
    salt: &[u8],
    rounds: u32,
    mut askpass: AskPass,
) -> Result<()> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::NewCipher;
    use aes::cipher::StreamCipher;

    // dunno the right way to get these constants
    const KEY_LEN: usize = 32;
    const IV_LEN: usize = 16;

    let password = askpass()?;
    let mut aes_key_iv = [0u8; KEY_LEN + IV_LEN];
    bcrypt_pbkdf::bcrypt_pbkdf(&password, salt, rounds, &mut aes_key_iv)?;

    let aes_key = GenericArray::from_slice(&aes_key_iv[0..KEY_LEN]);
    let aes_iv = GenericArray::from_slice(&aes_key_iv[KEY_LEN..]);

    let mut cipher = aes::Aes256Ctr::new(aes_key, aes_iv);
    cipher.apply_keystream(secrets);

    Ok(())
}

const ED25519_PARTS: usize = 2;

fn new_ed25519(pubkey: &PublicKey, parts: Vec<&[u8]>) -> Result<SecretParts> {
    use crate::nom::*;
    assert!(parts.len() == ED25519_PARTS);

    let raw_pub = parts[0];
    let raw_sec = parts[1];

    tuple((
        ssh_string_tag("ssh-ed25519"),
        length_value(be_u32, tag(raw_pub)),
        eof,
    ))(&pubkey.blob)
    .map_err(|_: NomErr| anyhow!("inconsistent private key"))?;

    let ed_sec = ed25519::SecretKey::from_slice(raw_sec)
        .ok_or_else(|| anyhow!("invalid ed25519 secret key"))?;
    let ed_pub = ed_sec.public_key();

    if raw_pub != ed_pub.as_ref() {
        return Err(anyhow!("inconsistent private key"));
    }

    let cannot = |_| anyhow!("cannot decrypt with this private key");
    let curve_pub = ed25519::to_curve25519_pk(&ed_pub).map_err(cannot)?;
    let curve_sec = ed25519::to_curve25519_sk(&ed_sec).map_err(cannot)?;

    Ok(SecretParts::Ed25519(curve_pub, curve_sec))
}

const RSA_OAEP_PARTS: usize = 6;

#[allow(clippy::many_single_char_names)]
fn new_rsa_oaep(pubkey: &PublicKey, parts: Vec<&[u8]>) -> Result<SecretParts> {
    use crate::nom::*;
    assert!(parts.len() == RSA_OAEP_PARTS);

    let n = BigUint::from_bytes_be(parts[0]);
    let e = BigUint::from_bytes_be(parts[1]);
    let d = BigUint::from_bytes_be(parts[2]);
    // skip iqmp
    let p = BigUint::from_bytes_be(parts[4]);
    let q = BigUint::from_bytes_be(parts[5]);

    tuple((
        ssh_string_tag("ssh-rsa"),
        length_value(be_u32, tag(parts[1])),
        length_value(be_u32, tag(parts[0])),
        eof,
    ))(&pubkey.blob)
    .map_err(|_: NomErr| anyhow!("inconsistent private key"))?;

    let key = RsaPrivateKey::from_components(n, e, d, vec![p, q]);
    key.validate()?;

    // box it up because it is big
    Ok(SecretParts::RsaOaep(Box::new(key)))
}

#[cfg(test)]
mod test {

    const SECRET_NONE: &[u8] = b"\
    -----BEGIN OPENSSH PRIVATE KEY-----\n\
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
    QyNTUxOQAAACDCP67FyNO6h3/nvVM9Jn3lEb0+q3W+oNpplDSp0077tQAAAJB0TYerdE2H\n\
    qwAAAAtzc2gtZWQyNTUxOQAAACDCP67FyNO6h3/nvVM9Jn3lEb0+q3W+oNpplDSp0077tQ\n\
    AAAEBDwWHy+pCf/WKlyhwwHFymEl2/lxVF0PIPyIP7nzLK08I/rsXI07qHf+e9Uz0mfeUR\n\
    vT6rdb6g2mmUNKnTTvu1AAAAB3Rlc3RpbmcBAgMEBQY=\n\
    -----END OPENSSH PRIVATE KEY-----\n\
    ";

    const SECRET_BCRYPT: &[u8] = b"\
    -----BEGIN OPENSSH PRIVATE KEY-----\n\
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAFaUJX8M\n\
    Pwuw/dD36vf2AcAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIMI/rsXI07qHf+e9\n\
    Uz0mfeURvT6rdb6g2mmUNKnTTvu1AAAAkOuSWLhj5JqnarRMioKy73Il5YWCsHO1BvDPpl\n\
    tahgUYIbTHhzTuZrNwliprVzaDss/9DFESP36tZF26USuZhXyJGWaQ1MD14Nqokv6f+eB8\n\
    +eTEVP57kHKZNXOerYL7t4DHJgMNJ+kjjpdMIyLadw2XP7SnIEG0P1m09/774JkcscIiKu\n\
    78Hg/SQXI9ZaYuBg==\n\
    -----END OPENSSH PRIVATE KEY-----\n\
    ";

    const PUBLIC: &str = "\
    ssh-ed25519 \
    AAAAC3NzaC1lZDI1NTE5AAAAIMI/rsXI07qHf+e9Uz0mfeURvT6rdb6g2mmUNKnTTvu1 \
    testing\n\
    ";

    #[test]
    fn test() {
        use super::*;

        let askpass = || Box::new(|| Ok("testing".to_owned()));

        let sec_none = parse_secret_key(SECRET_NONE, askpass()).unwrap();
        let sec_bcrypt = parse_secret_key(SECRET_BCRYPT, askpass()).unwrap();
        assert_eq!(sec_none, sec_bcrypt);

        let seckey = sec_none.clone();

        let pub_none = format!("{:b}", sec_none.pubkey);
        let pub_bcrypt = format!("{:b}", sec_bcrypt.pubkey);
        assert_eq!(pub_none, PUBLIC);
        assert_eq!(pub_bcrypt, PUBLIC);

        let pubkey = parse_public_keys(PUBLIC.as_bytes()).unwrap();
        assert!(pubkey.len() == 1);
        assert_eq!(pubkey[0], seckey.pubkey);
    }
}
