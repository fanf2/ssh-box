use crate::prelude::*;

#[derive(Clone, Debug, Eq)]
pub struct SecretKey {
    pubkey: PublicKey,
    parts: Record,
    cooked: CookedKey,
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CookedKey {
    Ed25519(curve25519::PublicKey, curve25519::SecretKey),
    RsaOaep(Box<RsaPrivateKey>),
}

impl SecretKey {
    pub fn pubkey(&self) -> PublicKey {
        // XXX rebuild it from secret parts
        self.pubkey.clone()
    }

    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let bail = || bail!("could not decrypt with {}", self.pubkey);
        match &self.cooked {
            CookedKey::Ed25519(pubkey, seckey) => {
                sealedbox::open(message, pubkey, seckey).or_else(|_| bail())
            }
            CookedKey::RsaOaep(key) => {
                key.decrypt(rsa_oaep_padding(), message).or_else(|_| bail())
            }
        }
    }
}

pub fn rsa_oaep_padding() -> PaddingScheme {
    PaddingScheme::new_oaep_with_label::<sha2::Sha256, _>("ssh-box")
}

pub fn read_secret_key(key_file: &str, askpass: AskPass) -> Result<SecretKey> {
    let context = || format!("reading {}", key_file);
    let ascii = std::fs::read(key_file).with_context(context)?;
    parse_secret_key(&ascii, askpass).with_context(context)
}

// See https://dnaeon.github.io/openssh-private-key-binary-format/
// and https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent

pub fn parse_secret_key(ascii: &[u8], askpass: AskPass) -> Result<SecretKey> {
    use crate::nom::*;

    let binary = pem_decap(ascii, "OPENSSH PRIVATE KEY")?;

    let bcrypt_params = preceded(
        pair(ssh_string_tag("aes256-ctr"), ssh_string_tag("bcrypt")),
        map_parser(ssh_string, pair(ssh_string, be_u32)),
    );
    let none_params =
        tuple((ssh_string_tag("none"), ssh_string_tag("none"), be_u32_is(0)));
    let cipher_params =
        alt((map(bcrypt_params, Some), value(None, none_params)));

    let (_, (cipher_params, pubblob, enciphered)) = tuple((
        preceded(tag(b"openssh-key-v1\0"), cipher_params),
        preceded(be_u32_is(1), ssh_string),
        terminated(ssh_string, eof),
    ))(&binary[..])
    .or_else(|_| bail!("could not parse private key"))?;

    let (_, mut pubparts) = terminated(ssh_record, eof)(pubblob)
        .or_else(|_| bail!("could not parse public part of private key"))?;

    let mut secrets = enciphered.to_owned();
    let blocksize = if cipher_params.is_some() { 16 } else { 8 };
    ensure!(secrets.len() % blocksize == 0, "bad alignment in private key");
    if let Some((salt, rounds)) = cipher_params {
        bcrypt_aes_decrypt(&mut secrets, salt, rounds, askpass)?;
    }

    let parse_seckey = many_till(ssh_string_owned, seckey_padding);
    let (_, (check1, check2, (secparts, _))) =
        tuple((be_u32, be_u32, parse_seckey))(&secrets[..])
            .or_else(|_| bail!("could not parse encrypted key"))?;

    ensure!(check1 == check2, "could not decrypt private key");

    pubparts.push(secparts.last().unwrap().clone());
    let pubkey = PublicKey::new(pubparts);
    match &*secparts[0] {
        b"ssh-ed25519" => new_ed25519(pubkey, secparts),
        b"ssh-rsa" => new_rsa_oaep(pubkey, secparts),
        algo => bail!("unsupported algoritm {}", from_utf8(algo)?),
    }
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

fn new_ed25519(pubkey: PublicKey, parts: Record) -> Result<SecretKey> {
    // parts: algo, pubkey, seckey, comment
    ensure!(parts.len() == 4, "incorrect ed25519 secret key format");
    ensure!(
        pubkey.key_parts() == &parts[0..2],
        "mismatched ed25519 secret key"
    );

    let ed_sec = ed25519::SecretKey::from_slice(&parts[2])
        .ok_or_else(|| anyhow!("invalid ed25519 secret key"))?;
    let ed_pub = ed_sec.public_key();
    ensure!(parts[1] == ed_pub.as_ref(), "inconsistent ed25519 secret key");

    let bail = |_| anyhow!("cannot decrypt with this private key");
    let curve_pub = ed25519::to_curve25519_pk(&ed_pub).map_err(bail)?;
    let curve_sec = ed25519::to_curve25519_sk(&ed_sec).map_err(bail)?;
    let cooked = CookedKey::Ed25519(curve_pub, curve_sec);

    Ok(SecretKey { pubkey, parts, cooked })
}

#[allow(clippy::many_single_char_names)]
fn new_rsa_oaep(pubkey: PublicKey, parts: Record) -> Result<SecretKey> {
    let pk_kp = pubkey.key_parts();
    ensure!(
        pk_kp.len() == 3 && parts.len() == 8,
        "incorrect RSA secret key format"
    );
    // note reverse order in public (e,n) / secret (n,e) keys
    ensure!(
        pk_kp[0] == parts[0] && pk_kp[1] == parts[2] && pk_kp[2] == parts[1],
        "mismatched ed25519 secret key"
    );

    // algo = parts[0]
    let n = BigUint::from_bytes_be(&parts[1]);
    let e = BigUint::from_bytes_be(&parts[2]);
    let d = BigUint::from_bytes_be(&parts[3]);
    // iqmp = parts[4]
    let p = BigUint::from_bytes_be(&parts[5]);
    let q = BigUint::from_bytes_be(&parts[6]);
    // comment = parts[7]

    let key = RsaPrivateKey::from_components(n, e, d, vec![p, q]);
    key.validate()?;
    // box it up because it is big
    let cooked = CookedKey::RsaOaep(Box::new(key));

    Ok(SecretKey { pubkey, parts, cooked })
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
