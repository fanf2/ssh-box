use anyhow::{anyhow, Context, Result};

use crate::askpass::AskPass;
use crate::util::*;

pub use sodiumoxide::crypto::sign::{PublicKey, SecretKey};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Named<Key> {
    pub key: Key,
    pub name: String,
}

impl From<Named<SecretKey>> for Named<PublicKey> {
    fn from(secret: Named<SecretKey>) -> Named<PublicKey> {
        Named { key: secret.key.public_key(), name: secret.name }
    }
}

impl Named<SecretKey> {
    pub fn public_key(self) -> Named<PublicKey> {
        self.into()
    }
}

impl std::fmt::Display for Named<PublicKey> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut binary = SshBuffer::new();
        binary.add_pubkey(&self.key);
        writeln!(f, "ssh-ed25519 {} {}", base64::encode(&binary), self.name)
    }
}

pub fn read_public_keys(key_file: &str) -> Result<Vec<Named<PublicKey>>> {
    let context = || format!("failed to read {}", key_file);
    let ascii = std::fs::read(key_file).with_context(context)?;
    parse_public_keys(&ascii).with_context(context)
}

pub fn read_secret_key(
    key_file: &str,
    askpass: AskPass,
) -> Result<Named<SecretKey>> {
    let context = || format!("failed to read {}", key_file);
    let ascii = std::fs::read(key_file).with_context(context)?;
    parse_secret_key(&ascii, askpass).with_context(context)
}

pub fn parse_public_keys(ascii: &[u8]) -> Result<Vec<Named<PublicKey>>> {
    use crate::nom::*;

    fn ssh_ed25519(armor: &[u8], comment: &str) -> Result<Named<PublicKey>> {
        let binary = base64::decode(armor)?;
        let (_, rawkey) = delimited(
            length_value(be_u32, tag(b"ssh-ed25519")),
            length_data(be_u32),
            eof,
        )(&binary[..])
        .map_err(|_: NomErr| anyhow!("invalid ed25519 public key"))?;
        let pubkey = PublicKey::from_slice(rawkey)
            .ok_or_else(|| anyhow!("invalid ed25519 public key"))?;
        Ok(Named { key: pubkey, name: comment.to_owned() })
    }

    fn ssh_pubkey(
        algo: &[u8],
        armor: &[u8],
        comment: &[u8],
    ) -> Result<Named<PublicKey>> {
        let algo = std::str::from_utf8(algo)?;
        let comment = std::str::from_utf8(comment)?;
        if algo == "ssh-ed25519" {
            ssh_ed25519(armor, comment)
        } else if comment.is_empty() {
            Err(anyhow!("unknown algorithm {}", algo))
        } else {
            Err(anyhow!("unknown algorithm {} for {}", algo, comment))
        }
    }

    let key = map(
        tuple((
            is_a(LDH_CHARS),
            space1,
            is_a(BASE64_CHARS),
            space0,
            not_line_ending,
        )),
        |(algo, _s1, armor, _s2, comment)| {
            Ok(Some(ssh_pubkey(algo, armor, comment)?))
        },
    );
    let empty = map(space0, |_| Ok(None));
    let comment =
        map(tuple((space0, tag(b"#"), not_line_ending)), |_| Ok(None));
    let invalid = map(not_line_ending, |_| Err(anyhow!("invalid public key")));
    let line = terminated(alt((key, empty, comment, invalid)), line_ending);

    let (_, mut lines) = all_consuming(many0(line))(ascii)
        .map_err(|_: NomErr| anyhow!("could not parse public key file"))?;

    let mut keys = Vec::new();
    for (lino, line) in lines.drain(..).enumerate() {
        match line {
            Ok(Some(key)) => {
                keys.push(key);
            }
            Ok(None) => (),
            Err(err) => {
                Err(err).with_context(|| format!("at line {}", lino))?;
            }
        }
    }

    Ok(keys)
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

// See https://dnaeon.github.io/openssh-private-key-binary-format/
//
pub fn parse_secret_key(
    ascii: &[u8],
    askpass: AskPass,
) -> Result<Named<SecretKey>> {
    use crate::nom::*;

    const PREFIX: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
    const SUFFIX: &[u8] = b"-----END OPENSSH PRIVATE KEY-----\n";
    let binary = base64::unarmor(ascii, PREFIX, SUFFIX)?;

    let ssh_ed25519 = || preceded(len_tag(b"ssh-ed25519"), ssh_string);
    let ssh_magic = || tag(b"openssh-key-v1\0");

    let parse_bcrypt_params = map(
        delimited(
            tuple((ssh_magic(), len_tag(b"aes256-ctr"), len_tag(b"bcrypt"))),
            map_parser(ssh_string, pair(ssh_string, be_u32)),
            be_u32_is(1),
        ),
        Some,
    );

    let parse_none_params = value(
        None,
        tuple((
            ssh_magic(),
            len_tag(b"none"),
            len_tag(b"none"),
            be_u32_is(0),
            be_u32_is(1),
        )),
    );

    let parse_pubkey = map_parser(ssh_string, ssh_ed25519());

    let (_, (cipher_params, pubkey1, encrypted, _eof)) = tuple((
        alt((parse_bcrypt_params, parse_none_params)),
        parse_pubkey,
        ssh_string,
        eof,
    ))(&binary[..])
    .map_err(|_: NomErr| anyhow!("could not parse private key"))?;

    let mut secrets = encrypted.to_owned();

    if let Some((salt, rounds)) = cipher_params {
        if encrypted.len() % 16 != 0 {
            return Err(anyhow!("bad alignment in private key"));
        } else {
            bcrypt_aes_decrypt(&mut secrets, salt, rounds, askpass)?;
        }
    } else if encrypted.len() % 8 != 0 {
        return Err(anyhow!("bad alignment in private key"));
    }

    let (pad, (check1, check2, pubkey2, rawkey, comment)) =
        tuple((be_u32, be_u32, ssh_ed25519(), ssh_string, ssh_string))(
            &secrets[..],
        )
        .map_err(|_: NomErr| anyhow!("could not parse encrypted key"))?;

    if check1 != check2 {
        return Err(anyhow!("could not decrypt private key"));
    }
    for (i, &e) in pad.iter().enumerate() {
        if e != 1 + i as u8 {
            return Err(anyhow!("erroneous padding in private key"));
        }
    }

    let seckey = SecretKey::from_slice(rawkey)
        .ok_or_else(|| anyhow!("invalid ed25519 secret key"))?;

    if pubkey1 != pubkey2 || pubkey1 != seckey.public_key().as_ref() {
        return Err(anyhow!("inconsistent private key"));
    }

    let comment = String::from_utf8(comment.to_owned())?;
    Ok(Named { key: seckey, name: comment })
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

        let pub_none = format!("{}", sec_none.public_key());
        let pub_bcrypt = format!("{}", sec_bcrypt.public_key());
        assert_eq!(pub_none, PUBLIC);
        assert_eq!(pub_bcrypt, PUBLIC);

        let pubkey = parse_public_keys(PUBLIC.as_bytes()).unwrap();
        assert!(pubkey.len() == 1);
        assert_eq!(pubkey[0], seckey.public_key());
    }
}
