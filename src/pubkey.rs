use crate::prelude::*;

#[derive(Clone, Debug, Eq)]
pub struct PublicKey {
    pub algo: String,
    pub blob: Vec<u8>,
    pub name: String,
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.blob == other.blob
    }
}

// for nom::ssh_pubkey()
impl From<(&[u8], &str)> for PublicKey {
    fn from((blob, algo): (&[u8], &str)) -> PublicKey {
        let algo = algo.to_owned();
        let blob = blob.to_owned();
        let name = String::new();
        PublicKey { algo, blob, name }
    }
}

// for sshbox::parse_message()
impl From<(PublicKey, &str)> for PublicKey {
    fn from((mut pubkey, name): (PublicKey, &str)) -> PublicKey {
        pubkey.name = name.to_owned();
        pubkey
    }
}

// for parse_public_keys()
impl From<(&str, Vec<u8>, &str)> for PublicKey {
    fn from((algo, blob, name): (&str, Vec<u8>, &str)) -> PublicKey {
        let algo = algo.to_owned();
        let name = name.to_owned();
        PublicKey { algo, blob, name }
    }
}

impl std::fmt::Binary for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let blob = base64_encode(&self.blob);
        if self.name.is_empty() {
            writeln!(f, "{} {}", self.algo, blob)
        } else {
            writeln!(f, "{} {} {}", self.algo, blob, self.name)
        }
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.name.is_empty() {
            write!(f, "{}", self.algo)
        } else {
            write!(f, "{} for {}", self.algo, self.name)
        }
    }
}

pub fn read_public_keys(key_file: &str) -> Result<Vec<PublicKey>> {
    let mut path = Path::new(key_file);
    let mut find;
    // if it is just a leafname, we might need to search for it
    if path.components().nth(1).is_none() && !path.exists() {
        find = path.canonicalize()?;
        while find.pop(/* path */) {
            find.push(".git");
            if find.exists() || !find.pop(/* .git */) || !find.pop(/* .. */) {
                break;
            }
            find.push(path);
            if find.exists() {
                path = find.as_path();
                break;
            }
        }
    }
    let context = || format!("reading {}", path.display());
    let ascii = std::fs::read(path).with_context(context)?;
    parse_public_keys(&ascii).with_context(context)
}

pub fn parse_public_keys(ascii: &[u8]) -> Result<Vec<PublicKey>> {
    use crate::nom::*;
    let keytext = tuple((
        preceded(space0, is_ldh),
        preceded(space1, is_base64),
        preceded(space0, is_utf8(not_line_ending)),
    ));
    let pubkey = map(keytext, PublicKey::from);
    let (_, keys) = commented_lines(pubkey)(ascii)
        .or_else(|_| bail!("could not parse list of public keys"))?;
    Ok(keys)
}

impl PublicKey {
    pub fn encrypt(&self, secrets: &[u8]) -> Result<Vec<u8>> {
        match self.algo.as_str() {
            "ssh-ed25519" => encrypt_ed25519(&self.blob, secrets),
            "ssh-rsa" => encrypt_rsa_oaep(&self.blob, secrets),
            _ => bail!("unsupported algoritm"),
        }
        .with_context(|| format!("{}", self))
    }
}

fn encrypt_ed25519(sshkey: &[u8], secrets: &[u8]) -> Result<Vec<u8>> {
    use crate::nom::*;
    let (_, rawkey) =
        delimited(ssh_string_tag("ssh-ed25519"), ssh_string, eof)(sshkey)
            .map_err(|_| anyhow!("could not unpack key"))?;
    let ed25519 = ed25519::PublicKey::from_slice(rawkey)
        .ok_or_else(|| anyhow!("incorrect key length"))?;
    let curve25519 = ed25519::to_curve25519_pk(&ed25519)
        .map_err(|_| anyhow!("could not convert key"))?;
    Ok(sealedbox::seal(secrets, &curve25519))
}

fn encrypt_rsa_oaep(sshkey: &[u8], secrets: &[u8]) -> Result<Vec<u8>> {
    use crate::nom::*;
    let (_, (raw_e, raw_n)) = delimited(
        ssh_string_tag("ssh-rsa"),
        pair(ssh_string, ssh_string),
        eof,
    )(sshkey)
    .or_else(|_| bail!("could not unpack key"))?;
    let n = BigUint::from_bytes_be(raw_n);
    let e = BigUint::from_bytes_be(raw_e);
    let pubkey = RsaPublicKey::new(n, e)?;
    let mut rng = rand::rngs::OsRng;
    Ok(pubkey.encrypt(&mut rng, rsa_oaep_padding(), secrets)?)
}

pub fn rsa_oaep_padding() -> PaddingScheme {
    PaddingScheme::new_oaep_with_label::<sha2::Sha256, _>("ssh-box-v1-rsa-oaep")
}
