use crate::prelude::*;

#[derive(Clone, Debug, Eq)]
pub struct PublicKey(Record);

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key_parts().hash(state);
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_parts() == other.key_parts()
    }
}

impl std::fmt::Binary for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.comment().is_empty() {
            writeln!(f, "{} {}", self.algo(), self.blob64())
        } else {
            writeln!(f, "{} {} {}", self.algo(), self.blob64(), self.comment())
        }
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.comment().is_empty() {
            write!(f, "{}", self.algo())
        } else {
            write!(f, "{} for {}", self.algo(), self.comment())
        }
    }
}

pub fn read_public_keys(key_file: &str) -> Result<Vec<PublicKey>> {
    let mut path = Path::new(key_file);
    let mut find;
    // if it is just a leafname, we might need to search for it
    if path.components().nth(1).is_none() && !path.exists() {
        find = std::fs::canonicalize(".")?;
        println!("searching from  {}", find.display());
        loop {
            find.push(".git");
            if find.exists() || !find.pop(/* .git */) || !find.pop(/* .. */) {
                break;
            }
            find.push(path);
            if find.exists() {
                path = find.as_path();
                break;
            }
            find.pop();
        }
    }
    let context = || format!("reading {}", path.display());
    let ascii = std::fs::read(path).with_context(context)?;
    parse_public_keys(&ascii).with_context(context)
}

pub fn parse_public_keys(ascii: &[u8]) -> Result<Vec<PublicKey>> {
    use crate::nom::*;
    let keytext = tuple((
        preceded(space0, ssh_name),
        preceded(space1, is_a(BASE64_CHARS)),
        preceded(space0, is_utf8(not_line_ending)),
    ));
    let pubkey = map_res(keytext, parse_public_key);
    let (_, keys) = commented_lines(pubkey)(ascii)
        .or_else(|_| bail!("could not parse list of public keys"))?;
    Ok(keys)
}

fn parse_public_key(
    (algo, blob64, comment): (&[u8], &[u8], &str),
) -> Result<PublicKey> {
    use crate::nom::*;
    let algo1 = from_utf8(algo)?;
    let blob = base64_decode(blob64)?;
    let (_, mut parts) = terminated(ssh_record, eof)(&blob).or_else(|_| {
        bail!("malformed base64 blob for {} {}", algo1, comment)
    })?;
    let algo2 = from_utf8(&parts[0])?;
    ensure!(algo1 == algo2, "mismatched key algorithms: {} / {}", algo1, algo2);
    parts.push(comment.as_bytes().to_owned());
    Ok(PublicKey(parts))
}

impl PublicKey {
    pub fn new(parts: Record) -> PublicKey {
        assert!(2 <= parts.len() && parts.len() <= 127);
        PublicKey(parts)
    }

    pub fn len(&self) -> u8 {
        self.0.len() as u8
    }

    pub fn algo(&self) -> &str {
        from_utf8(self.0.first().unwrap()).unwrap()
    }

    pub fn comment(&self) -> &str {
        from_utf8(self.0.last().unwrap()).unwrap()
    }

    // everything except the comment
    pub fn key_parts(&self) -> &[Vec<u8>] {
        self.0.split_last().unwrap().1
    }

    pub fn blob64(&self) -> String {
        let mut buf = Buf::new();
        buf.add_strings(self.key_parts());
        base64_encode(buf.as_ref())
    }

    pub fn encrypt(&self, buf: &mut Buf, secrets: &[u8]) -> Result<()> {
        let ciphertext = match self.algo() {
            "ssh-ed25519" => self.encrypt_ed25519(secrets)?,
            "ssh-rsa" => self.encrypt_rsa_oaep(secrets)?,
            _ => bail!("unsupported algoritm {}", &self),
        };
        buf.add_byte(self.len() + 1);
        buf.add_strings(&self.0);
        buf.add_string(&ciphertext);
        Ok(())
    }

    fn encrypt_ed25519(&self, secrets: &[u8]) -> Result<Vec<u8>> {
        // RFC 8709 section 4
        ensure!(self.len() == 3, "malformed key {}", &self);
        let ed25519 = ed25519::PublicKey::from_slice(&self.0[1])
            .ok_or_else(|| anyhow!("incorrect key length in {}", &self))?;
        let curve25519 = ed25519::to_curve25519_pk(&ed25519)
            .map_err(|_| anyhow!("could not make curve25519 from {}", &self))?;
        Ok(sealedbox::seal(secrets, &curve25519))
    }

    fn encrypt_rsa_oaep(&self, secrets: &[u8]) -> Result<Vec<u8>> {
        // RFC 4253 section 6.6 - note order is e,n in public key
        ensure!(self.len() == 4, "malformed key {}", &self);
        let e = BigUint::from_bytes_be(&self.0[1]);
        let n = BigUint::from_bytes_be(&self.0[2]);
        let pubkey = RsaPublicKey::new(n, e)?;
        let mut rng = rand::rngs::OsRng;
        Ok(pubkey.encrypt(&mut rng, rsa_oaep_padding(), secrets)?)
    }
}
