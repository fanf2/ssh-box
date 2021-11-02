use crate::prelude::*;

#[derive(Clone, Debug, Eq)]
pub struct PublicKey {
    pub algo: String,
    pub blob: Vec<u8>,
    pub name: String,
}

impl From<(&[u8], &str)> for PublicKey {
    fn from((blob, algo): (&[u8], &str)) -> PublicKey {
        let algo = algo.to_owned();
        let blob = blob.to_owned();
        let name = String::new();
        PublicKey { algo, blob, name }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.blob == other.blob
    }
}

impl std::fmt::Binary for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let blob = base64::encode(&self.blob);
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

impl PublicKey {
    pub fn encrypt(&self, secrets: &[u8]) -> Result<Vec<u8>> {
        match self.algo.as_str() {
            "ssh-ed25519" => encrypt_ed25519(&self.blob, secrets),
            _ => Err(anyhow!("unsupported algoritm")),
        }
        .with_context(|| format!("{}", self))
    }
}

fn encrypt_ed25519(sshkey: &[u8], secrets: &[u8]) -> Result<Vec<u8>> {
    use crate::nom::*;

    let (_, rawkey) = all_consuming(preceded(
        ssh_string_tag("ssh-ed25519"),
        ssh_string,
    ))(sshkey)
    .map_err(|_: NomErr| anyhow!("could not unpack key"))?;

    let ed25519 = ed25519::PublicKey::from_slice(rawkey)
        .ok_or_else(|| anyhow!("incorrect key length"))?;

    let curve25519 = ed25519::to_curve25519_pk(&ed25519)
        .map_err(|_| anyhow!("could not convert key"))?;

    Ok(sealedbox::seal(secrets, &curve25519))
}
