use anyhow::{anyhow, Context, Result};
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign as ed25519;

use crate::base64;

#[derive(Clone, Debug, Eq)]
pub struct Public {
    pub key: PublicParts,
    pub repr: Vec<u8>,
    pub comment: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicParts {
    Ed25519(ed25519::PublicKey),
    Invalid(&'static str),
    Unknown(String),
}

impl std::ops::Deref for Public {
    type Target = PublicParts;
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl PartialEq for Public {
    fn eq(&self, other: &Self) -> bool {
        self.repr == other.repr
    }
}

impl std::fmt::Display for Public {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = base64::encode(&self.repr);
        if self.comment.is_empty() {
            writeln!(f, "{} {}", self.algo(), repr)
        } else {
            writeln!(f, "{} {} {}", self.algo(), repr, &self.comment)
        }
    }
}

impl PublicParts {
    pub fn known(&self) -> bool {
        matches!(self, PublicParts::Ed25519(_))
    }

    pub fn algo(&self) -> &str {
        match &self {
            PublicParts::Ed25519(_) => "ssh-ed25519",
            PublicParts::Invalid(algo) => algo,
            PublicParts::Unknown(algo) => algo,
        }
    }

    pub fn encrypt(&self, cleartext: &[u8]) -> Result<Vec<u8>> {
        match &self {
            PublicParts::Ed25519(sigkey) => {
                let enckey = ed25519::to_curve25519_pk(sigkey)
                    .map_err(|_| anyhow!("could not convert key"))?;
                Ok(sealedbox::seal(cleartext, &enckey))
            }
            _ => Err(anyhow!("unsupported algorithm {}", self.algo())),
        }
    }
}

impl Public {
    pub fn encrypt(&self, cleartext: &[u8]) -> Result<Vec<u8>> {
        self.key
            .encrypt(cleartext)
            .with_context(|| format!("using {}", self.comment))
    }

    pub fn ed25519_from(repr: &[u8], raw: &[u8]) -> Public {
        let key = if let Some(parts) = ed25519::PublicKey::from_slice(raw) {
            PublicParts::Ed25519(parts)
        } else {
            PublicParts::Invalid("ssh-ed25519")
        };
        let repr = repr.to_owned();
        let comment = String::new();
        Public { key, repr, comment }
    }

    pub fn unknown_from(repr: &[u8], algo: &str) -> Public {
        let key = PublicParts::Unknown(algo.to_owned());
        let repr = repr.to_owned();
        let comment = String::new();
        Public { key, repr, comment }
    }

    pub fn set_comment(self, comment: &str) -> Public {
        Public { comment: comment.to_owned(), ..self }
    }
}

pub fn read_public_keys(key_file: &str) -> Result<Vec<Public>> {
    let context = || format!("failed to read {}", key_file);
    let ascii = std::fs::read(key_file).with_context(context)?;
    parse_public_keys(&ascii).with_context(context)
}

pub fn parse_public_keys(ascii: &[u8]) -> Result<Vec<Public>> {
    use crate::nom::*;

    let pubkey_blob = map_opt(is_base64, |repr| {
        let (_, pubkey) = all_consuming(ssh_pubkey)(&repr).ok()?;
        pubkey.known().then(|| pubkey)
    });

    let key = map_opt(
        tuple((is_ldh, space1, pubkey_blob, space0, is_utf8(not_line_ending))),
        |(algo, _s1, pubkey, _s2, comment)| {
            (pubkey.algo() == algo)
                .then(|| Ok(Some(pubkey.set_comment(comment))))
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
