use anyhow::{anyhow, Context, Result};
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign as ed25519;

use crate::base64;

pub trait PublicKey {
    fn repr(&self) -> &PublicRepr;

    fn algo(&self) -> &str {
        &self.repr().algo
    }

    fn blob(&self) -> &[u8] {
        &self.repr().blob
    }

    fn name(&self) -> &str {
        &self.repr().name
    }

    fn has_name(&self) -> bool {
        !self.name().is_empty()
    }

    fn set_name(self, name: &str) -> self;

    fn known(&self) -> bool {
        false
    }

    fn encrypt(&self, _: &[u8]) -> Result<Vec<u8>>;
}

impl<S, O> PartialEq for S
where
    S: PublicKey,
    O: PublicKey,
{
    fn eq(&self, other: &O) -> bool {
        self.blob() == other.blob()
    }
}

impl<T> std::fmt::Display for T
where
    T: PublicKey,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let blob = base64::encode(self.blob());
        if self.has_name() {
            writeln!(f, "{} {} {}", self.algo(), blob, self.name())
        } else {
            writeln!(f, "{} {}", self.algo(), blob)
        }
    }
}

impl<T> std::fmt::Binary for T
where
    T: PublicKey,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.algo());
        if self.0.has_name() {
            write!(f, " for key {}", self.name())
        }
    }
}

#[derive(Clone, Debug, Eq)]
pub struct PublicRepr {
    pub algo: String,
    pub blob: Vec<u8>,
    pub name: String,
}

impl PublicKey for PublicRepr {
    fn repr(&self) -> PublicRepr {
        self
    }

    fn set_name(self, name: &str) -> self {
        let name = name.to_owned();
        PublicRepr { name, ..self }
    }
}

impl PublicRepr {
    pub fn from(algo: &str, blob: &[u8]) -> PublicRepr {
        let algo = algo.to_owned();
        let blob = blob.to_owned();
        let name = String::new();
        PublicRepr { algo, blob, name }
    }
}

#[derive(Clone, Debug, Eq)]
pub struct PublicBad {
    pub repr: PublicRepr,
    pub why: &'static str,
}

impl PublicKey for PublicBad {
    fn repr(&self) -> &PublicRepr {
        &self.repr
    }

    fn set_name(self, name: &str) -> self {
        PublicBad { repr: self.repr.set_name(name), ..self }
    }

    fn encrypt(&self, cleartext: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!("{} {:b}", self.why, &self))
    }
}

impl PublicBad {
    pub fn from(algo: &str, blob: &[u8], why: &'static str) -> impl PublicKey {
        let repr = PublicRepr::from(algo, blob);
        PublicBad { repr, why }
    }
}

#[derive(Clone, Debug, Eq)]
pub struct PublicEd25519 {
    pub repr: PublicRepr,
    pub key: ed25519::PublicKey,
}

impl PublicKey for PublicEd25519 {
    fn repr(&self) -> &PublicRepr {
        &self.repr
    }

    fn set_name(self, name: &str) -> self {
        let repr = self.repr.set_name(name);
        PublicEd25519 { repr, ..self }
    }

    fn known(&self) -> bool {
        true
    }

    fn encrypt(&self, cleartext: &[u8]) -> Result<Vec<u8>> {
        let enckey = ed25519::to_curve25519_pk(self.key)
            .map_err(|_| anyhow!("could not convert key"))?;
        Ok(sealedbox::seal(cleartext, &enckey))
    }
}

impl PublicEd25519 {
    fn from(algo: &str, blob: &[u8], raw: &[u8]) -> impl PublicKey {
        if let Some(key) = ed25519::PublicKey::from_slice(raw) {
            let repr = PublicRepr::from(algo, blob);
            PublicEd25519 { repr, key }
        } else {
            PublicBad::from(algo, blob, "could not parse")
        }
    }
}
