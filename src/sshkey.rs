use anyhow::{anyhow, Context, Result};

use crate::askpass::AskPass;
use crate::base64;
use crate::util::*;

pub use sodiumoxide::crypto::sign::{PublicKey, SecretKey};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Named<Key> {
    pub key: Key,
    pub name: String,
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
