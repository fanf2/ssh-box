use sodiumoxide::crypto::sign::PublicKey;

pub struct SshBuffer(Vec<u8>);

impl std::ops::Deref for SshBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SshBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::convert::AsRef<[u8]> for SshBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl SshBuffer {
    pub fn new() -> Self {
        SshBuffer(Vec::new())
    }

    pub fn add_u32(&mut self, n: u32) {
        self.extend_from_slice(&n.to_be_bytes());
    }

    pub fn add_string(&mut self, string: &[u8]) {
        self.add_u32(string.len() as u32);
        self.extend_from_slice(string);
    }

    pub fn add_pubkey(&mut self, key: &PublicKey) {
        self.add_string(b"ssh-ed25519");
        self.add_string(key.as_ref());
    }
}
