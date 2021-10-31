use sodiumoxide::crypto::sign as ed25519;

pub struct Public {
    pub key: PublicParts,
    pub repr: Vec<u8>,
    pub comment: Vec<u8>,
}

pub enum PublicParts {
    Ed25519(ed25519::PublicKey),
    Invalid(&'static [u8]),
    Unknown(Vec<u8>),
}

impl Public {
    pub fn ed25519_from(repr: &[u8], raw: &[u8]) -> Public {
        let key = if let Some(parts) = ed25519::PublicKey::from_slice(raw) {
            PublicParts::Ed25519(parts)
        } else {
            PublicParts::Invalid(b"ssh-ed25519")
        };
        let repr = repr.to_owned();
        let comment = Vec::new();
        Public { key, repr, comment }
    }

    pub fn unknown_from(repr: &[u8], algo: &[u8]) -> Public {
        let key = PublicParts::Unknown(algo.to_owned());
        let repr = repr.to_owned();
        let comment = Vec::new();
        Public { key, repr, comment }
    }

    pub fn set_comment(self, comment: &[u8]) -> Public {
        Public { comment: comment.to_owned(), ..self }
    }
}
