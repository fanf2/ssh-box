use crate::prelude::*;

pub trait SecretKey {
    fn pubkey(&self) -> &PublicKey;
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>>;
}

pub fn read_secret_key(
    key_file: &str,
    askpass: AskPass,
) -> Result<Box<dyn SecretKey>> {
    let context = || format!("reading {}", key_file);
    let ascii = std::fs::read(key_file).with_context(context)?;
    parse_secret_key(&ascii, askpass).with_context(context)
}

// See https://dnaeon.github.io/openssh-private-key-binary-format/

pub fn parse_secret_key(
    ascii: &[u8],
    askpass: AskPass,
) -> Result<Box<dyn SecretKey>> {
    use crate::nom::*;

    let binary = ascii_unarmor(
        ascii,
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "-----END OPENSSH PRIVATE KEY-----\n",
    )?;

    let bcrypt_params = preceded(
        pair(ssh_string_tag("aes256-ctr"), ssh_string_tag("bcrypt")),
        map_parser(ssh_string, pair(ssh_string, be_u32)),
    );

    let none_params =
        tuple((ssh_string_tag("none"), ssh_string_tag("none"), be_u32_is(0)));

    let cipher_params =
        alt((map(bcrypt_params, Some), value(None, none_params)));

    let (_, (cipher_params, pubkey, enciphered)) = tuple((
        preceded(tag(b"openssh-key-v1\0"), cipher_params),
        preceded(be_u32_is(1), map_parser(ssh_string, ssh_pubkey)),
        terminated(ssh_string, eof),
    ))(&binary[..])
    .map_err(|_: NomErr| anyhow!("could not parse private key"))?;

    let mut secrets = enciphered.to_owned();

    if let Some((salt, rounds)) = cipher_params {
        if enciphered.len() % 16 != 0 {
            return Err(anyhow!("bad alignment in private key"));
        } else {
            bcrypt_aes_decrypt(&mut secrets, salt, rounds, askpass)?;
        }
    } else if enciphered.len() % 8 != 0 {
        return Err(anyhow!("bad alignment in private key"));
    }

    let (algo, builder, part_count) = match pubkey.algo.as_str() {
        "ssh-ed25519" => ("ssh-ed25519", SecretEd25519::new, ED25519_PARTS),
        _ => return Err(anyhow!("unsupported algoritm")),
    };

    let split_parts =
        preceded(ssh_string_tag(algo), count(ssh_string, part_count));
    let (pad, (check1, check2, secret_parts)) =
        tuple((be_u32, be_u32, split_parts))(&secrets[..])
            .map_err(|_: NomErr| anyhow!("could not parse encrypted key"))?;

    if check1 != check2 {
        return Err(anyhow!("could not decrypt private key"));
    }
    for (i, &e) in pad.iter().enumerate() {
        if e != 1 + i as u8 {
            return Err(anyhow!("erroneous padding in private key"));
        }
    }

    builder(pubkey, secret_parts)
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

struct SecretEd25519 {
    pubkey: PublicKey,
    curve_pub: curve25519::PublicKey,
    curve_sec: curve25519::SecretKey,
}

impl SecretKey for SecretEd25519 {
    fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        sealedbox::open(message, &self.curve_pub, &self.curve_sec)
            .map_err(|_| anyhow!("could not decrypt with {}", self.pubkey))
    }
}

const ED25519_PARTS: usize = 3;

impl SecretEd25519 {
    fn new(
        mut pubkey: PublicKey,
        parts: Vec<&[u8]>,
    ) -> Result<Box<dyn SecretKey>> {
        use crate::nom::*;

        assert!(parts.len() == ED25519_PARTS);

        let raw_pub = parts[0];
        let raw_sec = parts[1];

        pubkey.name = String::from_utf8(parts[3].to_owned())?;

        let ed_sec = ed25519::SecretKey::from_slice(raw_sec)
            .ok_or_else(|| anyhow!("invalid ed25519 secret key"))?;
        let ed_pub = ed_sec.public_key();

        if raw_pub != ed_pub.as_ref() {
            return Err(anyhow!("inconsistent private key"));
        }

        tuple((
            ssh_string_tag("ssh-ed25519"),
            be_u32_is(raw_pub.len() as u32),
            tag(raw_pub),
            eof,
        ))(&pubkey.blob)
        .map_err(|_: NomErr| anyhow!("inconsistent private key"))?;

        let cannot = |_| anyhow!("cannot decrypt with this private key");
        let curve_pub = ed25519::to_curve25519_pk(&ed_pub).map_err(cannot)?;
        let curve_sec = ed25519::to_curve25519_sk(&ed_sec).map_err(cannot)?;

        Ok(Box::new(SecretEd25519 { pubkey, curve_pub, curve_sec }))
    }
}
