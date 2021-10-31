use anyhow::{anyhow, Result};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign::ed25519;

use crate::sshkey::*;
use crate::util::*;

const PREFIX: &[u8] = b"-----BEGIN SSH-BOX ENCRYPTED FILE-----\n";
const SUFFIX: &[u8] = b"-----END SSH-BOX ENCRYPTED FILE-----\n";

const MAGIC: &[u8] = b"ssh-box-v1\0";

type Recipient<'a> = (&'a [u8], &'a [u8], &'a [u8]);

fn parse_message(binary: &[u8]) -> Result<(Vec<Recipient>, &[u8], &[u8])> {
    use crate::util::nom::*;

    let len_tag = |bytes: &'static [u8]| length_value(be_u32, tag(bytes));
    let ssh_string = || length_data(be_u32);
    let ssh_ed25519 = || preceded(len_tag(b"ssh-ed25519"), ssh_string());

    let mut parse = consumed(length_count(
        preceded(tag(MAGIC), be_u32),
        length_value(
            be_u32,
            tuple((ssh_ed25519(), ssh_string(), ssh_string())),
        ),
    ));

    let (ciphertext, (header, recipients)) = parse(&binary[..])
        .map_err(|_: NomErr| anyhow!("could not parse message header"))?;

    Ok((recipients, header, ciphertext))
}

pub fn list(message: &[u8]) -> Result<()> {
    let binary = base64::unarmor(message, PREFIX, SUFFIX)?;

    let (recipients, _, _) = parse_message(&binary)?;

    for (rawkey, comment, _) in recipients {
        let name = String::from_utf8(comment.to_owned())?;
        let key = PublicKey::from_slice(rawkey).ok_or_else(|| {
            anyhow!("invalid ed25519 public key for {}", name)
        })?;
        println!("{}", Named { key, name });
    }
    Ok(())
}

pub fn decrypt(
    recipient: &Named<SecretKey>,
    message: &[u8],
) -> Result<Vec<u8>> {
    let binary = base64::unarmor(message, PREFIX, SUFFIX)?;

    let (recipients, header, ciphertext) = parse_message(&binary)?;

    let ssh_pubkey = recipient.key.public_key();
    let mykey = ssh_pubkey.as_ref();
    let myname = &recipient.name;

    let de_pubkey = ed25519::to_curve25519_pk(&ssh_pubkey)
        .map_err(|_| anyhow!("could not decrypt using {}", myname))?;
    let de_seckey = ed25519::to_curve25519_sk(&recipient.key)
        .map_err(|_| anyhow!("could not decrypt using {}", myname))?;

    let mut secrets = None;
    for (pubkey, _comment, encrypted) in recipients {
        if pubkey == mykey {
            use crate::util::nom::*;
            let decrypted = sealedbox::open(encrypted, &de_pubkey, &de_seckey)
                .map_err(|_| anyhow!("could not decrypt to {}", myname))?;
            let mut unpack =
                all_consuming(pair(length_data(be_u32), length_data(be_u32)));
            let (_, (nonce, key)) =
                unpack(&decrypted[..]).map_err(|_: NomErr| {
                    anyhow!("could not unpack aead secrets")
                })?;
            secrets = Some((
                aead::Nonce::from_slice(nonce)
                    .ok_or_else(|| anyhow!("invalid nonce"))?,
                aead::Key::from_slice(key)
                    .ok_or_else(|| anyhow!("invalid aead key"))?,
            ));
        }
    }

    let (nonce, key) =
        secrets.ok_or_else(|| anyhow!("{} is not a recipient", myname))?;

    let cleartext = aead::open(ciphertext, Some(header), &nonce, &key)
        .map_err(|_| anyhow!("aead decryption failed"))?;
    Ok(cleartext)
}

pub fn encrypt(
    recipients: &[Named<PublicKey>],
    message: &[u8],
) -> Result<Vec<u8>> {
    let nonce = aead::gen_nonce();
    let key = aead::gen_key();

    let mut secrets = SshBuffer::new();
    secrets.add_string(nonce.as_ref());
    secrets.add_string(key.as_ref());
    let secrets = secrets.as_ref();

    let mut binary = SshBuffer::new();
    binary.extend_from_slice(MAGIC);
    binary.add_u32(recipients.len() as u32);

    let mut rcpt = SshBuffer::new();
    for pubkey in recipients {
        let enckey = ed25519::to_curve25519_pk(&pubkey.key)
            .map_err(|_| anyhow!("could not encrypt to {}", pubkey.name))?;
        let encrypted = sealedbox::seal(secrets, &enckey);

        rcpt.add_pubkey(&pubkey.key);
        rcpt.add_string(pubkey.name.as_bytes());
        rcpt.add_string(&encrypted);
        binary.add_string(&rcpt);
        rcpt.clear();
    }

    let ciphertext = aead::seal(message, Some(binary.as_ref()), &nonce, &key);
    binary.extend_from_slice(&ciphertext[..]);

    Ok(base64::armored(&binary, PREFIX, SUFFIX))
}
