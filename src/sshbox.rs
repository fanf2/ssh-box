use anyhow::{anyhow, Result};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign::ed25519;
use std::fmt::Write;

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
        tuple((ssh_ed25519(), ssh_string(), ssh_string())),
    ));

    let (ciphertext, (header, recipients)) = parse(binary)
        .map_err(|_: NomErr| anyhow!("could not parse message header"))?;

    Ok((recipients, header, ciphertext))
}

pub fn list(message: &[u8]) -> Result<String> {
    let binary = base64::unarmor(message, PREFIX, SUFFIX)?;
    let (recipients, _, _) = parse_message(&binary)?;

    let mut list = String::new();
    for (rawkey, comment, _) in recipients {
        let name = String::from_utf8(comment.to_owned())?;
        let key = PublicKey::from_slice(rawkey).ok_or_else(|| {
            anyhow!("invalid ed25519 public key for {}", name)
        })?;
        write!(list, "{}", Named { key, name })?;
    }
    Ok(list)
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
            let decrypted = sealedbox::open(encrypted, &de_pubkey, &de_seckey)
                .map_err(|_| anyhow!("could not decrypt to {}", myname))?;
            secrets = Some((
                aead::Nonce::from_slice(&decrypted[0..aead::NONCEBYTES])
                    .ok_or_else(|| anyhow!("invalid nonce"))?,
                aead::Key::from_slice(&decrypted[aead::NONCEBYTES..])
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

    let mut secrets = Vec::new();
    secrets.extend_from_slice(nonce.as_ref());
    secrets.extend_from_slice(key.as_ref());
    let secrets = &secrets[..];

    let mut binary = SshBuffer::new();
    binary.extend_from_slice(MAGIC);
    binary.add_u32(recipients.len() as u32);

    for pubkey in recipients {
        let enckey = ed25519::to_curve25519_pk(&pubkey.key)
            .map_err(|_| anyhow!("could not encrypt to {}", pubkey.name))?;
        let encrypted = sealedbox::seal(secrets, &enckey);
        binary.add_pubkey(&pubkey.key);
        binary.add_string(pubkey.name.as_bytes());
        binary.add_string(&encrypted);
    }

    let ciphertext = aead::seal(message, Some(binary.as_ref()), &nonce, &key);
    binary.extend_from_slice(&ciphertext[..]);

    Ok(base64::armored(&binary, PREFIX, SUFFIX))
}

#[cfg(test)]
mod test {

    const SECRET_ZERO: &[u8] = b"\
    -----BEGIN OPENSSH PRIVATE KEY-----\n\
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
    QyNTUxOQAAACD88aI+Jay1MEgZlfOGZmMplk9foBQvg0JCvTw4xogNogAAAIi72eREu9nk\n\
    RAAAAAtzc2gtZWQyNTUxOQAAACD88aI+Jay1MEgZlfOGZmMplk9foBQvg0JCvTw4xogNog\n\
    AAAEAMtqFIDexbUvh5ZloO2JLNJfMPOB76EKOVNtrh6DaJh/zxoj4lrLUwSBmV84ZmYymW\n\
    T1+gFC+DQkK9PDjGiA2iAAAABHplcm8B\n\
    -----END OPENSSH PRIVATE KEY-----\n\
    ";

    const SECRET_ONE: &[u8] = b"\
    -----BEGIN OPENSSH PRIVATE KEY-----\n\
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
    QyNTUxOQAAACDGsO9dFysfSxK2D9t7ybYM5kUTnzjaLNcCqqmhvex2XAAAAIgYA8aRGAPG\n\
    kQAAAAtzc2gtZWQyNTUxOQAAACDGsO9dFysfSxK2D9t7ybYM5kUTnzjaLNcCqqmhvex2XA\n\
    AAAECqxkaC8YKuyuXcbAl6DMv/Ca5eCshweOQQbfQ6AqVUs8aw710XKx9LErYP23vJtgzm\n\
    RROfONos1wKqqaG97HZcAAAAA29uZQEC\n\
    -----END OPENSSH PRIVATE KEY-----\n\
    ";

    const SECRET_TWO: &[u8] = b"\
    -----BEGIN OPENSSH PRIVATE KEY-----\n\
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
    QyNTUxOQAAACBUh0x+FydQOmQgZn2J6+FEl81bOba2If+FBl3t8tsWfwAAAIiPPWL/jz1i\n\
    /wAAAAtzc2gtZWQyNTUxOQAAACBUh0x+FydQOmQgZn2J6+FEl81bOba2If+FBl3t8tsWfw\n\
    AAAECNNik9+qZ8us+3q/mvTNUH9cDG7uJDZGVwqIgXptpO91SHTH4XJ1A6ZCBmfYnr4USX\n\
    zVs5trYh/4UGXe3y2xZ/AAAAA3R3bwEC\n\
    -----END OPENSSH PRIVATE KEY-----\n\
    ";

    const PUBLIC: &str = "\
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMaw710XKx9LErYP23vJtgzmRROfONos1wKqqaG97HZc one\n\
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFSHTH4XJ1A6ZCBmfYnr4USXzVs5trYh/4UGXe3y2xZ/ two\n\
    ";

    const MESSAGE: &[u8] = b"Mr. Watson, come here. I want to see you.";

    #[test]
    fn test() {
        use super::*;

        let recipients = parse_public_keys(PUBLIC.as_bytes()).unwrap();

        let encrypted = encrypt(&recipients, MESSAGE).unwrap();

        let list = list(&encrypted).unwrap();
        assert_eq!(PUBLIC, list);

        let askpass = || Box::new(|| Ok("testing".to_owned()));
        let sec_zero = parse_secret_key(SECRET_ZERO, askpass()).unwrap();
        let sec_one = parse_secret_key(SECRET_ONE, askpass()).unwrap();
        let sec_two = parse_secret_key(SECRET_TWO, askpass()).unwrap();
        let dec_zero = decrypt(&sec_zero, &encrypted);
        let dec_one = decrypt(&sec_one, &encrypted).unwrap();
        let dec_two = decrypt(&sec_two, &encrypted).unwrap();
        assert!(dec_zero.is_err());
        assert_eq!(dec_one, MESSAGE);
        assert_eq!(dec_two, MESSAGE);
    }
}
