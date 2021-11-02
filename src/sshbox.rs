use crate::prelude::*;

const PREFIX: &str = "-----BEGIN SSH-BOX ENCRYPTED FILE-----\n";
const SUFFIX: &str = "-----END SSH-BOX ENCRYPTED FILE-----\n";

const MAGIC: &[u8] = b"ssh-box-v1\0";

type Recipient<'a> = (PublicKey, &'a [u8]);

fn parse_message(binary: &[u8]) -> Result<(Vec<Recipient>, &[u8], &[u8])> {
    use crate::nom::*;

    let pubkey_name =
        map(pair(ssh_string_pubkey, is_utf8(ssh_string)), PublicKey::from);
    let parse_header = length_count(
        preceded(tag(MAGIC), be_u32),
        pair(pubkey_name, ssh_string),
    );

    let (ciphertext, (header, recipients)) = consumed(parse_header)(binary)
        .map_err(|_: NomErr| anyhow!("could not parse message header"))?;

    Ok((recipients, header, ciphertext))
}

pub fn list(message: &[u8]) -> Result<String> {
    let binary = ascii_unarmor(message, PREFIX, SUFFIX)?;
    let (recipients, _, _) = parse_message(&binary)?;

    let mut list = String::new();
    for (pubkey, _) in recipients {
        write!(list, "{:b}", pubkey)?;
    }
    Ok(list)
}

pub fn decrypt(seckey: &SecretKey, message: &[u8]) -> Result<Vec<u8>> {
    let binary = ascii_unarmor(message, PREFIX, SUFFIX)?;
    let (recipients, header, ciphertext) = parse_message(&binary)?;

    let (_, encrypted) = recipients
        .iter()
        .find(|(pubkey, _)| pubkey == &seckey.pubkey)
        .ok_or_else(|| anyhow!("no recipient matches {}", &seckey.pubkey))?;

    let secrets = seckey.decrypt(encrypted)?;

    let nonce = aead::Nonce::from_slice(&secrets[0..aead::NONCEBYTES])
        .ok_or_else(|| anyhow!("invalid aead nonce"))?;
    let key = aead::Key::from_slice(&secrets[aead::NONCEBYTES..])
        .ok_or_else(|| anyhow!("invalid aead key"))?;

    aead::open(ciphertext, Some(header), &nonce, &key)
        .map_err(|_| anyhow!("aead decryption failed"))
}

pub fn encrypt(recipients: &[PublicKey], message: &[u8]) -> Result<String> {
    let nonce = aead::gen_nonce();
    let key = aead::gen_key();

    let mut secrets = Vec::new();
    secrets.extend_from_slice(nonce.as_ref());
    secrets.extend_from_slice(key.as_ref());

    let mut binary = Buf::new();
    binary.add_bytes(MAGIC);
    binary.add_u32(recipients.len() as u32);

    for pubkey in recipients {
        binary.add_string(&pubkey.blob);
        binary.add_string(pubkey.name.as_bytes());
        binary.add_string(&pubkey.encrypt(&secrets)?);
    }

    let ciphertext = aead::seal(message, Some(binary.bytes()), &nonce, &key);
    binary.add_bytes(&ciphertext);

    Ok(ascii_armored(binary.bytes(), PREFIX, SUFFIX))
}

pub struct Buf(Vec<u8>);

impl Buf {
    pub fn new() -> Self {
        Buf(Vec::new())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn add_bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    pub fn add_u32(&mut self, n: u32) {
        self.add_bytes(&n.to_be_bytes());
    }

    pub fn add_string(&mut self, string: &[u8]) {
        self.add_u32(string.len() as u32);
        self.add_bytes(string);
    }
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
        let encrypted = encrypted.as_bytes();

        let list = list(encrypted).unwrap();
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
        assert_eq!(sec_one.pubkey, recipients[0]);
        assert_eq!(sec_two.pubkey, recipients[1]);
    }
}
