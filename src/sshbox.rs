use crate::prelude::*;

const PEM_LABEL: &str = "SSH-BOX ENCRYPTED FILE";

const MAGIC: &[u8] = b"https://dotat.at/prog/ssh-box/v1\0";

pub struct Header {
    rcpt: HashMap<PublicKey, Vec<u8>>,
    label: Vec<u8>,
    other: Vec<Record>,
    errors: Vec<Record>,
}

fn parse_message(binary: &[u8]) -> Result<(Header, &[u8], &[u8])> {
    use crate::nom::*;
    use nom::number::complete::u8 as byte;

    let zero = verify(byte, |&n| n == 0);
    let non0 = verify(byte, |&n| n != 0);
    let parse_one = length_count(non0, ssh_string_owned);
    let parse_all = preceded(tag(MAGIC), many_till(parse_one, zero));

    let (ciphertext, (authdata, (mut items, _zero))) =
        consumed(parse_all)(binary)
            .map_err(|_| anyhow!("could not parse message header"))?;

    let mut rcpt = HashMap::new();
    let mut label = Vec::new();
    let mut other = Vec::new();
    let mut errors = Vec::new();
    for mut item in items.drain(..) {
        match &*item[0] {
            b"label" => {
                if item.len() == 2 {
                    label.extend_from_slice(&*item[1]);
                } else {
                    errors.push(item);
                }
            }
            b"ssh-ed25519" | b"ssh-rsa" => {
                let secrets = item.pop().unwrap();
                // XXX error checking
                let pubkey = PublicKey::new(item);
                // XXX duplicate checking
                rcpt.insert(pubkey, secrets);
            }
            _ => {
                other.push(item);
            }
        }
    }

    let header = Header { rcpt, label, other, errors };
    Ok((header, authdata, ciphertext))
}

#[allow(unused_variables)]
pub fn check(wanted: &[PublicKey], message: &[u8]) -> Result<(String, String)> {
    let binary = pem_decap(message, PEM_LABEL)?;
    let (header, _, _) = parse_message(&binary)?;
    unimplemented!()
}

pub fn list(message: &[u8]) -> Result<String> {
    let binary = pem_decap(message, PEM_LABEL)?;
    let (header, _, _) = parse_message(&binary)?;

    let mut list = String::new();
    for pubkey in header.rcpt.keys() {
        write!(list, "{:b}", pubkey)?;
    }
    Ok(list)
}

pub fn decrypt(
    seckey: &SecretKey,
    message: &[u8],
) -> Result<(Header, Vec<u8>)> {
    let binary = pem_decap(message, PEM_LABEL)?;
    let (header, authdata, ciphertext) = parse_message(&binary)?;
    let pubkey = seckey.pubkey();
    let encrypted = header
        .rcpt
        .get(&pubkey)
        .ok_or_else(|| anyhow!("no recipient matches {}", pubkey))?;
    let secrets = seckey.decrypt(encrypted)?;

    let nonce = aead::Nonce::from_slice(&secrets[0..aead::NONCEBYTES])
        .ok_or_else(|| anyhow!("invalid aead nonce"))?;
    let key = aead::Key::from_slice(&secrets[aead::NONCEBYTES..])
        .ok_or_else(|| anyhow!("invalid aead key"))?;

    let body = aead::open(ciphertext, Some(authdata), &nonce, &key)
        .map_err(|_| anyhow!("aead decryption failed"))?;

    Ok((header, body))
}

pub fn encrypt(recipients: &[PublicKey], message: &[u8]) -> Result<String> {
    let nonce = aead::gen_nonce();
    let key = aead::gen_key();

    let mut secrets = Vec::new();
    secrets.extend_from_slice(nonce.as_ref());
    secrets.extend_from_slice(key.as_ref());

    let mut binary = Buf::new();
    binary.add_bytes(MAGIC);

    for pubkey in recipients {
        pubkey.encrypt(&mut binary, &secrets)?;
    }
    binary.add_byte(0);

    let ciphertext = aead::seal(message, Some(binary.as_ref()), &nonce, &key);
    binary.add_bytes(&ciphertext);

    Ok(pem_encap(binary.as_ref(), PEM_LABEL))
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
    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\n\
    Plr90Ox1ZG7d9tAAAAA3R3bwECAwQFBgc=\n\
    -----END OPENSSH PRIVATE KEY-----\n\
    ";

    const PUBLIC: &str = "\
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMaw710XKx9LErYP23vJtgzmRROfONos1wKqqaG97HZc one\n\
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChwbws1eJKxUhMQYIDwkglrS295fv4M8XrY8\
    pOFD0dMHW8cXiHj+dfGg9TZrY2RjmUBxgW6RSR1jaZSdk0wkqX6yg1E6ObG1Mgmn7BSBxxsg9W\
    5CVMhdL2fsaCCHOw0PtHCR1hMPWOqbD4X9kkXOJe3vX7pOgw35spyKTyqswoINWbVgB/1oHsTn\
    KsGyfdmUGQknRQnPanyEBXjU57RnGnoO/c71vdsG8ldRkE/V+81KuvDp0OAjFCORwd4vU5Yf6l\
    GMLgjcWjkW87hNNyUTWxLTNs8by7lGHvNvIosW8mXaE3E999up4nblqnNauUG1FtyeZSH7H0Ws\
    a6uD/p+3LcCdctvgLhYu8wujor5egMpreQZIAnD7SL1fdgtAmblIgJaGuhptIzs3aj2VRgkyDw\
    dePr7vMowBXDfMzPOAbBkXGjNNLbU1mdil/pDoeGdEGIhC51BDlNWJyv3WNCsEUYzOrxW1QO1b\
    iNdXScBy4eNh5Qgi51X7AAlQoS3dp18Lc= two\n\
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
        let (_, dec_one) = decrypt(&sec_one, &encrypted).unwrap();
        let (_, dec_two) = decrypt(&sec_two, &encrypted).unwrap();
        assert!(dec_zero.is_err());
        assert_eq!(dec_one, MESSAGE);
        assert_eq!(dec_two, MESSAGE);
        assert_eq!(sec_one.pubkey(), recipients[0]);
        assert_eq!(sec_two.pubkey(), recipients[1]);
    }
}
