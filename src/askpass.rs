use anyhow::{anyhow, Result};
use rpassword::*;

pub type AskPass = Box<dyn FnMut() -> Result<String>>;

pub fn for_file(key_file: &str) -> AskPass {
    let prompt = format!("\rEnter passphrase for {}: ", key_file);
    Box::new(move || {
        if atty::is(atty::Stream::Stdin) {
            Ok(read_password_from_tty(Some(&prompt))?)
        } else {
            Err(anyhow!("no terminal to read passphrase"))
        }
    })
}
