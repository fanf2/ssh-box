use anyhow::{anyhow, Result};
use rpassword::*;

pub type AskPass = Box<dyn FnMut() -> Result<String>>;

// when there isn't a terminal, we might try to open /dev/tty (or
// something like that on ununixy systems) before checking $DISPLAY
// and running ssh-askpass ... the rpassword crate is a bit awkward
// because its behaviour is rather different from ssh-add.
//
// another issue to think about is the typo retry loop

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
