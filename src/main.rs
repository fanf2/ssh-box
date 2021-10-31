#![allow(dead_code)]

use anyhow::{anyhow, Result};
use getopts::Options;

mod askpass;
mod base64;
mod key;
mod nom;
mod sshbox;
mod sshkey;
mod util;

fn usage(progname: &str, opts: Options, status: i32) {
    let brief =
        format!("usage: {} {{-c|-d|-e|-l}} [options] [files]", progname);
    print!("{}", opts.usage(&brief));
    std::process::exit(status);
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let progname = &args[0];

    sodiumoxide::init()
        .map_err(|_| anyhow!("could not initialize libsodium"))?;

    const RCPT_FILE: &str = "ssh_box_keys";
    const KEY_FILE: &str = "~/.ssh/id_ed25519";

    let mut opts = Options::new();
    opts.optflag("c", "check", "check encrypted file's recipient list");
    opts.optflag("d", "decrypt", "decrypt a file using your secret key");
    opts.optflag("e", "encrypt", "encrypt a file to a list of recipients");
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("l", "list", "list an encrypted file's recipients");
    opts.optopt("r", "recipients", "recipient public key list", RCPT_FILE);
    opts.optopt("s", "secret", "secret key file", KEY_FILE);

    let matches = opts.parse(&args[1..])?;

    let rcpt_file =
        matches.opt_str("r").unwrap_or_else(|| RCPT_FILE.to_string());
    let key_file = matches.opt_str("s").unwrap_or_else(|| KEY_FILE.to_string());

    if matches.opt_present("h") {
        usage(progname, opts, 0);
    } else if matches.opt_present("c") {
        println!("checking wrt {}", rcpt_file);
    } else if matches.opt_present("d") {
        println!("decrypting with {}", key_file);
    } else if matches.opt_present("e") {
        println!("encrypting to {}", rcpt_file);
    } else if matches.opt_present("l") {
        println!("listing recipients");
    } else {
        //usage(progname, opts, 1);
    }

    let pubkey = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRE3hd+N+jMlLuQsnB/IozFl/5O4SBvM4uWlCN+Fs8P eg\n";
    let message = b"example\n";
    let recipients = key::parse_public_keys(pubkey)?;
    let encrypted = sshbox::encrypt(&recipients, message)?;
    print!("{}", encrypted);

    Ok(())
}
