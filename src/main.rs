#![allow(dead_code)]
use crate::prelude::*;
use getopts::Options;

mod askpass;
mod base64;
mod nom;
mod prelude;
mod pubkey;
mod seckey;
mod sshbox;

fn usage(progname: &str, opts: Options, status: i32) {
    let brief =
        format!("usage: {} {{-c|-d|-e|-l}} [options] [files]", progname);
    print!("{}", opts.usage(&brief));
    std::process::exit(status);
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let progname = &args[0];

    sodiumoxide::init().or_else(|_| bail!("could not initialize libsodium"))?;

    const RCPT_FILE: &str = "ssh_box_keys";
    const KEY_FILE: &str = "~/.ssh/box_ed25519";

    let mut opts = Options::new();
    opts.optflag("c", "check", "check encrypted file's recipient list");
    opts.optflag("d", "decrypt", "decrypt a file using your secret key");
    opts.optflag("e", "encrypt", "encrypt a file to a list of recipients");
    opts.optflag("k", "keygen", "generate an ssh-box key pair");
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
    } else if matches.opt_present("k") {
        return keygen(key_file);
    } else {
        //usage(progname, opts, 1);
    }

    let pubkeys = b"\
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRE3hd+N+jMlLuQsnB/IozFl/5O4SBvM4uWlCN+Fs8P ed\n\
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJmjUTr9pyZJEzs/iS48mZZEofOQBCu27VKL/mlu38+KJ3aeR7dCiQbrF97+k8+S82g64zHxxs4gwFwLmQrym6/WmrCxI1VPzWDQvSZ6u8jQN0m/N+uatXTV3jqjaFeVFGwdR6+4SFmPTFqLpv4JrgMlnjq0Rw2s8JAA7h0Dyq4YDBoTd7/37fCY9KJfju54G7mDKszm8MvDb/f/7xXDkQkKmb46PB9+T4q/j0iWMGqV9PCot3YwiIIp8iM+ZUh/jdj+0bxP3WJOfkhBQf7msuE2yKjzoWZMHPtJ2v5dusaqS5t6GCgA2QloP2ebYDSBh2ugUZzstwhLIdc9jIvOGayyXKyDDblqf2xKx0Pm0RNc+7STmYI0pXuvBycknHlBq4JzZQD5M39r/x+tJC5/WeePbaILB32di3EKwEAGOwXbC4zOb+7p3kPAFOkZRfXkG70T4sLmlZD3Vhb0ac5UABc2a/XTYb4gjK4jy2mn3qSC4gvx0rqcks50XmV0rRoQM= rsa\n\
";
    let message = b"example\n";
    let recipients = parse_public_keys(pubkeys)?;
    let encrypted = sshbox::encrypt(&recipients, message)?;
    print!("{}", encrypted);

    Ok(())
}

fn args_inout(args: Vec<String>) -> Result<()> {
    ensure!(args.len() != 2, "must have input and output file arguments");
    unimplemented!()
}

fn keygen(mut file: String) -> Result<()> {
    use std::process::Command;

    let home = std::env::var("HOME")?;
    let user = std::env::var("USER")?;
    let comment = format!("{} (ssh-box)", user);

    if file.starts_with("~/") {
        file = file.replacen("~", &home, 1);
    }
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f", &file, "-C", &comment])
        .status()?;
    std::process::exit(status.code().unwrap_or(1));
}
