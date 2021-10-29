use anyhow::Result;
use getopts::Options;

mod askpass;
mod sshkey;

fn usage(progname: &str, opts: Options, status: i32) {
    let brief = format!("usage: {} {{-c|-d|-e|-l}} [options]", progname);
    print!("{}", opts.usage(&brief));
    std::process::exit(status);
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let progname = &args[0];

    const RCPT_FILE: &str = "recipients.pub";
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
    if matches.opt_present("h") {
        usage(progname, opts, 0);
    } else if matches.opt_present("c") {
        let rcpt_file =
            matches.opt_str("r").unwrap_or_else(|| RCPT_FILE.to_string());
        println!("checking wrt {}", rcpt_file);
    } else if matches.opt_present("d") {
        let key_file =
            matches.opt_str("s").unwrap_or_else(|| KEY_FILE.to_string());
        println!("decrypting with {}", key_file);
    } else if matches.opt_present("e") {
        let rcpt_file =
            matches.opt_str("r").unwrap_or_else(|| RCPT_FILE.to_string());
        println!("encrypting to {}", rcpt_file);
    } else if matches.opt_present("l") {
        println!("listing recipients");
    } else {
        // usage(progname, opts, 1);
    }

    use sshkey::*;

    let key_file = "id_ed25519.clear";
    let askpass = askpass::for_file(key_file);
    print!("{}", PublicKey::from(read_secret_key(key_file, askpass)?));

    Ok(())
}
