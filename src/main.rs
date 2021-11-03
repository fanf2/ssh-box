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
    let key_file = map_tilde(key_file)?;

    if matches.opt_present("h") {
        usage(progname, opts, 0);
    } else if matches.opt_present("c") {
        let recipients = read_public_keys(&rcpt_file)?;
        let input = args_input(&matches.free)?;
        let (only_rcpt, only_file) = sshbox::check(&recipients, &input)?;
        let mut status = 0;
        if !only_rcpt.is_empty() {
            print!("only in {}:\n{}", &rcpt_file, only_rcpt);
            status = 1;
        }
        if !only_file.is_empty() {
            print!("only in {}:\n{}", matches.free[0], only_file);
            status = 1;
        }
        std::process::exit(status);
    } else if matches.opt_present("d") {
        let askpass = askpass::for_file(&key_file);
        let seckey = read_secret_key(&key_file, askpass)?;
        let (input, output) = args_in_out(&matches.free)?;
        let cleartext = sshbox::decrypt(&seckey, &input)?;
        output.write(&cleartext)?;
    } else if matches.opt_present("e") {
        let recipients = read_public_keys(&rcpt_file)?;
        let (input, output) = args_in_out(&matches.free)?;
        let ciphertext = sshbox::encrypt(&recipients, &input)?;
        output.write(ciphertext.as_bytes())?;
    } else if matches.opt_present("l") {
        let output = sshbox::list(&args_input(&matches.free)?)?;
        std::io::stdout().write_all(output.as_bytes())?;
    } else if matches.opt_present("k") {
        keygen(key_file)?;
    } else {
        usage(progname, opts, 1);
    }
    Ok(())
}

fn map_tilde(file: String) -> Result<String> {
    let home =
        std::env::var("HOME").with_context(|| "expanding ~ with $HOME")?;
    if file.starts_with("~/") {
        Ok(file.replacen("~", &home, 1))
    } else {
        Ok(file)
    }
}

fn keygen(file: String) -> Result<()> {
    use std::process::Command;
    let comment = format!("{} (ssh-box)", std::env::var("USER")?);
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f", &file, "-C", &comment])
        .status()?;
    std::process::exit(status.code().unwrap_or(1));
}

struct Output {
    name: String,
    write: Box<dyn std::io::Write>,
}

impl Output {
    fn new(name: &str) -> Result<Output> {
        let write: Box<dyn std::io::Write>;
        if name == "-" {
            ensure!(
                !atty::is(atty::Stream::Stdout),
                "output should be a file or pipe"
            );
            write = Box::new(std::io::stdout())
        } else {
            write = Box::new(
                std::fs::File::create(name)
                    .with_context(|| format!("writing {}", name))?,
            )
        }
        let name = name.to_owned();
        Ok(Output { name, write })
    }

    fn write(mut self, data: &[u8]) -> Result<()> {
        let context = || format!("writing {}", self.name);
        self.write.write_all(data).with_context(context)?;
        self.write.flush().with_context(context)?;
        Ok(())
    }
}

fn read_input(name: &str) -> Result<Vec<u8>> {
    if name == "-" {
        ensure!(
            !atty::is(atty::Stream::Stdin),
            "input should be a file or pipe"
        );
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input)?;
        Ok(input)
    } else {
        std::fs::read(name).with_context(|| format!("reading {}", name))
    }
}

fn args_in_out(args: &[String]) -> Result<(Vec<u8>, Output)> {
    ensure!(args.len() == 2, "must have input and output file arguments");
    let input = read_input(&args[0])?;
    let output = Output::new(&args[1])?;
    Ok((input, output))
}

fn args_input(args: &[String]) -> Result<Vec<u8>> {
    ensure!(args.len() == 1, "must have one input file argument");
    read_input(&args[0])
}
