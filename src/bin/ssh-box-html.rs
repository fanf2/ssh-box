//! Documentation htmlifier
//! =======================

use anyhow::{bail, Context, Result};
use regex::bytes::Regex;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn slurp(file: &Path) -> Result<Vec<u8>> {
    std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))
}

fn spew(file: &Path, head: &[u8], body: &[u8], foot: &[u8]) -> Result<()> {
    let mut contents = Vec::new();
    contents.extend_from_slice(head);
    contents.extend_from_slice(body);
    contents.extend_from_slice(foot);
    std::fs::write(file, &contents)?;
    println!("> {}", file.display());
    Ok(())
}

fn command(args: &[&str], file: &Path) -> Result<Vec<u8>> {
    let mut command = Command::new(args[0]);
    command.args(&args[1..]).arg(file);
    let display = format!("{:?}", command);
    let display = display.replace("\"", "");
    println!("! {}", display);
    let output = command.output()?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("{} {} failed", args[0], file.to_str().unwrap());
    }
    Ok(output.stdout)
}

fn path(dir: &str, file: &str, suffix: &str) -> PathBuf {
    let mut path = PathBuf::from(dir);
    let filex = file.to_owned() + suffix;
    path.push(filex);
    path
}

fn man(file: &Path) -> Result<Vec<u8>> {
    command(&["mandoc", "-Werror", "-Ofragment", "-Thtml"], file)
}

fn mandate(file: &Path) -> Result<()> {
    if !Path::new(".git").is_dir() {
        return Ok(());
    }
    let git_log = &[
        "git",
        "log",
        "--format='.Dd %ad'",
        "--date=format:'%b %e, %Y'",
        "--max-count=1",
    ];
    let dateline = command(git_log, file)?;
    let re = Regex::new(r"^\.Dd.*$")?;
    let original = slurp(file)?;
    let updated = &*re.replace(&original, &dateline);
    if original != updated {
        print!("{}", String::from_utf8_lossy(&dateline));
        spew(file, b"", updated, b"")?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let head = slurp(Path::new("doc/_header.html"))?;
    let foot = slurp(Path::new("doc/_footer.html"))?;

    for file in ["ssh-box.5"] {
        let in_file = path("doc", file, "");
        let out_file = path("doc", file, ".html");
        mandate(&in_file)?;
        let body = man(&in_file)?;
        spew(&out_file, &head, &body, &foot)?;
    }

    Ok(())
}
