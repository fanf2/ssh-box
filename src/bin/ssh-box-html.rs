//! Documentation htmlifier
//! =======================

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn slurp(file: &str) -> Result<Vec<u8>> {
    std::fs::read(file).with_context(|| format!("failed to read {}", file))
}

fn spew(file: &Path, head: &[u8], body: &[u8], foot: &[u8]) -> Result<()> {
    let mut contents = Vec::new();
    contents.extend_from_slice(head);
    contents.extend_from_slice(body);
    contents.extend_from_slice(foot);
    std::fs::write(file, &contents)?;
    Ok(())
}

fn path(dir: &str, file: &str, suffix: &str) -> PathBuf {
    let mut path = PathBuf::from(dir);
    let filex = file.to_owned() + suffix;
    path.push(filex);
    path
}

fn man(file: &Path) -> Result<Vec<u8>> {
    let output = Command::new("mandoc")
        .args(["-Werror", "-Ofragment", "-Thtml"])
        .arg(file)
        .output()?;
    std::io::stderr().write_all(&output.stderr)?;
    if !output.status.success() {
        bail!("mandoc {} failed", file.to_str().unwrap());
    }
    Ok(output.stdout)
}

fn main() -> Result<()> {
    let head = slurp("doc/_header.html")?;
    let foot = slurp("doc/_footer.html")?;

    for file in ["ssh-box.5"] {
        let in_file = path("doc", file, "");
        let out_file = path("doc", file, ".html");
        let body = man(&in_file)?;
        spew(&out_file, &head, &body, &foot)?;
    }

    Ok(())
}
