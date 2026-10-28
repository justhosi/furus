//! `rufus-helper`: privileged device writer (pkexec/D-Bus entry point).
//!
//! Slice S01 only: a version/usage stub. Plan validation and execution
//! arrive in S06.

fn usage() -> &'static str {
    "usage: rufus-helper [--version] [--help]\n\
     privileged write helper; plan validation and execution arrive in S06."
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") => println!("rufus-helper {}", env!("CARGO_PKG_VERSION")),
        Some("--help" | "-h") => println!("{}", usage()),
        None => {
            println!("{}", usage());
        }
        Some(other) => {
            eprintln!("rufus-helper: unexpected argument '{other}'\n{}", usage());
            std::process::exit(1);
        }
    }
}
