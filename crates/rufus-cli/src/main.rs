//! `rufus`: command-line front end.
//!
//! Slice S01 only: `--version` / `--help` stub. Real subcommands
//! (`list`, `analyze`, `plan`, `write`, `checksum`) arrive in S03.

const HELP: &str = concat!(
    "rufus ",
    env!("CARGO_PKG_VERSION"),
    " — native Linux USB/ISO writer (S01 stub)

usage: rufus [--version] [--help] <command> [options]

future commands (arrive in S03):
  list                 enumerate candidate USB devices
  analyze <image>      report image kind and boot options
  plan                 print the validated write plan as JSON
  write                execute a plan via the privileged helper
  checksum <image>     hash an image (md5/sha1/sha256/sha512)

options:
  --version            print version and exit 0
  --help, -h           print this help and exit 0
"
);

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") => println!("rufus {}", env!("CARGO_PKG_VERSION")),
        Some("--help" | "-h") => print!("{HELP}"),
        None => {
            eprint!("{HELP}");
            eprintln!("error: no command given (commands arrive in S03)");
            std::process::exit(1);
        }
        Some(other) => {
            eprint!("{HELP}");
            eprintln!("error: unknown command '{other}' (commands arrive in S03)");
            std::process::exit(1);
        }
    }
}
