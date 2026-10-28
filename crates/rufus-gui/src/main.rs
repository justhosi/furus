//! `rufus-gui`: desktop front end (Slint, arrives in S24/S24a).
//!
//! Slice S01 only: a stub so the workspace builds and `xtask size` has a
//! GUI binary to measure.

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") => println!("rufus-gui {}", env!("CARGO_PKG_VERSION")),
        Some("--help" | "-h") => println!("usage: rufus-gui [--version] [--help]"),
        _ => println!("GUI arrives in S24"),
    }
}
