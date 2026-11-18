/// QEMU VGA-text boot capture for the BIOS bootloader modes
/// (test-only): each boot test below drives its disk file through
/// this instead of transcribing expectations from sources.
///
/// Technique: the `isa-debugcon` / `-chardev file` path yields an
/// empty log on the QEMU + SeaBIOS builds this suite runs under,
/// so the harness boots with `-display none -monitor
/// unix:<sock>,server,nowait`, waits out the load, then sends
/// `pmemsave 0xb8000 4000 "<file>"` (double-quoted path) over the
/// monitor socket and decodes the dump as 25 rows of 80
/// character/attribute pairs. Boot media always come from
/// [`boot_disk`] (full plans with a partition table): bare FAT32
/// volumes cannot boot FreeDOS (its kernel assigns drive letters
/// from partition tables only) and GRUB4DOS likewise needs a
/// real partition entry.
///
/// Every capture kills and reaps its child and drops its scratch
/// directory (socket and dump vanish with it) on every path, so
/// no machine and no file survives a failed assertion; every
/// monitor read carries a timeout, so a silent QEMU fails the

mod qemu;
mod qemu_boot;

    use std::io::Read as _;
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use crate::error::CoreError;
    use crate::error::Result as TestResult;

    /// VGA text buffer shape: 25 rows of 80
    /// character/attribute pairs.
    const VGA_ROWS: usize = 25;
    const VGA_COLS: usize = 80;
    const VGA_BYTES: usize = VGA_ROWS * VGA_COLS * 2;

    /// Whether `qemu-system-x86_64` answers `--version`: the one
    /// probe every boot test gates on (the same smoke shape as
    /// the `fsck.fat` acceptances elsewhere in this file).
    pub(crate) fn have_qemu() -> bool {
        std::process::Command::new("qemu-system-x86_64")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// A spawned QEMU that is killed and reaped on drop, so no
    /// machine survives a failed assertion or an early return.
    struct Guard {
        child: Option<std::process::Child>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Send one monitor line (the reply is drained by the
    /// caller after it has had time to arrive).
    fn send(stream: &mut UnixStream, line: &str) -> TestResult<()> {
        stream
            .write_all(line.as_bytes())
            .map_err(|source| CoreError::io("qemu monitor", source))
    }

    /// Read and discard one monitor reply (greeting, command
    /// reply, prompt): bounded by the stream timeout, so a
    /// silent monitor fails instead of hanging.
    fn drain(stream: &mut UnixStream) -> TestResult<()> {
        let mut buf = [0u8; 65536];
        stream
            .read(&mut buf)
            .map_err(|source| CoreError::io("qemu monitor", source))?;
        Ok(())
    }

    /// Connect to the monitor socket, retrying while QEMU binds
    /// it; a socket that never answers refuses naming it.
    fn connect(sock: &std::path::Path) -> TestResult<UnixStream> {
        let mut last = String::new();
        for _ in 0..50 {
            match UnixStream::connect(sock) {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    last = error.to_string();
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        Err(CoreError::invalid(format!(
            "qemu monitor at {} never answered ({last}): refusing",
            sock.display()
        )))
    }

    /// Decode a VGA dump into 25 right-trimmed rows: every second
    /// byte is the character cell (the attribute byte interleaves
    /// it), non-printable cells read as a space.
    fn decode(dump: &[u8]) -> TestResult<Vec<String>> {
        if dump.len() < VGA_BYTES {
            return Err(CoreError::invalid(format!(
                "qemu vga dump holds {} bytes, the text buffer needs {VGA_BYTES}: refusing",
                dump.len()
            )));
        }
        let mut lines = Vec::with_capacity(VGA_ROWS);
        for row in 0..VGA_ROWS {
            let mut text = String::with_capacity(VGA_COLS);
            for col in 0..VGA_COLS {
                let byte = dump
                    .get(row * VGA_COLS * 2 + col * 2)
                    .expect("the vga window fits the length check above");
                text.push(if (0x20..0x7F).contains(byte) {
                    *byte as char
                } else {
                    ' '
                });
            }
            lines.push(text.trim_end().to_string());
        }
        Ok(lines)
    }

    /// Boot `disk` in QEMU, wait `wait`, capture the VGA text
    /// buffer and quit the machine.
    pub(crate) fn capture(disk: &std::path::Path, wait: Duration) -> TestResult<Vec<String>> {
        capture_keys(disk, wait, &[])
    }

    /// [`capture`] plus one `sendkey` line per entry of `keys`
    /// after the wait (then a settle wait before the dump): the
    /// GRUB2 config test drives the loader shell this way.
    pub(crate) fn capture_keys(
        disk: &std::path::Path,
        wait: Duration,
        keys: &[&str],
    ) -> TestResult<Vec<String>> {
        let scratch = tempfile::tempdir().expect("a qemu scratch directory");
        let sock = scratch.path().join("mon.sock");
        let dump = scratch.path().join("vga.bin");
        let child = std::process::Command::new("qemu-system-x86_64")
            .arg("-m")
            .arg("128")
            .arg("-drive")
            .arg(format!("file={},format=raw,if=ide", disk.display()))
            .arg("-display")
            .arg("none")
            .arg("-no-reboot")
            .arg("-monitor")
            .arg(format!("unix:{},server,nowait", sock.display()))
            .spawn()
            .map_err(|source| CoreError::io("qemu-system-x86_64", source))?;
        let guard = Guard { child: Some(child) };
        std::thread::sleep(wait);
        let mut stream = connect(&sock)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|source| CoreError::io("qemu monitor", source))?;
        drain(&mut stream)?;
        for key in keys {
            send(&mut stream, &format!("sendkey {key}\n"))?;
            std::thread::sleep(Duration::from_millis(150));
        }
        if !keys.is_empty() {
            std::thread::sleep(Duration::from_secs(3));
        }
        // The dump path is double-quoted: the monitor splits
        // unquoted paths on whitespace.
        send(
            &mut stream,
            &format!("pmemsave 0xb8000 4000 \"{}\"\n", dump.display()),
        )?;
        std::thread::sleep(Duration::from_secs(1));
        drain(&mut stream)?;
        send(&mut stream, "quit\n")?;
        std::thread::sleep(Duration::from_millis(300));
        drop(guard);
        let bytes = std::fs::read(&dump).map_err(|source| CoreError::io(&dump, source))?;
        decode(&bytes)
    }

    /// Print the non-empty rows for the test log: every boot test
    /// reports what it saw, so a failure quotes the screen.
    pub(crate) fn log(lines: &[String]) {
        eprintln!("qemu vga screen (non-empty rows only):");
        for line in lines.iter().filter(|line| !line.is_empty()) {
            eprintln!("  |{line}|");
        }
    }
}

/// Build the Syslinux 4.07 fixture ISO: the same descriptor and
/// directory shape as [`syslinux_iso`], but a 4.07 banner and no
/// `.c32` files. 4.07 needs no core library, which is what makes
/// it the bootable fixture: 6.04 needs real `.c32` modules no
/// test can provide, so a 6.04 stick can never get past its
