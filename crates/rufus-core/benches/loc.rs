//! `loc` benchmark: parse `assets/resources/RCDATA_500.bin` 10 times and
//! report min/median/max in milliseconds (std only, `harness = false`).

use std::error::Error;
use std::time::Instant;

use rufus_core::Catalog;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../assets/resources/RCDATA_500.bin");
    let bytes = std::fs::read(&path)?;
    let mut durations_ms: Vec<f64> = Vec::with_capacity(10);
    for _ in 0..10 {
        let started = Instant::now();
        let catalog = Catalog::from_bytes(&bytes)?;
        std::hint::black_box(catalog.languages());
        durations_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    durations_ms.sort_by(|a, b| a.total_cmp(b));
    let min = durations_ms.first().copied().unwrap_or(0.0);
    let median = durations_ms[durations_ms.len() / 2];
    let max = durations_ms.last().copied().unwrap_or(0.0);
    println!(
        "loc parse over 10 runs ({} bytes): min={min:.3}ms median={median:.3}ms max={max:.3}ms",
        bytes.len()
    );
    for (index, elapsed) in durations_ms.iter().enumerate() {
        println!("  run {index}: {elapsed:.3}ms");
    }
    Ok(())
}
