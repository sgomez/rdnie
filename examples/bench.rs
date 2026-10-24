//! Benchmark for the card's holder, comparable with `bench/`: times `--runs` fresh sessions up to the
//! signature certificate, or every certificate with `--all`, and `--sign` signs once; prints times only.

use rdnie::{
    DigestAlgorithm, Error, INTERMEDIATE_CA_LABEL, PcscTransport, Pin, SIGNATURE_LABEL, Session,
};
use sha2_010::{Digest, Sha256};
use std::time::{Duration, Instant};

const DEFAULT_RUNS: usize = 20;

fn main() {
    if let Err(error) = run() {
        println!("stopped: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    let arguments: Vec<String> = std::env::args().collect();
    let value = |flag: &str| {
        arguments
            .iter()
            .position(|argument| argument == flag)
            .and_then(|index| arguments.get(index + 1))
    };
    let reader = match value("--reader") {
        Some(name) => name.clone(),
        None => PcscTransport::connect_first_dnie()?.reader(),
    };
    let runs = match value("--runs") {
        Some(runs) => runs
            .parse::<usize>()
            .map_err(|_| Error::Transport("--runs takes a number".to_owned()))?,
        None => DEFAULT_RUNS,
    }
    .max(1);
    println!("tool: rdnie {}", env!("CARGO_PKG_VERSION"));
    println!("reader: {reader}");
    let all = arguments.iter().any(|argument| argument == "--all");

    let mut steps: [(&str, Vec<Duration>); 4] = [
        ("connect + open", vec![]),
        ("labels", vec![]),
        (
            if all {
                "certificates (all)"
            } else {
                "certificate (signature)"
            },
            vec![],
        ),
        ("total", vec![]),
    ];
    for _ in 0..runs {
        let start = Instant::now();
        let mut session = Session::open(PcscTransport::connect(&reader)?)?;
        let opened = start.elapsed();
        let mut labels = session.labels()?;
        let listed = start.elapsed();
        if all {
            labels.push(INTERMEDIATE_CA_LABEL.to_owned());
        } else {
            labels = vec![SIGNATURE_LABEL.to_owned()];
        }
        for label in &labels {
            session
                .certificate(label)?
                .ok_or_else(|| Error::Transport(format!("no certificate {label}")))?;
        }
        let read = start.elapsed();
        let times = [
            opened,
            listed.saturating_sub(opened),
            read.saturating_sub(listed),
            read,
        ];
        for ((_, recorded), time) in steps.iter_mut().zip(times) {
            recorded.push(time);
        }
    }
    for (step, times) in &mut steps {
        summary(step, times);
    }

    if arguments.iter().any(|argument| argument == "--sign") {
        sign(&reader)?;
    }
    Ok(())
}

/// One signature of a fixed digest in a fresh session, timed from the retries read to the result.
fn sign(reader: &str) -> Result<(), Error> {
    let mut session = Session::open(PcscTransport::connect(reader)?)?;
    let key = session
        .private_key(SIGNATURE_LABEL)?
        .ok_or_else(|| Error::Transport("no signature key".to_owned()))?;
    println!("retries before the PIN: {}", session.pin_retries_left()?);
    let pin = rpassword::prompt_password("PIN (not shown): ")
        .map_err(|error| Error::Transport(format!("cannot read the PIN: {error}")))?;
    let digest = Sha256::digest(b"rdnie bench");
    let start = Instant::now();
    session.sign(&digest, DigestAlgorithm::Sha256, &key, Pin::new(pin))?;
    summary("sign", &mut [start.elapsed()]);
    Ok(())
}

fn summary(step: &str, times: &mut [Duration]) {
    times.sort();
    let ms = |time: &Duration| time.as_secs_f64() * 1e3;
    println!(
        "{step}: median {:.1} ms, min {:.1} ms, max {:.1} ms ({} runs)",
        ms(&times[times.len() / 2]),
        ms(&times[0]),
        ms(&times[times.len() - 1]),
        times.len()
    );
}
