//! Manual probe for the card's holder: prints ATR, status words, counts and pass/fail only.

use std::fmt::Write as _;

use rdnie::{Error, KeyGeneration, PcscTransport, Session, Transport};

fn main() {
    if let Err(error) = run() {
        println!("stopped: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    let mut transport = PcscTransport::connect_first_dnie()?;
    println!("ATR: {}", hex(&transport.reset()?));

    let mut session = Session::open(transport)?;
    println!("card: DNIe 3.0/4.0");
    let key_set = match session.key_generation() {
        KeyGeneration::First => "r1",
        KeyGeneration::Second => "r2",
    };
    println!("key set: {key_set}");

    let certificates = session.certificates()?;
    println!("certificates: {}", certificates.len());

    match session.pin_retries() {
        Ok(retries) => {
            println!("component certificate: pass");
            println!("retries: {retries}");
        }
        Err(Error::PinBlocked) => {
            println!("component certificate: pass");
            println!("retries: 0 (blocked)");
        }
        Err(error) => {
            println!("component certificate or PIN channel: fail ({error})");
            return Err(error);
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02X}");
        out
    })
}
