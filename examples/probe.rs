//! Manual probe for the card's holder: prints ATR, status words, labels, counts and pass/fail only;
//! `--verbose` also prints the holder's data, which must never leave the machine.
//! `--list` prints the reader names and stops; `--reader <name>` connects to that reader.
//! Every card step prints its elapsed time; a failing one prints its status word.
//!
//! Checking that opening a session does not reset the card:
//!
//! 1. With Firefox (through `OpenSC`) logged in with the DNIe, run the probe, then confirm Firefox
//!    still works with the card.
//! 2. Run `--leave-channel` twice in a row: it opens a session, runs `pin_retries()`, leaves its
//!    channel open and exits without a reset, so the second run starts on a card with a leftover
//!    channel and must still pass.

use rdnie::{
    Certificate, Error, HashAlgorithm, Holder, INTERMEDIATE_CA_LABEL, KeyGeneration, PcscTransport,
    Pin, SIGNATURE_LABEL, Session, Transport, describe_atr,
};
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs8::DecodePublicKey};
use sha2_010::{Digest, Sha256};
use std::time::Instant;
use x509_cert::{
    der::{Decode, Encode},
    ext::pkix::{KeyUsage, KeyUsages},
};

fn main() {
    if let Err(error) = run() {
        println!("stopped: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.iter().any(|argument| argument == "--list") {
        for reader in PcscTransport::readers()? {
            println!("reader: {reader}");
        }
        return Ok(());
    }
    let transport = match arguments.iter().position(|argument| argument == "--reader") {
        Some(index) => {
            let name = arguments.get(index + 1).ok_or(Error::NoReader)?;
            PcscTransport::connect(name)?
        }
        None => PcscTransport::connect_first_dnie()?,
    };
    println!("reader: {}", transport.reader());
    let atr = transport.atr()?;
    println!("{}", describe_atr(&atr));

    let mut session = timed("open", || Session::open(transport))?;
    println!("card: DNIe 3.0/4.0");
    if arguments
        .iter()
        .any(|argument| argument == "--leave-channel")
    {
        let retries = timed("pin_retries", || session.pin_retries())?;
        println!("retries: {retries}");
        println!("left the channel open, no reset");
        return Ok(());
    }
    let key_set = match session.key_generation() {
        KeyGeneration::First => "r1",
        KeyGeneration::Second => "r2",
        _ => "unknown",
    };
    println!("key set: {key_set}");

    let listed = timed("certificates", || session.certificates())?;
    println!("certificates: {}", listed.len());
    let signature = timed("certificate (signature)", || {
        session.certificate(SIGNATURE_LABEL)
    })?;
    println!(
        "signature certificate: {}",
        if signature.is_some() {
            "pass"
        } else {
            "fail (not found)"
        }
    );
    let intermediate = timed("certificate (intermediate CA)", || {
        session.certificate(INTERMEDIATE_CA_LABEL)
    })?;
    println!(
        "intermediate CA: {}",
        match intermediate {
            Some(der) if x509_cert::Certificate::from_der(&der).is_ok() => "pass",
            Some(_) => "fail (not X.509)",
            None => "fail (not found)",
        }
    );

    let mut certificates = Vec::with_capacity(listed.len());
    for certificate in listed {
        println!("label: {}", certificate.label);
        let Some(der) = session.certificate(&certificate.label)? else {
            println!("  certificate: fail (not found)");
            continue;
        };
        holder(
            &der,
            std::env::args().any(|argument| argument == "--verbose"),
        );
        certificates.push((certificate, der));
    }
    match timed("pin_retries", || session.pin_retries()) {
        Ok(retries) => {
            println!("component certificate: pass");
            println!("retries: {retries}");
        }
        Err(Error::PinBlocked) => {
            println!("component certificate: pass");
            println!("retries: 0 (blocked)");
            return Ok(());
        }
        Err(error) => {
            println!("component certificate or PIN channel: fail ({error})");
            return Err(error);
        }
    }

    if std::env::args().any(|argument| argument == "--sign") {
        sign(&mut session, &certificates)?;
    }
    Ok(())
}

/// Prints the elapsed time of a card step, and its error (status word included) if it fails.
fn timed<R>(step: &str, run: impl FnOnce() -> Result<R, Error>) -> Result<R, Error> {
    let start = Instant::now();
    let result = run();
    println!("{step}: {} ms", start.elapsed().as_millis());
    if let Err(error) = &result {
        println!("{step}: fail ({error})");
    }
    result
}

/// Signs a fixed digest with the signature key and checks the result against its certificate.
fn sign(
    session: &mut Session<PcscTransport>,
    certificates: &[(Certificate, Vec<u8>)],
) -> Result<(), Error> {
    let Some((certificate, der)) = certificates.iter().find(|(_, der)| is_signature(der)) else {
        println!("signature certificate: not found");
        return Ok(());
    };
    let retries = session.pin_retries()?;
    println!("retries before the PIN: {retries}");

    let pin = rpassword::prompt_password("PIN (not shown): ")
        .map_err(|error| Error::Transport(format!("cannot read the PIN: {error}")))?;
    let digest = Sha256::digest(b"rdnie probe");
    let signature = match session.sign(
        &digest,
        HashAlgorithm::Sha256,
        &certificate.key,
        Pin::new(pin),
    ) {
        Ok(signature) => signature,
        Err(error) => {
            println!("sign: fail ({error})");
            return Err(error);
        }
    };
    println!("sign: pass");
    let verified = verifies(der, &digest, &signature);
    println!(
        "local verification: {}",
        if verified { "pass" } else { "fail" }
    );
    Ok(())
}

/// Prints which holder fields the certificate yields; their values only when `verbose`.
fn holder(der: &[u8], verbose: bool) {
    let holder = match Holder::from_der(der) {
        Ok(holder) => holder,
        Err(error) => {
            println!("  holder: fail ({error})");
            return;
        }
    };
    let show = |field: &Option<String>| match field {
        Some(value) if verbose => format!("{value:?}"),
        Some(_) => "yes".to_owned(),
        None => "no".to_owned(),
    };
    println!(
        "  holder: name {}, first surname {}, second surname {}, number {}",
        show(&holder.name),
        show(&holder.first_surname),
        show(&holder.second_surname),
        show(&holder.number),
    );
}

fn is_signature(der: &[u8]) -> bool {
    x509_cert::Certificate::from_der(der)
        .ok()
        .and_then(|certificate| certificate.tbs_certificate.get::<KeyUsage>().ok().flatten())
        .is_some_and(|(_, usage)| usage.0.contains(KeyUsages::NonRepudiation))
}

fn verifies(der: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    let Ok(certificate) = x509_cert::Certificate::from_der(der) else {
        return false;
    };
    let Ok(spki) = certificate.tbs_certificate.subject_public_key_info.to_der() else {
        return false;
    };
    RsaPublicKey::from_public_key_der(&spki).is_ok_and(|key| {
        key.verify(Pkcs1v15Sign::new::<Sha256>(), digest, signature)
            .is_ok()
    })
}
