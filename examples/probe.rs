//! Manual probe for the card's holder: prints ATR, status words, counts and pass/fail only.

use std::fmt::Write as _;

use rdnie::{
    Certificate, Error, HashAlgorithm, KeyGeneration, PcscTransport, Pin, Session, Transport,
};
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs8::DecodePublicKey};
use sha2_010::{Digest, Sha256};
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

/// Signs a fixed digest with the signature key and checks the result against its certificate.
fn sign(session: &mut Session<PcscTransport>, certificates: &[Certificate]) -> Result<(), Error> {
    let Some(certificate) = certificates.iter().find(|c| is_signature(&c.der)) else {
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
    let verified = verifies(&certificate.der, &digest, &signature);
    println!(
        "local verification: {}",
        if verified { "pass" } else { "fail" }
    );
    Ok(())
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02X}");
        out
    })
}
