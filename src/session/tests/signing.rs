use super::*;

#[test]
fn signs_digests_that_verify_with_the_certificate() {
    let data = b"document";
    let cases = [
        (
            HashAlgorithm::Sha256,
            Pkcs1v15Sign::new::<Sha256>(),
            Sha256::digest(data).to_vec(),
        ),
        (
            HashAlgorithm::Sha384,
            Pkcs1v15Sign::new::<Sha384>(),
            Sha384::digest(data).to_vec(),
        ),
        (
            HashAlgorithm::Sha512,
            Pkcs1v15Sign::new::<Sha512>(),
            Sha512::digest(data).to_vec(),
        ),
    ];
    let mut session = open(signing_card());
    let certificate = session.certificate("Cert1").unwrap().unwrap();
    for (algorithm, scheme, digest) in cases {
        let signature = sign_with(&mut session, &digest, algorithm).unwrap();
        verify(&certificate, scheme, &digest, &signature);
    }
}

#[test]
fn rejects_a_digest_of_another_length_before_any_apdu() {
    let mut session = open(signing_card());
    let key = session.certificates().unwrap().remove(0).key;
    let sent = session.transport.commands();
    let result = session.sign(
        &[0; 48],
        HashAlgorithm::Sha256,
        &key,
        Pin::new(DEFAULT_PIN.to_owned()),
    );
    assert!(matches!(
        result,
        Err(Error::DigestLength {
            expected: 32,
            actual: 48
        })
    ));
    assert_eq!(session.transport.commands(), sent);
}

#[test]
fn verifies_the_pin_in_a_fresh_transaction_after_reading_the_retries() {
    let mut session = open(signing_card());
    sign_with(&mut session, &[0; 32], HashAlgorithm::Sha256).unwrap();
    let queries = session.transport.pin_queries();
    let read = queries.iter().find(|query| !query.with_pin).unwrap();
    let verified = queries.iter().find(|query| query.with_pin).unwrap();
    assert!(read.transaction < verified.transaction);
}

#[test]
fn opens_the_user_channel_inside_the_pin_channel() {
    let (result, card) = sign_with_pin(signing_card(), DEFAULT_PIN);
    result.unwrap();
    let [pin_channels @ .., user_channel] = card.handshakes() else {
        panic!("no handshake");
    };
    assert!(user_channel.inside_channel);
    assert!(
        pin_channels
            .iter()
            .all(|handshake| !handshake.inside_channel)
    );
}

#[test]
fn signing_with_a_listed_key_reads_no_certificate_file() {
    let mut session = open(signing_card());
    sign_with(&mut session, &[0; 32], HashAlgorithm::Sha256).unwrap();
    assert_eq!(certificate_files_selected(&session.transport), []);
}
