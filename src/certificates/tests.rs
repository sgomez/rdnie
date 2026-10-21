use crate::{
    Session,
    emulator::{DNIE_3_ATR, EmulatedDnie, HolderCertificate},
};

#[test]
fn pairs_each_certificate_with_the_file_of_its_key() {
    let certificates = [
        HolderCertificate::new(1, 120),
        HolderCertificate::new(2, 120),
    ];
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    let listed = Session::open(card).unwrap().certificates().unwrap();
    let files: Vec<[u8; 2]> = listed.iter().map(|c| c.key.file).collect();
    let expected: Vec<[u8; 2]> = certificates.iter().filter_map(|c| c.key_file).collect();
    assert_eq!(files, expected);
}
