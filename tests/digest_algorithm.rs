//! The length of the digest each algorithm produces.

use rdnie::DigestAlgorithm;

#[test]
fn reports_the_digest_length_of_each_algorithm() {
    assert_eq!(DigestAlgorithm::Sha256.digest_length(), 32);
    assert_eq!(DigestAlgorithm::Sha384.digest_length(), 48);
    assert_eq!(DigestAlgorithm::Sha512.digest_length(), 64);
}
