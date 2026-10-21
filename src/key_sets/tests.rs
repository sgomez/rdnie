use rsa::traits::PublicKeyParts;

use super::*;

#[test]
fn every_key_set_loads_as_a_1024_bit_rsa_key() {
    for keys in [&R1_PIN, &R1_USER, &R2_PIN, &R2_USER] {
        assert_eq!(keys.private_key().size(), 128);
    }
}

#[test]
fn embeds_both_component_roots() {
    let roots = ComponentRoots::embedded();
    assert_eq!(roots.first.size(), 128);
    assert_eq!(roots.second.n().to_bytes_be(), COMPONENT_ROOT_2_MODULUS);
}

#[test]
fn pairs_the_user_set_with_the_pin_set_of_its_generation() {
    for idesp in [Some("BMP100000"), Some("BMP100001"), None] {
        let pin = KeySet::for_card(idesp, Channel::Pin);
        let user = KeySet::for_card(idesp, Channel::User);
        assert_eq!(pin.ca_chr, user.ca_chr);
        assert_ne!(pin.terminal_chr, user.terminal_chr);
    }
}

#[test]
fn the_emulator_carries_the_public_halves_of_every_key_set() {
    let halves: Vec<_> = crate::emulator::terminal_keys()
        .into_iter()
        .map(|key| (key.chr, key.modulus, key.user))
        .collect();
    let expected = [
        (&R1_PIN, false),
        (&R1_USER, true),
        (&R2_PIN, false),
        (&R2_USER, true),
    ]
    .map(|(keys, user)| (keys.terminal_chr, keys.modulus.to_vec(), user));
    assert_eq!(halves, expected);
}
