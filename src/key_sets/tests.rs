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
    for generation in [KeyGeneration::First, KeyGeneration::Second] {
        let pin = KeySet::for_generation(generation, Channel::Pin);
        let user = KeySet::for_generation(generation, Channel::User);
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

#[test]
fn resolves_the_idesp_into_a_key_generation() {
    let cases = [
        (Some("BMP000001"), KeyGeneration::First),
        (Some("BMP099999"), KeyGeneration::First),
        (Some("BMP100000"), KeyGeneration::First),
        (Some("BMP100001"), KeyGeneration::Second),
        (Some("BMP100002"), KeyGeneration::Second),
        (Some("BMP200000"), KeyGeneration::Second),
        (Some("TST000042"), KeyGeneration::Second),
        (Some("AAA000001"), KeyGeneration::First),
        (Some(""), KeyGeneration::Second),
        (None, KeyGeneration::Second),
    ];
    for (idesp, expected) in cases {
        assert_eq!(KeyGeneration::from_idesp(idesp), expected, "{idesp:?}");
    }
}

#[test]
fn selects_each_key_set_by_generation_and_channel() {
    let sets = [
        (KeyGeneration::First, Channel::Pin, &R1_PIN),
        (KeyGeneration::First, Channel::User, &R1_USER),
        (KeyGeneration::Second, Channel::Pin, &R2_PIN),
        (KeyGeneration::Second, Channel::User, &R2_USER),
    ];
    for (generation, channel, expected) in sets {
        assert!(std::ptr::eq(
            KeySet::for_generation(generation, channel),
            expected
        ));
    }
}
