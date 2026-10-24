use super::*;

// Expected values computed with OpenSSL, independently of this module.
fn hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().unwrap()
}

#[test]
fn derives_session_keys_and_ssc() {
    let kicc: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    let kifd: [u8; 32] = std::array::from_fn(|i| u8::try_from((0x5A + 7 * i) % 256).unwrap());
    let channel = SecureMessaging::derive(
        &kicc,
        &kifd,
        array("11 22 33 44 55 66 77 88"),
        array("99 AA BB CC DD EE FF 00"),
    );
    assert_eq!(
        channel.kenc,
        array::<16>("22181f6f645783ce10463d5f7aa9c7cb")
    );
    assert_eq!(
        channel.kmac,
        array::<16>("ae823ff63e29f830a0525dcf97138c58")
    );
    assert_eq!(channel.ssc, 0x5566_7788_DDEE_FF00);
}

// ISO/IEC 9797-1 Annex B, MAC algorithm 3 with padding method 1.
#[test]
fn retail_mac_matches_iso_9797_example() {
    assert_eq!(
        retail_mac(&array("0123456789ABCDEF FEDCBA9876543210"))
            .chain_update(b"Now is the time for all ")
            .finalize()
            .into_bytes()[..],
        hex("A1C72E74EA3FA9B6")
    );
}

// Session keys and SSC from JMulticard's TestApduEncrypter; the SSC there is the
// already incremented one.
fn jmulticard_session() -> SecureMessaging {
    SecureMessaging {
        kenc: array("598f26e36e11a8ec14b81e19bda223ca"),
        kmac: array("5de2939a1ea03a930b88206d8f73e8a7"),
        ssc: 0xd31a_c8ec_7ba0_fe74,
    }
}

// JMulticard's vectors keep a 4-byte MAC; DNIe 3.0/4.0 sends all 8, whose first four match.
#[test]
fn protects_select_by_name() {
    let protected = jmulticard_session()
        .protect(&Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data: b"Master.File".to_vec(),
            le: None,
        })
        .unwrap();
    assert_eq!(
        protected.to_bytes().unwrap(),
        hex("0ca404001d 871101 3e9ac315a8e855dd3722f291078ac2bd 8e08 b6f56963ca2b8632")
    );
}

#[test]
fn protects_verify() {
    let mut channel = jmulticard_session();
    channel.ssc = 0xd31a_c8ec_7ba0_fe6e;
    let protected = channel
        .protect(&Command {
            cla: 0x00,
            ins: 0x20,
            p1: 0x00,
            p2: 0x00,
            data: b"CRYPTOKI".to_vec(),
            le: None,
        })
        .unwrap();
    assert_eq!(
        protected.to_bytes().unwrap(),
        hex("0c2000001d 871101 ce1ab937c332f3faee43336d4311ef33 8e08 6908df4e6eb3ceae")
    );
}

#[test]
fn protects_le_without_outer_le() {
    let protected = jmulticard_session()
        .protect(&Command {
            cla: 0x00,
            ins: 0x84,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
            le: Some(8),
        })
        .unwrap();
    assert_eq!(
        protected.to_bytes().unwrap(),
        hex("0c8400000d 970108 8e08 514f434b4e88a669")
    );
}

fn select(data: Vec<u8>) -> Command {
    Command {
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data,
        le: None,
    }
}

#[test]
fn encodes_long_cryptogram_with_ber_length() {
    let protected = jmulticard_session().protect(&select(vec![0; 130])).unwrap();
    assert_eq!(protected.data[..4], [0x87, 0x81, 0x89, 0x01]);
}

// Same session, after a protected command: the response is checked with SSC ...fe76.
fn answered_session() -> SecureMessaging {
    let mut channel = jmulticard_session();
    channel.ssc += 1;
    channel
}

fn protected_response(raw: &str) -> Response {
    Response::parse(&hex(raw)).unwrap()
}

const SHORT_RESPONSE: &str = "871901 065563852c30f15cf75a2ac2480a9cb05b1a590c9120a406 99029000 \
                              8e08 e21d201538257ab2 9000";

#[test]
fn unprotects_response_data() {
    let response = answered_session()
        .unprotect(&protected_response(SHORT_RESPONSE))
        .unwrap();
    assert_eq!(response.data, (1..=20).collect::<Vec<u8>>());
    assert_eq!(response.status, StatusWord::SUCCESS);
}

#[test]
fn takes_status_from_inner_status_word() {
    let response = answered_session()
        .unprotect(&protected_response("990263c3 8e08 0515cae12cef8ff4 9000"))
        .unwrap();
    assert_eq!(response.data, []);
    assert_eq!(response.status, StatusWord(0x63C3));
}

#[test]
fn unprotects_response_over_255_bytes() {
    let response = answered_session()
        .unprotect(&protected_response(
            "87820109017a49d26c2d17b79354b22ac4f004e790052c75b823269f8712819bf82c06ee567ebf42933b4a24c8e72aaa
             571197ec049f2d0665acfaf7064a3699a45b2ba596cbb63b0a2a6af6f73021737df2471546ae4817c4634bac26a27f89
             076572f4fdd8192d9a4548b918f3d70a9110c447e64e2f3db5fdc94acbbb7dc5d595ac053b4374e796d92e61243c08bf
             712e39a4ea0294813ca15e4cef88bc6d0a6c38f4bb305a823c20f58ea26ce87f2a84ebcdbdb8234ce8f1068ea5c0749c
             c028346c6e6f247edb4cda063da3a5f6377635f85e46da8272bcbdc46b8f63b6d676ec0b7d18dc27ebfa77cf7ea48604
             48b9fad8a90ee4ca97dcd5ca6555614753262b7be1d0bef6514d89e5d299029000
             8e08 048437e730b8db6a 9000",
        ))
        .unwrap();
    assert_eq!(response.data, (0..=255).collect::<Vec<u8>>());
}

#[test]
fn rejects_wrong_mac() {
    let tampered = SHORT_RESPONSE.replace("e21d201538257ab2", "e21d201538257ab3");
    assert!(matches!(
        answered_session().unprotect(&protected_response(&tampered)),
        Err(Error::SecureChannel(_))
    ));
}

#[test]
fn rejects_response_checked_with_another_ssc() {
    assert!(matches!(
        jmulticard_session().unprotect(&protected_response(SHORT_RESPONSE)),
        Err(Error::SecureChannel(_))
    ));
}

#[test]
fn rejects_response_without_mac() {
    assert!(matches!(
        answered_session().unprotect(&protected_response("99029000 9000")),
        Err(Error::SecureChannel(_))
    ));
}

#[test]
fn rejects_response_without_status_word() {
    assert!(matches!(
        answered_session().unprotect(&protected_response("8e08 e21d201538257ab2 9000")),
        Err(Error::SecureChannel(_))
    ));
}

#[test]
fn rejects_response_with_truncated_tlv() {
    assert!(matches!(
        answered_session().unprotect(&protected_response("871901 0655 9000")),
        Err(Error::SecureChannel(_))
    ));
}

#[test]
fn returns_plain_error_status_without_its_data() {
    let mut channel = answered_session();
    let response = channel.unprotect(&protected_response("0102 6982")).unwrap();
    assert_eq!(response.status, StatusWord(0x6982));
    assert_eq!(response.data, []);
    assert_eq!(channel.ssc, 0xd31a_c8ec_7ba0_fe76);
}

#[test]
fn reports_channel_lost_on_6688() {
    assert!(matches!(
        answered_session().unprotect(&protected_response("6688")),
        Err(Error::ChannelLost)
    ));
}

struct ScriptedCard {
    responses: Vec<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl Transport for ScriptedCard {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        self.sent.push(apdu.to_vec());
        Ok(self.responses.remove(0))
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![0x3B, 0x7F])
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        unreachable!("the codec never resets the card")
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

#[test]
fn resends_with_le_from_inner_6cxx() {
    let mut card = ScriptedCard {
        responses: vec![
            hex("99026c10 8e08 ef3d270b01ac5e01 9000"),
            hex("99029000 8e08 d22b55897ca31887 9000"),
        ],
        sent: vec![],
    };
    let response = SecureChannel::new(jmulticard_session(), &mut card)
        .transmit(&select(b"Master.File".to_vec()))
        .unwrap();
    assert_eq!(response.status, StatusWord::SUCCESS);
    assert!(card.sent[1].windows(3).any(|tlv| tlv == [0x97, 0x01, 0x10]));
}

#[test]
fn returns_other_inner_warnings_without_resending() {
    for status in [[0x62, 0x82], [0x61, 0x10], [0x63, 0xC2]] {
        let mut sender = jmulticard_session();
        let mut objects = vec![TAG_STATUS, 0x02, status[0], status[1]];
        sender.ssc += 2;
        let mac = sender.mac(&objects);
        push_tlv(&mut objects, TAG_MAC, &mac);
        objects.extend([0x90, 0x00]);
        let mut card = ScriptedCard {
            responses: vec![objects],
            sent: vec![],
        };
        let response = SecureChannel::new(jmulticard_session(), &mut card)
            .transmit(&select(b"Master.File".to_vec()))
            .unwrap();
        assert_eq!(response.status, StatusWord(u16::from_be_bytes(status)));
        assert_eq!(card.sent.len(), 1);
    }
}

#[test]
fn unprotects_the_card_side_response_in_every_length_form() {
    for (length, header) in [
        (0, &[TAG_STATUS, 0x02][..]),
        (8, &[TAG_CRYPTOGRAM, 0x09]),
        (128, &[TAG_CRYPTOGRAM, 0x81, 0x81]),
        (384, &[TAG_CRYPTOGRAM, 0x82, 0x01, 0x81]),
    ] {
        let plain: Vec<u8> = (0..length)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut channel = SecureMessaging::fixed();
        let raw = channel.protected_response(&plain, StatusWord(0x6282));
        assert_eq!(raw[..header.len()], *header, "{length}");
        let response = channel.unprotect(&Response::parse(&raw).unwrap()).unwrap();
        assert_eq!(response.data, plain);
        assert_eq!(response.status, StatusWord(0x6282));
    }
}

#[test]
fn protects_data_up_to_short_apdu() {
    let protected = jmulticard_session().protect(&select(vec![0; 255])).unwrap();
    assert_eq!(protected.cla, 0x0C);
}

#[test]
fn keeps_the_secure_messaging_bits_of_a_protected_cla() {
    for cla in [0x0C, 0x04, 0x08, 0x8C] {
        let protected = jmulticard_session()
            .protect(&Command {
                cla,
                ..select(b"Master.File".to_vec())
            })
            .unwrap();
        assert_eq!(protected.cla, cla | 0x0C, "{cla:02X}");
    }
}

#[test]
fn keeps_response_data_that_is_not_padded_whole() {
    for plain in [
        hex("0102030405060701"),
        hex("0000000000000000"),
        hex("8001020304050607 08090A0B0C0D0E0F"),
        hex("0102030405060780 0000000000000001"),
    ] {
        let mut channel = SecureMessaging::fixed();
        let raw = channel.protected_response(&plain, StatusWord::SUCCESS);
        let response = channel.unprotect(&Response::parse(&raw).unwrap()).unwrap();
        assert_eq!(response.data, plain);
    }
}

#[test]
fn strips_exactly_the_padding_of_response_data() {
    for (plain, data) in [
        ("0102030405060780", "01020304050607"),
        ("aabb800000000000", "aabb"),
        ("8000000000000000", ""),
        ("0102030405060708 8000000000000000", "0102030405060708"),
    ] {
        let mut channel = SecureMessaging::fixed();
        let raw = channel.protected_response(&hex(plain), StatusWord::SUCCESS);
        let response = channel.unprotect(&Response::parse(&raw).unwrap()).unwrap();
        assert_eq!(response.data, hex(data), "{plain}");
    }
}

/// The card's answers to commands protected with `card_side`, which follows the channel's SSC.
fn answers(card_side: &mut SecureMessaging, statuses: &[StatusWord]) -> Vec<Vec<u8>> {
    statuses
        .iter()
        .map(|&status| {
            card_side.ssc += 1;
            let answer = card_side.protected_response(&[], status);
            card_side.ssc += 1;
            answer
        })
        .collect()
}

#[test]
fn ends_an_endless_inner_wrong_length_with_its_status() {
    let mut card = ScriptedCard {
        responses: answers(&mut SecureMessaging::fixed(), &[StatusWord(0x6C05); 3]),
        sent: vec![],
    };
    let result = SecureChannel::new(SecureMessaging::fixed(), &mut card)
        .transmit(&select(b"Master.File".to_vec()));
    assert!(matches!(result, Err(Error::Status(StatusWord(0x6C05)))));
    assert_eq!(card.sent.len(), 3);
}

#[test]
fn refuses_raw_apdus_and_resets_inside_a_channel() {
    let mut card = ScriptedCard {
        responses: vec![],
        sent: vec![],
    };
    let mut channel = SecureChannel::new(SecureMessaging::fixed(), &mut card);
    assert!(matches!(
        channel.transmit_raw(&[0x00, 0xA4, 0x04, 0x00]),
        Err(Error::Transport(_))
    ));
    assert!(matches!(channel.reset(), Err(Error::Transport(_))));
    drop(channel);
    assert_eq!(card.sent.len(), 0);
}

#[test]
fn reads_the_atr_of_the_card_beneath_a_channel() {
    let mut card = ScriptedCard {
        responses: vec![],
        sent: vec![],
    };
    let channel = SecureChannel::new(SecureMessaging::fixed(), &mut card);
    assert_eq!(channel.atr().unwrap(), [0x3B, 0x7F]);
}

#[test]
fn runs_a_transaction_on_the_channel_itself() {
    let mut card = ScriptedCard {
        responses: answers(&mut SecureMessaging::fixed(), &[StatusWord::SUCCESS]),
        sent: vec![],
    };
    let mut channel = SecureChannel::new(SecureMessaging::fixed(), &mut card);
    let status = channel
        .transaction(|inside| Ok(inside.transmit(&select(b"Master.File".to_vec()))?.status))
        .unwrap();
    assert_eq!(status, StatusWord::SUCCESS);
}

#[test]
fn sends_the_commands_of_a_channel_opened_inside_another_to_the_card_beneath() {
    let outer = || SecureMessaging::derive(&[0x55; 32], &[0x66; 32], [0x77; 8], [0x88; 8]);
    let mut card_side = SecureMessaging::fixed();
    let handshake = select(b"Handshake".to_vec());
    let command = select(b"Master.File".to_vec());
    let expected = card_side.protect(&command).unwrap().to_bytes().unwrap();
    card_side.ssc -= 1;
    let mut responses = answers(&mut outer(), &[StatusWord::SUCCESS]);
    responses.extend(answers(&mut card_side, &[StatusWord::SUCCESS]));
    let mut card = ScriptedCard {
        responses,
        sent: vec![],
    };
    let response = SecureChannel::new(outer(), &mut card)
        .open_inside(|outer| {
            outer.transmit(&handshake)?.into_success()?;
            Ok(SecureMessaging::fixed())
        })
        .unwrap()
        .transmit(&command)
        .unwrap();
    assert_eq!(response.status, StatusWord::SUCCESS);
    assert_eq!(card.sent[1], expected);
}

#[test]
fn refuses_data_beyond_short_apdu() {
    assert!(matches!(
        jmulticard_session().protect(&select(vec![0; 256])),
        Err(Error::CommandTooLong(256))
    ));
}
