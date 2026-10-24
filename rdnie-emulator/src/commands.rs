//! How the emulated card answers each APDU.

use super::*;

impl EmulatedDnie {
    fn answer(&mut self, apdu: &Apdu) -> Vec<u8> {
        match apdu.ins {
            SELECT => self.select(apdu),
            READ_BINARY => self.read_binary(apdu),
            GET_CHALLENGE if self.faulty(HandshakeFault::RefusingChallenge) => vec![0x69, 0x85],
            GET_CHALLENGE => self.deliver(CHALLENGE.to_vec(), apdu.le),
            GET_RESPONSE
                if matches!(self.delivery, Delivery::EndlessPending)
                    || self.endless == Some(Endless::Pending) =>
            {
                vec![0x61, 0x05]
            }
            GET_RESPONSE if !self.pending.is_empty() => self.serve_pending(apdu.le.unwrap_or(256)),
            GET_RESPONSE => vec![0x69, 0x85],
            _ if self.chip.is_some() => self.authenticate(apdu),
            _ => vec![0x6D, 0x00],
        }
    }

    fn authenticate(&mut self, apdu: &Apdu) -> Vec<u8> {
        let refused = match (apdu.ins, apdu.p1, apdu.p2) {
            (GET_CHIP_INFO, _, _) => Some(HandshakeFault::RefusingChipInfo),
            (MSE, 0x81, 0xB6) => Some(HandshakeFault::RefusingMseVerifyCertificate),
            (PSO, 0x00, 0xAE) => Some(HandshakeFault::RefusingVerifyCertificate),
            (MSE, 0xC1, 0xA4) => Some(HandshakeFault::RefusingMseAuthentication),
            (INTERNAL_AUTHENTICATE, _, _) => Some(HandshakeFault::RefusingInternalAuthenticate),
            (EXTERNAL_AUTHENTICATE, _, _) => Some(HandshakeFault::RefusingExternalAuthenticate),
            _ => None,
        };
        if refused.is_some_and(|step| self.faulty(step)) {
            return vec![0x69, 0x85];
        }
        match (apdu.ins, apdu.p1, apdu.p2) {
            (GET_CHIP_INFO, _, _) => self.deliver(chip::SERIAL.to_vec(), apdu.le),
            (MSE, 0x81, 0xB6) | (PSO, 0x00, 0xAE) => vec![0x90, 0x00],
            (MSE, 0xC1, 0xA4) => self
                .chip_mut()
                .select_terminal(apdu.data)
                .to_be_bytes()
                .to_vec(),
            (INTERNAL_AUTHENTICATE, _, _) => match self.chip_mut().internal_authenticate(apdu.data)
            {
                Ok(answer) => self.deliver(answer, apdu.le),
                Err(status) => status.to_be_bytes().to_vec(),
            },
            (EXTERNAL_AUTHENTICATE, _, _) => {
                self.channel = self.chip_mut().external_authenticate(apdu.data, CHALLENGE);
                self.user_channel = self.chip_mut().user_terminal();
                if self.channel.is_some() {
                    vec![0x90, 0x00]
                } else {
                    vec![0x63, 0x00]
                }
            }
            (VERIFY, _, _) => vec![0x69, 0x82],
            _ => vec![0x6D, 0x00],
        }
    }

    fn answer_protected(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let mut channel = self.channel.take().expect("protected only with a channel");
        let Some(inner) = channel.unwrap(apdu) else {
            return Ok(vec![0x66, 0x88]);
        };
        let step = match (inner.ins, inner.p1, inner.p2) {
            (VERIFY, _, _) if inner.data.is_empty() => Some(Step::PinRetries),
            (VERIFY, _, _) => Some(Step::Verify),
            (MSE, 0x41, 0xB6) => Some(Step::Signing),
            _ => None,
        };
        if let Some(step) = step {
            self.strike(step)?;
        }
        if inner.ins == VERIFY {
            self.pin_queries.push(PinQuery {
                transaction: self.transactions,
                with_pin: !inner.data.is_empty(),
            });
        }
        let wrong_length = match self.endless {
            Some(Endless::WrongLength) => true,
            Some(Endless::WrongLengthOnPin) => inner.ins == VERIFY && !inner.data.is_empty(),
            _ => false,
        };
        let answer = if wrong_length {
            vec![0x6C, 0x05]
        } else if inner.ins == VERIFY {
            if inner.data.is_empty() {
                self.retries_status().to_be_bytes().to_vec()
            } else {
                let status = match self.verify_answer {
                    Some(status) => status,
                    None => self.verify_pin(&inner.data),
                };
                status.to_be_bytes().to_vec()
            }
        } else if (inner.ins, inner.p1, inner.p2) == (MSE, 0x41, 0xB6) {
            self.select_signing_key(&inner.data).to_be_bytes().to_vec()
        } else if (inner.ins, inner.p1, inner.p2) == (PSO, 0x9E, 0x9A) {
            self.sign(&inner.data)
        } else {
            let delivery = std::mem::replace(&mut self.delivery, Delivery::Direct);
            let answer = self.answer(&Apdu {
                ins: inner.ins,
                p1: inner.p1,
                p2: inner.p2,
                data: &inner.data,
                le: inner.le,
            });
            self.delivery = delivery;
            answer
        };
        let mut response = channel.wrap(&answer, self.response_shape);
        if inner.ins == READ_BINARY {
            if let Some(status) = self.unauthenticated_read.take() {
                response = with_status(answer[..answer.len() - 2].to_vec(), status);
            }
        }
        match self.channel {
            Some(_) => self.mark_last_handshake_inside_channel(),
            None => self.channel = Some(channel),
        }
        Ok(response)
    }

    /// A channel negotiated inside another replaces it once its last answer is wrapped.
    fn mark_last_handshake_inside_channel(&mut self) {
        if let Some(handshake) = self.chip_mut().handshakes.last_mut() {
            handshake.inside_channel = true;
        }
    }

    fn verify_pin(&mut self, pin: &[u8]) -> u16 {
        if self.user_channel {
            return 0x6982;
        }
        if self.retries == 0 {
            return 0x6983;
        }
        if pin == self.pin {
            self.pin_verified = true;
            self.retries = DEFAULT_RETRIES;
            return 0x9000;
        }
        self.retries -= 1;
        self.retries_status()
    }

    /// `MSE SET DST` data `84 02 <key file>`.
    fn select_signing_key(&mut self, data: &[u8]) -> u16 {
        match data {
            [0x84, 0x02, high, low] if self.holder_keys.contains_key(&[*high, *low]) => {
                self.signing_key = Some([*high, *low]);
                0x9000
            }
            _ => 0x6A88,
        }
    }

    /// PKCS#1 v1.5 signature of a `DigestInfo`, only in the user channel with the PIN verified.
    fn sign(&mut self, digest_info: &[u8]) -> Vec<u8> {
        if !self.user_channel || !self.pin_verified {
            return vec![0x69, 0x82];
        }
        let Some(key) = self
            .signing_key
            .and_then(|file| self.holder_keys.get(&file))
        else {
            return vec![0x69, 0x85];
        };
        let signature = key
            .sign(Pkcs1v15Sign::new_unprefixed(), digest_info)
            .expect("DigestInfo fits the holder key");
        with_status(signature, 0x9000)
    }

    fn retries_status(&self) -> u16 {
        match (self.retries_answer, self.retries) {
            (Some(status), _) => status,
            (None, 0) => 0x6983,
            (None, retries) => 0x63C0 | u16::from(retries),
        }
    }

    fn select(&mut self, apdu: &Apdu) -> Vec<u8> {
        match (apdu.p1, apdu.data) {
            (0x04, MASTER_FILE_NAME) => {
                self.current.clear();
                with_status(self.master_file_answer.clone(), 0x9000)
            }
            (0x00, &[high, low]) => {
                let mut path = self.current_df();
                path.push([high, low]);
                let announced = match self.files.get(&path) {
                    Some(file) => file.announced,
                    None if self.files.keys().any(|file| file.starts_with(&path)) => 0,
                    None => return vec![0x6A, 0x82],
                };
                let mut proprietary = vec![0x81, 0x02];
                proprietary.extend_from_slice(&u16::try_from(announced).unwrap().to_be_bytes());
                proprietary.extend_from_slice(&[0x82, 0x01, 0x01, 0x83, 0x02, high, low]);
                let mut fci = vec![0x6F, u8::try_from(proprietary.len()).unwrap()];
                fci.extend(proprietary);
                let answer = self.deliver(fci, apdu.le);
                // A `6Cxx` asks for the SELECT again, so the card stays where it was.
                if !matches!(answer.as_slice(), [0x6C, _]) {
                    self.selected.push(path.clone());
                    self.current = path;
                }
                answer
            }
            _ => vec![0x6A, 0x86],
        }
    }

    /// The selected path if it is a directory, or the directory holding the selected file.
    fn current_df(&self) -> Path {
        let mut path = self.current.clone();
        if self.files.contains_key(&path) {
            path.pop();
        }
        path
    }

    fn read_binary(&mut self, apdu: &Apdu) -> Vec<u8> {
        let Some(file) = self.files.get(&self.current) else {
            return vec![0x69, 0x86];
        };
        let offset = usize::from(u16::from_be_bytes([apdu.p1, apdu.p2]));
        if offset >= file.content.len() {
            return vec![0x6B, 0x00];
        }
        let wanted = apdu.le.unwrap_or(256);
        let end = file.content.len().min(offset + wanted);
        let data = file.content[offset..end].to_vec();
        if data.len() < wanted {
            with_status(data, 0x6282)
        } else {
            self.deliver(data, apdu.le)
        }
    }

    fn deliver(&mut self, data: Vec<u8>, le: Option<usize>) -> Vec<u8> {
        match self.delivery {
            Delivery::Direct => with_status(data, 0x9000),
            Delivery::GetResponse { .. } => {
                let announced = length_byte(data.len());
                self.pending = data;
                vec![0x61, announced]
            }
            Delivery::ExactLe if le == Some(data.len()) => with_status(data, 0x9000),
            Delivery::ExactLe => vec![0x6C, length_byte(data.len())],
            Delivery::EndlessPending => vec![0x61, 0x05],
        }
    }

    fn serve_pending(&mut self, le: usize) -> Vec<u8> {
        let Delivery::GetResponse { chunk } = self.delivery else {
            unreachable!("only get-response delivery leaves data pending")
        };
        let served: Vec<u8> = self
            .pending
            .drain(..le.min(chunk).min(self.pending.len()))
            .collect();
        match self.pending.len() {
            0 => with_status(served, 0x9000),
            left => with_status(served, 0x6100 | u16::from(length_byte(left))),
        }
    }
}

impl EmulatedDnie {
    /// Drops what a reset clears, whoever caused it.
    pub(crate) fn power_cycle(&mut self) {
        self.pending.clear();
        self.current.clear();
        self.channel = None;
        self.user_channel = false;
        self.pin_verified = false;
        self.signing_key = None;
        if let Some(chip) = &mut self.chip {
            chip.reset();
        }
    }
}

impl EmulatedDnie {
    /// Resets the card and returns its ATR, as a reader's reset would.
    ///
    /// # Errors
    ///
    /// [`Error::CardRemoved`] if the card left the reader.
    pub fn reset(&mut self) -> Result<Vec<u8>, Error> {
        if self.presence == Presence::Removed {
            return Err(Error::CardRemoved);
        }
        self.resets += 1;
        self.power_cycle();
        Ok(self.atr.clone())
    }

    fn receive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        if self.presence == Presence::Removed {
            return Err(Error::CardRemoved);
        }
        self.commands += 1;
        let protected = apdu.first().is_some_and(|cla| cla & PROTECTED == PROTECTED);
        if protected && self.channel.is_some() {
            if self.endless == Some(Endless::Pending) {
                return Ok(vec![0x61, 0x05]);
            }
            return match self.fault.take() {
                Some(Fault::Reset) => {
                    self.power_cycle();
                    Err(Error::CardReset)
                }
                Some(Fault::ChannelLost) => {
                    self.channel = None;
                    Ok(vec![0x66, 0x88])
                }
                Some(Fault::BadResponseMac) => {
                    let mut response = self.answer_protected(apdu)?;
                    let mac_end = response.len() - 3;
                    response[mac_end] ^= 0xFF;
                    Ok(response)
                }
                None => self.answer_protected(apdu),
            };
        }
        let Some(apdu) = parse(apdu) else {
            return Ok(vec![0x67, 0x00]);
        };
        if apdu.ins == EXTERNAL_AUTHENTICATE {
            if self.faulty(HandshakeFault::ResettingOnExternalAuthenticate) {
                self.power_cycle();
                return Err(Error::CardReset);
            }
            if self.faulty(HandshakeFault::FailingOnExternalAuthenticate) {
                return Err(Error::Transport("reader unplugged".to_owned()));
            }
        }
        if apdu.ins == SELECT && apdu.data == IDESP && self.current.is_empty() {
            self.strike(Step::Opening)?;
        }
        if apdu.ins == SELECT && apdu.data == pkcs15::CDF[1] && self.current == [pkcs15::CDF[0]] {
            self.strike(Step::Certificates)?;
        }
        if apdu.ins != GET_RESPONSE {
            self.pending.clear();
            // As a real DNIe, the first plain command in a channel gets `69 87` and drops the channel.
            if self.channel.take().is_some() {
                return Ok(vec![0x69, 0x87]);
            }
        }
        Ok(self.answer(&apdu))
    }
}

/// The emulated card while a transaction holds it.
struct InTransaction<'card>(&'card mut EmulatedDnie);

impl Port for InTransaction<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.receive(apdu)
    }
}

impl Transport for EmulatedDnie {
    fn atr(&self) -> Result<Vec<u8>, Error> {
        if self.presence == Presence::Removed {
            return Err(Error::CardRemoved);
        }
        Ok(self.atr.clone())
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Port) -> Result<R, Error>,
    ) -> Result<R, Error> {
        if self.presence == Presence::Removed {
            return Err(Error::CardRemoved);
        }
        self.transactions += 1;
        if self.retry_lost_between_transactions && !self.pin_queries.is_empty() {
            self.retry_lost_between_transactions = false;
            self.retries = self.retries.saturating_sub(1);
        }
        body(&mut InTransaction(self))
    }
}

fn parse(apdu: &[u8]) -> Option<Apdu<'_>> {
    let [_cla, ins, p1, p2, body @ ..] = apdu else {
        return None;
    };
    let (data, le) = match body {
        [] => (&[][..], None),
        [le] => (&[][..], Some(*le)),
        [lc, rest @ ..] if rest.len() == usize::from(*lc) => (rest, None),
        [lc, rest @ ..] if rest.len() == usize::from(*lc) + 1 => {
            let (data, le) = rest.split_at(usize::from(*lc));
            (data, Some(le[0]))
        }
        _ => return None,
    };
    Some(Apdu {
        ins: *ins,
        p1: *p1,
        p2: *p2,
        data,
        le: le.map(|le| if le == 0 { 256 } else { usize::from(le) }),
    })
}

fn length_byte(length: usize) -> u8 {
    u8::try_from(length % 256).expect("reduced modulo 256")
}

fn with_status(mut data: Vec<u8>, status: u16) -> Vec<u8> {
    data.extend_from_slice(&status.to_be_bytes());
    data
}
