//! A transport that keeps every exchange with the emulator, and the fuzz corpora written from them.

use std::{collections::BTreeSet, fs, path::Path};

use rdnie::{Error, Transport};

use super::EmulatedDnie;

/// Keeps every command and the raw response the emulator gave it.
pub struct Recorder {
    pub card: EmulatedDnie,
    pub exchanges: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Recorder {
    pub fn new(card: EmulatedDnie) -> Self {
        Self {
            card,
            exchanges: Vec::new(),
        }
    }
}

impl Transport for Recorder {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let response = self.card.transmit_raw(apdu)?;
        self.exchanges.push((apdu.to_vec(), response.clone()));
        Ok(response)
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.card.reset()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

/// Writes `seeds` into `fuzz/corpus/<target>`.
pub fn write_corpus(target: &str, seeds: BTreeSet<Vec<u8>>) {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target);
    fs::create_dir_all(&corpus).unwrap();
    for (index, seed) in seeds.into_iter().enumerate() {
        fs::write(corpus.join(format!("seed-{index}")), seed).unwrap();
    }
}
