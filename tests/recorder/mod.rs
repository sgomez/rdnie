//! A transport that keeps every exchange with the card, and the fuzz corpora written from them.

use std::{collections::BTreeSet, fs, path::Path};

use rdnie::{Error, Transport};

/// Keeps every command and the raw response the card gave it.
pub struct Recorder<T> {
    pub card: T,
    pub exchanges: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<T> Recorder<T> {
    pub fn new(card: T) -> Self {
        Self {
            card,
            exchanges: Vec::new(),
        }
    }
}

impl<T: Transport> Transport for Recorder<T> {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let response = self.card.transmit_raw(apdu)?;
        self.exchanges.push((apdu.to_vec(), response.clone()));
        Ok(response)
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        self.card.atr()
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
