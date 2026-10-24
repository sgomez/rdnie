//! A transport that keeps every exchange with the card, and the fuzz corpora written from them.

use std::{collections::BTreeSet, fs, path::Path};

use rdnie::{Atr, Error, Port, Transport};

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
    fn atr(&self) -> Result<Atr, Error> {
        self.card.atr()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Port) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let exchanges = &mut self.exchanges;
        self.card
            .transaction(|port| body(&mut Recording { port, exchanges }))
    }
}

/// The inner transport's port, keeping what passes through it.
struct Recording<'a> {
    port: &'a mut dyn Port,
    exchanges: &'a mut Vec<(Vec<u8>, Vec<u8>)>,
}

impl Port for Recording<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let response = self.port.transmit(apdu)?;
        self.exchanges.push((apdu.to_vec(), response.clone()));
        Ok(response)
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
