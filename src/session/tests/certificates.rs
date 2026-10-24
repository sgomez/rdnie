use super::*;

struct Unplugged(EmulatedDnie, bool);

impl crate::Transport for Unplugged {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        if self.1 {
            return Err(Error::Transport("unplugged".to_owned()));
        }
        self.0.transmit_raw(apdu)
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        self.0.atr()
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.0.reset()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn crate::Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

fn listed_card() -> EmulatedDnie {
    EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&[
        HolderCertificate::new(1, 120).labelled("CertFirma"),
        HolderCertificate::new(2, 120).without_key(),
        HolderCertificate::new(3, 120).labelled("CertAutenticacion"),
    ])
}

#[test]
fn a_second_listing_sends_nothing_to_the_card() {
    let mut session = open(listed_card());
    let first = session.certificates().unwrap();
    let sent = session.transport.commands();
    let second = session.certificates().unwrap();
    assert_eq!(session.transport.commands(), sent);
    let labels =
        |list: &[crate::Certificate]| list.iter().map(|c| c.label.clone()).collect::<Vec<_>>();
    assert_eq!(labels(&first), labels(&second));
    assert_eq!(first.len(), 2);
}

#[test]
fn a_fetch_after_a_listing_reads_only_the_certificate_file() {
    let mut session = open(listed_card());
    session.certificates().unwrap();
    let selected = session.transport.selected().len();
    assert!(session.certificate("CertFirma").unwrap().is_some());
    let cdf = crate::emulator::CDF.to_vec();
    assert!(!session.transport.selected()[selected..].contains(&cdf));
    assert_eq!(certificate_files_selected(&session.transport), [1]);
}

#[test]
fn a_fetch_as_the_first_call_loads_the_certificates() {
    let mut session = open(listed_card());
    let sent = session.transport.commands();
    assert!(session.certificate("CertFirma").unwrap().is_some());
    assert!(session.transport.commands() > sent);
}

#[test]
fn a_failed_fetch_is_retried_on_the_next_call() {
    let mut session =
        Session::open_with_roots(Unplugged(listed_card(), false), ComponentRoots::embedded())
            .unwrap();
    session.transport.1 = true;
    assert!(matches!(
        session.certificate("CertFirma"),
        Err(Error::Transport(_))
    ));
    session.transport.1 = false;
    assert!(session.certificate("CertFirma").unwrap().is_some());
}

#[test]
fn a_failed_load_is_retried_on_the_next_call() {
    let mut session =
        Session::open_with_roots(Unplugged(listed_card(), false), ComponentRoots::embedded())
            .unwrap();
    session.transport.1 = true;
    assert!(matches!(session.certificates(), Err(Error::Transport(_))));
    session.transport.1 = false;
    assert_eq!(session.certificates().unwrap().len(), 2);
}

#[test]
fn listing_selects_no_certificate_file() {
    let mut session = open(listed_card());
    assert_eq!(session.certificates().unwrap().len(), 2);
    assert_eq!(certificate_files_selected(&session.transport), []);
}

#[test]
fn a_fetch_selects_only_that_certificate_file() {
    let mut session = open(listed_card());
    assert!(session.certificate("CertAutenticacion").unwrap().is_some());
    assert_eq!(certificate_files_selected(&session.transport), [3]);
}

#[test]
fn a_second_fetch_sends_nothing_to_the_card() {
    let mut session = open(listed_card());
    let first = session.certificate("CertFirma").unwrap();
    let sent = session.transport.commands();
    assert_eq!(session.certificate("CertFirma").unwrap(), first);
    assert_eq!(session.transport.commands(), sent);
}

#[test]
fn a_corrupt_certificate_fails_only_its_fetch() {
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&[
        HolderCertificate::new(1, 120).labelled("CertFirma"),
        HolderCertificate::not_x509(2, 120).labelled("CertRota"),
    ]);
    let mut session = open(card);
    assert_eq!(session.certificates().unwrap().len(), 2);
    assert!(matches!(
        session.certificate("CertRota"),
        Err(Error::MalformedCertificate)
    ));
    assert!(session.certificate("CertFirma").unwrap().is_some());
}

#[test]
fn a_failed_prkdf_read_keeps_the_cdf() {
    let card = listed_card().with_file(&crate::emulator::PRKDF, vec![0x00; 16]);
    let mut session = open(card);
    assert!(matches!(
        session.certificates(),
        Err(Error::MalformedPkcs15)
    ));
    let sent = session.transport.selected().len();
    assert!(session.certificate("CertFirma").unwrap().is_some());
    let cdf = crate::emulator::CDF.to_vec();
    assert!(!session.transport.selected()[sent..].contains(&cdf));
}

#[test]
fn a_failed_certificate_read_caches_nothing() {
    let mut session =
        Session::open_with_roots(Unplugged(listed_card(), false), ComponentRoots::embedded())
            .unwrap();
    session.certificates().unwrap();
    session.transport.1 = true;
    assert!(matches!(
        session.certificate("CertFirma"),
        Err(Error::Transport(_))
    ));
    session.transport.1 = false;
    assert!(session.certificate("CertFirma").unwrap().is_some());
}
