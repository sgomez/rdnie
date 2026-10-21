use super::*;

struct Unplugged(EmulatedDnie, bool);

impl crate::Transport for Unplugged {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        if self.1 {
            return Err(Error::Transport("unplugged".to_owned()));
        }
        self.0.transmit_raw(apdu)
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
    let ders = |list: &[crate::Certificate]| list.iter().map(|c| c.der.clone()).collect::<Vec<_>>();
    assert_eq!(ders(&first), ders(&second));
    assert_eq!(first.len(), 2);
}

#[test]
fn a_fetch_after_a_listing_sends_nothing_to_the_card() {
    let mut session = open(listed_card());
    session.certificates().unwrap();
    let sent = session.transport.commands();
    assert!(session.certificate("CertFirma").unwrap().is_some());
    assert_eq!(session.transport.commands(), sent);
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
