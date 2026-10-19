//! Checks that a reader holds a DNIe, without sending it any APDU.

fn main() {
    match rdnie::PcscTransport::connect_first_dnie() {
        Ok(_) => println!("DNIe found"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
