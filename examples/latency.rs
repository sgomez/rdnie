//! Latency probe for the card's holder (#145): per file, APDU counts, FCI length, DER extent and
//! time per instruction, never any data. `--reader <name>` connects to that reader.

use rdnie::{
    Atr, Error, INTERMEDIATE_CA_LABEL, PcscTransport, Port, SIGNATURE_LABEL, Session, Transport,
};
use std::{
    cell::RefCell,
    rc::Rc,
    time::{Duration, Instant},
};

const SELECT: u8 = 0xA4;
const READ_BINARY: u8 = 0xB0;
const GET_RESPONSE: u8 = 0xC0;
const COMPRESSION_HEADER: usize = 8;
const SWEEP: [u8; 5] = [1, 32, 64, 128, 222];
const SWEEP_RUNS: usize = 10;

fn main() {
    if let Err(error) = run() {
        println!("stopped: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    let arguments: Vec<String> = std::env::args().collect();
    let mut transport = match arguments.iter().position(|argument| argument == "--reader") {
        Some(index) => PcscTransport::connect(arguments.get(index + 1).ok_or(Error::NoReader)?)?,
        None => PcscTransport::connect_first_dnie()?,
    };
    println!("reader: {}", transport.reader());
    sweep(&mut transport)?;

    let log = Log::default();
    let transport = Counting {
        inner: transport,
        log: Rc::clone(&log),
    };
    let mut session = step("open", &log, || Session::open(transport))?;
    let labels = step("labels", &log, || session.labels())?;
    println!("certificates: {}", labels.len());
    step("certificate (signature)", &log, || {
        session.certificate(SIGNATURE_LABEL)
    })?;
    step("certificate (intermediate CA)", &log, || {
        session.certificate(INTERMEDIATE_CA_LABEL)
    })?;
    Ok(())
}

/// One APDU exchange; its data stays in memory and is never printed.
struct Exchange {
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    le: Option<u8>,
    response: Vec<u8>,
    sw: u16,
    elapsed: Duration,
}

impl Exchange {
    fn new(apdu: &[u8], response: &[u8], elapsed: Duration) -> Self {
        let (data, le) = match apdu.get(4..) {
            None | Some([]) => (vec![], None),
            Some([le]) => (vec![], Some(*le)),
            Some([lc, rest @ ..]) => {
                let lc = usize::from(*lc);
                (
                    rest.get(..lc).unwrap_or(rest).to_vec(),
                    rest.get(lc).copied(),
                )
            }
        };
        let split = response.len().saturating_sub(2);
        let byte = |index| apdu.get(index).copied().unwrap_or(0);
        Self {
            ins: byte(1),
            p1: byte(2),
            p2: byte(3),
            data,
            le,
            response: response[..split].to_vec(),
            sw: status_word(response),
            elapsed,
        }
    }
}

type Log = Rc<RefCell<Vec<Exchange>>>;

struct Counting {
    inner: PcscTransport,
    log: Log,
}

impl Transport for Counting {
    fn atr(&self) -> Result<Atr, Error> {
        self.inner.atr()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Port) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let log = Rc::clone(&self.log);
        self.inner
            .transaction(|port| body(&mut CountingPort { port, log }))
    }
}

struct CountingPort<'a> {
    port: &'a mut dyn Port,
    log: Log,
}

impl Port for CountingPort<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let start = Instant::now();
        let response = self.port.transmit(apdu)?;
        let elapsed = start.elapsed();
        self.log
            .borrow_mut()
            .push(Exchange::new(apdu, &response, elapsed));
        Ok(response)
    }
}

/// Runs a session step and reports its time, its APDUs and each file it read.
fn step<R>(name: &str, log: &Log, run: impl FnOnce() -> Result<R, Error>) -> Result<R, Error> {
    let from = log.borrow().len();
    let start = Instant::now();
    let result = run();
    let total = start.elapsed();
    let log = log.borrow();
    let exchanges = &log[from..];
    let on_the_wire: Duration = exchanges.iter().map(|exchange| exchange.elapsed).sum();
    println!(
        "{name}: {} ms, {} APDUs, {} µs outside the exchanges",
        total.as_millis(),
        exchanges.len(),
        total.saturating_sub(on_the_wire).as_micros()
    );
    if let Err(error) = &result {
        println!("{name}: fail ({error})");
    }
    for file in files(exchanges) {
        report(file);
    }
    result
}

/// Splits the exchanges at each SELECT by name, which starts every file read.
fn files(exchanges: &[Exchange]) -> Vec<&[Exchange]> {
    let mut starts: Vec<usize> = (0..exchanges.len())
        .filter(|&index| exchanges[index].ins == SELECT && exchanges[index].p1 == 0x04)
        .collect();
    if starts.first() != Some(&0) {
        starts.insert(0, 0);
    }
    starts.push(exchanges.len());
    starts
        .windows(2)
        .map(|bounds| &exchanges[bounds[0]..bounds[1]])
        .filter(|file| !file.is_empty())
        .collect()
}

fn report(file: &[Exchange]) {
    let selected: Vec<&[u8]> = file
        .iter()
        .filter(|exchange| exchange.ins == SELECT && exchange.p1 == 0x00)
        .map(|exchange| exchange.data.as_slice())
        .collect();
    let name = match selected.last().copied() {
        Some([0x00, 0x06]) => "IDESP",
        Some([0x60, 0x04]) => "CDF",
        Some([0x60, 0x01]) => "PrKDF",
        Some(_) => "certificate",
        None => "master file only",
    };
    let count = |ins| file.iter().filter(|exchange| exchange.ins == ins).count();
    let sw1 = |sw1| {
        file.iter()
            .filter(|exchange| exchange.sw >> 8 == sw1)
            .count()
    };
    println!(
        "  {name}: d {}, SELECT {}, GET RESPONSE {}, READ BINARY {}, 6Cxx {}, 6987 {}",
        selected.len(),
        count(SELECT),
        count(GET_RESPONSE),
        count(READ_BINARY),
        sw1(0x6C),
        file.iter().filter(|exchange| exchange.sw == 0x6987).count(),
    );
    if let Some(last) = file.iter().rfind(|exchange| exchange.ins == READ_BINARY) {
        lengths(name, file, last);
    }
    for (label, ins) in [
        ("SELECT", SELECT),
        ("GET RESPONSE", GET_RESPONSE),
        ("READ BINARY", READ_BINARY),
    ] {
        let mut times: Vec<Duration> = file
            .iter()
            .filter(|exchange| exchange.ins == ins)
            .map(|exchange| exchange.elapsed)
            .collect();
        times.sort();
        if let (Some(min), Some(max)) = (times.first(), times.last()) {
            println!(
                "    {label}: min {} / median {} / max {} µs",
                min.as_micros(),
                times[times.len() / 2].as_micros(),
                max.as_micros()
            );
        }
    }
    let total: Duration = file.iter().map(|exchange| exchange.elapsed).sum();
    println!("    file total: {} µs", total.as_micros());
}

fn lengths(name: &str, file: &[Exchange], last: &Exchange) {
    let le = last
        .le
        .map_or(0, |le| if le == 0 { 256 } else { usize::from(le) });
    let fci = usize::from(u16::from_be_bytes([last.p1, last.p2])) + le;
    let stopped = if matches!(last.sw, 0x6282 | 0x6B00) {
        format!(", stopped on {:04X}", last.sw)
    } else {
        String::new()
    };
    let content = content(file);
    println!(
        "    FCI length {fci}{stopped}, read {} bytes",
        content.len()
    );
    let extent = match name {
        "CDF" | "PrKDF" => directory_extent(&content),
        "certificate" => certificate_extent(&content),
        _ => return,
    };
    let trailing = content.get(extent..).unwrap_or_default();
    let kind = if trailing.is_empty() {
        "none"
    } else if trailing.iter().all(|&byte| byte == 0x00) {
        "all 00"
    } else if trailing.iter().all(|&byte| byte == 0xFF) {
        "all FF"
    } else {
        "mixed"
    };
    println!(
        "    DER extent {extent}, trailing {} ({kind})",
        fci.saturating_sub(extent)
    );
}

/// The bytes READ BINARY returned, with any GET RESPONSE that completed one.
fn content(file: &[Exchange]) -> Vec<u8> {
    let mut content = Vec::new();
    let mut reading = false;
    for exchange in file {
        match exchange.ins {
            READ_BINARY => reading = true,
            GET_RESPONSE => {}
            _ => reading = false,
        }
        let answered = matches!(exchange.sw, 0x9000 | 0x6282) || exchange.sw >> 8 == 0x61;
        if reading && answered {
            content.extend(&exchange.response);
        }
    }
    content
}

/// The bytes the consecutive SEQUENCEs at the start take, as `pkcs15::entries` decodes them.
fn directory_extent(content: &[u8]) -> usize {
    let mut at = 0;
    while content.get(at) == Some(&0x30) {
        match tlv_length(&content[at..]) {
            Some(length) if at + length <= content.len() => at += length,
            _ => break,
        }
    }
    at
}

/// The header plus the zlib bytes the inflater consumes, or the DER TLV if it does not inflate.
fn certificate_extent(content: &[u8]) -> usize {
    let stream = content.get(COMPRESSION_HEADER..).unwrap_or_default();
    let mut inflater = flate2::bufread::ZlibDecoder::new(stream);
    match std::io::copy(&mut inflater, &mut std::io::sink()) {
        Ok(_) => COMPRESSION_HEADER + usize::try_from(inflater.total_in()).unwrap_or(0),
        Err(_) if content.first() == Some(&0x30) => tlv_length(content).unwrap_or(0),
        Err(_) => 0,
    }
}

fn tlv_length(tlv: &[u8]) -> Option<usize> {
    let first = *tlv.get(1)?;
    let (header, length) = match first {
        0..=0x7F => (2, usize::from(first)),
        0x81 => (3, usize::from(*tlv.get(2)?)),
        0x82 => (
            4,
            usize::from(u16::from_be_bytes([*tlv.get(2)?, *tlv.get(3)?])),
        ),
        _ => return None,
    };
    Some(header + length)
}

/// Times READ BINARY of the CDF at each Le and fits time = a + c · Le.
fn sweep(transport: &mut PcscTransport) -> Result<(), Error> {
    transport.transaction(|port| {
        command(
            port,
            &[&[0x00, SELECT, 0x04, 0x00, 11][..], b"Master.File"].concat(),
        )?;
        command(port, &[0x00, SELECT, 0x00, 0x00, 0x02, 0x50, 0x15])?;
        command(port, &[0x00, SELECT, 0x00, 0x00, 0x02, 0x60, 0x04])?;
        let mut points = Vec::new();
        for le in SWEEP {
            if let Some(median) = median_read(port, le)? {
                println!("sweep Le {le}: median {median:.0} µs");
                points.push((f64::from(le), median));
            }
        }
        if let Some((a, c)) = fit(&points) {
            println!("sweep fit: a {a:.0} µs per exchange, c {c:.2} µs per byte");
        }
        Ok(())
    })
}

fn median_read(port: &mut dyn Port, le: u8) -> Result<Option<f64>, Error> {
    let mut times = Vec::with_capacity(SWEEP_RUNS);
    for _ in 0..SWEEP_RUNS {
        let start = Instant::now();
        let response = port.transmit(&[0x00, READ_BINARY, 0x00, 0x00, le])?;
        times.push(start.elapsed());
        let sw = status_word(&response);
        if sw != 0x9000 || response.len() != usize::from(le) + 2 {
            println!(
                "sweep Le {le}: {sw:04X}, {} bytes, skipped",
                response.len().saturating_sub(2)
            );
            return Ok(None);
        }
    }
    times.sort();
    Ok(Some(times[times.len() / 2].as_secs_f64() * 1e6))
}

/// Sends a SELECT, dropping a leftover channel once and completing `61xx`.
fn command(port: &mut dyn Port, apdu: &[u8]) -> Result<(), Error> {
    let mut sw = status_word(&port.transmit(apdu)?);
    if sw == 0x6987 {
        sw = status_word(&port.transmit(apdu)?);
    }
    if sw >> 8 == 0x61 {
        let [_, le] = sw.to_be_bytes();
        sw = status_word(&port.transmit(&[0x00, GET_RESPONSE, 0x00, 0x00, le])?);
    }
    if sw == 0x9000 {
        Ok(())
    } else {
        Err(Error::Transport(format!("sweep select answered {sw:04X}")))
    }
}

fn fit(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    let (mut n, mut sx, mut sy, mut sxx, mut sxy) = (0.0, 0.0, 0.0, 0.0, 0.0);
    for &(x, y) in points {
        n += 1.0;
        sx += x;
        sy += y;
        sxx += x * x;
        sxy += x * y;
    }
    let denominator = n * sxx - sx * sx;
    if points.len() < 2 || denominator == 0.0 {
        return None;
    }
    let c = (n * sxy - sx * sy) / denominator;
    Some(((sy - c * sx) / n, c))
}

fn status_word(response: &[u8]) -> u16 {
    match response {
        [.., sw1, sw2] => u16::from_be_bytes([*sw1, *sw2]),
        _ => 0,
    }
}
