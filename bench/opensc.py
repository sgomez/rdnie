"""OpenSC counterpart of `examples/bench.rs`: same steps through PKCS#11, same output, times only."""

import argparse
import atexit
import getpass
import os
import tempfile
import time

import PyKCS11

SIGNATURE_LABEL = "CertFirmaDigital"
# Without it OpenSC reads the files from its disk cache instead of the card after the first run.
NO_CACHE = """app default {
    framework pkcs15 { use_file_caching = no; }
    card_driver dnie { user_consent_enabled = no; }
}
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", default="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--sign", action="store_true")
    parser.add_argument("--file-cache", action="store_true", help="keep the system opensc.conf")
    args = parser.parse_args()
    if not args.file_cache:
        conf = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        conf.write(NO_CACHE)
        conf.close()
        atexit.register(os.unlink, conf.name)
        os.environ["OPENSC_CONF"] = conf.name
    print(f"tool: opensc {args.module}, file cache {'on' if args.file_cache else 'off'}")

    steps = {"connect + open": [], "labels": [], "certificate (signature)": [], "total": []}
    for _ in range(max(1, args.runs)):
        start = time.perf_counter()
        lib, session = open_session(args.module)
        opened = time.perf_counter()
        certificates = {
            session.getAttributeValue(handle, [PyKCS11.CKA_LABEL])[0]: handle
            for handle in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        }
        listed = time.perf_counter()
        if SIGNATURE_LABEL not in certificates:
            raise SystemExit("stopped: no signature certificate")
        session.getAttributeValue(certificates[SIGNATURE_LABEL], [PyKCS11.CKA_VALUE], allAsBinary=True)
        read = time.perf_counter()
        session.closeSession()
        lib.unload()
        for step, seconds in zip(steps, [opened - start, listed - opened, read - listed, read - start]):
            steps[step].append(seconds)
    for step, times in steps.items():
        summary(step, times)

    if args.sign:
        sign(args.module)


def open_session(module):
    lib = PyKCS11.PyKCS11Lib()
    lib.load(module)
    slots = lib.getSlotList(tokenPresent=True)
    if not slots:
        raise SystemExit("stopped: no card")
    return lib, lib.openSession(slots[0])


def sign(module):
    """One signature of fixed data in a fresh session, timed from C_Login to the result."""
    lib, session = open_session(module)
    certificate = session.findObjects(
        [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_LABEL, SIGNATURE_LABEL)]
    )[0]
    key_id = session.getAttributeValue(certificate, [PyKCS11.CKA_ID])[0]
    key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, key_id)])[0]
    pin = getpass.getpass("PIN (not shown): ")
    start = time.perf_counter()
    session.login(pin)
    session.sign(key, b"rdnie bench", PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS))
    summary("sign", [time.perf_counter() - start])
    session.logout()
    session.closeSession()
    lib.unload()


def summary(step, times):
    times = sorted(seconds * 1e3 for seconds in times)
    print(
        f"{step}: median {times[len(times) // 2]:.1f} ms, min {times[0]:.1f} ms, "
        f"max {times[-1]:.1f} ms ({len(times)} runs)"
    )


if __name__ == "__main__":
    main()
