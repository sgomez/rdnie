# Benchmark: rdnie, JMulticard and OpenSC

Run by the card's holder, by hand, with the same reader and card for all three:

```sh
just bench --runs 20            # rdnie, release build
just bench --all --runs 20      # rdnie reading every certificate, as JMulticard does
just bench-jmulticard --runs 20 # JMulticard 2.1
just bench-opensc --runs 20     # OpenSC's PKCS#11 module, file cache off
just bench-spy bench --runs 1   # PC/SC calls of one run; also bench-jmulticard, bench-opensc
```

Each run starts from a new connection and ends with the signature certificate in memory. `--sign` adds one signature after asking for the PIN, a single attempt; the timer starts after the PIN is typed.

- **Compare `total`.** The tools split the steps differently: JMulticard's `getDnie` resets the card and reads every certificate, and OpenSC reads behind its PKCS#11 calls when it chooses.
- **`total` leaves out process start-up**, the JVM's included; time the whole command for that.
- **OpenSC with `--file-cache`** keeps the system `opensc.conf`, and its disk cache answers runs after the first one: report it as a separate, warm result.
- **Publish only** these outputs, the reader model and the tool versions. `bench-spy` keeps only the call statistics; never publish raw `pcsc-spy` output, since its APDUs carry the holder's data.
