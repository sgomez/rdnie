# Benchmark: rdnie, JMulticard and OpenSC

From a new PC/SC connection to the signature certificate in memory, on the same DNIe and the same reader (Alcor Micro AU9540), Linux. Harnesses and how to run them: [`bench/`](../bench/README.md).

## Time

Median of 20 runs; min and max within 1 % of it except where noted.

| Tool | Total | vs rdnie |
| --- | --- | --- |
| rdnie at `b0761bb`, release build | 416 ms | |
| rdnie, every certificate (`--all`) | 830 ms | 2.0× |
| JMulticard 2.1 | 1323 ms | 3.2× |
| OpenSC, PKCS#11, file cache off | 1526 ms | 3.7× |

JMulticard's slowest run, 2917 ms, is most likely its first: class loading and JIT.

## PC/SC calls

One cold run under `pcsc-spy`.

| Tool | APDUs | In `SCardTransmit` | Rest of PC/SC | Outside PC/SC |
| --- | --- | --- | --- | --- |
| rdnie | 42 | 412 ms | 24 ms | ≈ 0 |
| rdnie `--all` | 72 | 826 ms | 15 ms | ≈ 0 |
| JMulticard | 84 | 1174 ms | 208 ms | 176 ms |
| OpenSC | 130 | 1521 ms | 18 ms | ≈ 0 |

## Reading

- **The gap is on the card.** rdnie spends 94 to 98 % of its time waiting for it, and sends half the APDUs of JMulticard and a third of OpenSC's.
- **The work is not the same.** rdnie reads the CDF, the PrKDF and the one certificate asked for. JMulticard's `getDnie` resets the card (its two connects and disconnects, 146 ms) and reads every certificate; OpenSC does all its reading before the first object call, which returns in 0.1 ms.
- **Same work:** reading every certificate, as JMulticard does, rdnie takes 830 ms, still 1.6× faster than JMulticard and 1.8× faster than OpenSC, with 72 APDUs to their 84 and 130.
