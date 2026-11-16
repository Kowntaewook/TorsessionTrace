# Local fixed-image pilot, 16 November 2026

**Status:** three privately retained, replayable Linux whole-RAM images. This is an engineering pilot, not a public corpus or an additional independent sample for the onion studies.

## What was captured

On an Apple Silicon Mac, QEMU 11.1.3 ran an x86-64 Ubuntu 24.04.5 Minimal VM with two virtual CPUs and 1536 MiB RAM. Tor Browser 16.0.1 ran headless inside it. The fixture started a SOCKS relay restricted to its loopback HTTP server and gave each condition a new random target URL. The server recorded HTTP GETs in a separate append-only journal. Proxy connection logs were not retained, so this pilot does not establish which loopback requests traversed the relay. No Tor circuit or onion service was used. `absent` did not place the target on the page; `link_only` rendered a link without clicking it; `clicked` clicked the link and checked navigation. Each condition started a new browser process. The capture order in the clean VM was **link_only, clicked, absent**. These images share one VM and are not independent host samples.

QEMU's `dump-guest-memory` saved a physical-memory ELF while the browser was held open. The host then checked journal stability across capture, matched all recorded browser PIDs with Volatility `linux.pslist`, and ran TorSessionTrace over those PIDs. The complete `pslist` and hit JSON, control record, journal, result JSON, exact Linux symbol table, image hash, and a zstd archive are retained privately. The archive was decompressed and checked against the raw image hash before the raw temporary copy was removed. [Capture and replay instructions](../benchmarks/fixed_corpus/README.md) are in the repository.

## Observations

| Condition | Target GETs | Exact target hits | Browser PIDs found / recorded | Adapter scan time | ELF SHA-256 | zstd SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| absent | 0 | 0 | 10/10 | 98.390 s | `b41ab8cfe5a2c94f549c91c962c5434a678bf707d982d8ee0b4d26319d95ef90` | `75c9d2138747c25ac65348dcb9a56614125894605ce01dbc8523b21b89ee7e0d` |
| link_only | 0 | 4 | 10/10 | 104.516 s | `89191ae2899d118c9c08b8c9ec04d82f49e46937e803b292c1348138253f77ae` | `eff04817223eb71b8f2ea17def22cf53949f01439e1145129ec74debd7bdef94` |
| clicked | 1 | 40 | 10/10 | 97.637 s | `ff017f70509e5ae4a022076710f2eb4b5efd63a952c935284b6d53ec0f28d496` | `a62e5c2dc3e74c590916c403495efea7fe9652d0aae57145ae1abfa745774119` |

Every protocol check passed; the separate absent-control URL had zero hits in every image. All **3/3 clean-VM archives passed independent replay**: their restored ELF hashes, complete process/hit JSON, and stable result fields matched the first analyses. Each ELF was 1,627,523,139 bytes. The compressed archives were 448,791,613, 458,883,151, and 448,962,763 bytes in table order. Scan times include one adapter invocation over all ten selected PIDs, but not the separate `pslist` call, archive work, or QEMU capture. There is one measurement per condition, on a laptop under differing load, so the times are descriptive only. The HTTP journal establishes whether this fixture received a target GET; it cannot assign any particular memory copy to the request.

## Input provenance and replay

- [Ubuntu Minimal cloud image](https://cloud-images.ubuntu.com/minimal/releases/noble/release/) SHA-256: `406630c08b5e545fcc7209854b129d47e3af822db128c9f19336593b5a2d3fe0`, checked against Ubuntu's published `SHA256SUMS`.
- Tor Browser 16.0.1 Linux x86-64 archive SHA-256: `5b36ad610c20c81faa72caf27d1cd3a11f14a327c320b4cec581400016ba78b0`, downloaded from the [La Cebolla mirror listed by Tor Project](https://support.torproject.org/tor-browser/getting-started/downloading/). Its detached signature and the matching geckodriver archive signature verified with the Tor Browser Developers key, fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`. The geckodriver archive SHA-256 was `bf39579b3623fb0fa12dabfda2ca57ffba9aab4faef66b5e12a9922821027a28`.
- Guest kernel: `6.8.0-147-generic`. Its btf2json 0.1.0 Volatility symbol file SHA-256: `1b2966e265c36f3ddae7138597681d618dc65c56d4bac9571cbd5f450f12afb8`. Volatility 3 was 2.28.2; browser executable SHA-256 was `cdcd40436a4aef8e3583b1d95fa3b6c18bffe6f26921283e197052c56c8ae593`.
- Each private `capture-manifest.json` also hashes the complete control, journal, process table, hits, result, and source files. Replay checks those hashes, decompresses the unchanged ELF, reruns Volatility, and compares stable result fields and complete process/hit JSON.

The [public, URL-free manifest](../research-results/2026-11-16-fixed-corpus/manifest.json) contains the three case hashes, measurements, and source hashes in machine-readable form. It is an index to private images, not a substitute for the images and full journals.

The first `absent` pilot used an earlier cloud-init SSH key whose public comment contained a personal host name. Its image was retained **outside** this three-image clean-VM table. The initial QMP socket path was also too long; no RAM was produced on that attempt. That pilot's later capture passed after a writable Volatility cache was specified and space was freed for compression; its original raw-image hash and replay result are recorded privately. A later clean-VM boot failed because cloud-init did not discover a seed attached as a CD-ROM. Reattaching it as a virtio drive and booting a fresh overlay resolved the issue. These are setup failures, not negative detections.

## Release and interpretation limits

The three archives remain in a private workspace pending a whole-image content and redistribution audit. Their hashes and scripts are public, but outsiders cannot yet independently rerun these exact bytes. The clean VM used only disposable experiment credentials and synthetic targets; that design lowers exposure risk but does not itself certify a RAM image for release. The images contain executable and profile data from third-party software. A future public corpus needs documented content review and distribution terms, or fresh captures built for that purpose.

This pilot confirms the local archive/replay pipeline and provides another controlled example of an unclicked URL in browser memory with no target GET. It does not increase the sample size of the prior Windows/Linux onion experiments, estimate population accuracy, prove a visit from a string, or validate structural session reconstruction.
