# Tor Browser whole-RAM integration and benchmark — 2026-11-02

Two GitHub Actions runners launched **Tor Browser 16.0**, rendered a fresh random URL as an HTML link without opening that link, and captured the **entire machine's RAM while the browser was running**. Volatility 3 2.28.2 then found a browser PID in each full image through the native OS `pslist` plugin. TorSessionTrace scanned that PID through its OS-specific adapter. A second random URL, never inserted into the browser page, served as an absent control. The scripts required a positive rendered-link hit and zero absent-control hits; they repeated the successful PID scan three times and required identical counts.

| Measurement | Windows | Linux |
| --- | ---: | ---: |
| Passing run and aggregate result | [Windows run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41434692131) · [result](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41434692131/artifacts/13136545618) | [Linux run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41436080774) · [result](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41436080774/artifacts/13136358738) |
| Capture format and tool | WinPmem Go, sparse raw | AVML v0.21.0, uncompressed LiME |
| Image file bytes | 11,811,160,064 | 7,661,664,672 |
| Native `pslist` process count | 146 | 156 |
| Native `pslist` seconds | 70.869 | 11.238 |
| Selected Tor Browser process | `firefox.exe`, PID 1616 | `firefox.real`, PID 2524 |
| Adapter string hits per run | 883 | 2,295 |
| Rendered, unvisited link hits per run | 2 | 3 |
| Absent-control hits per run | 0 | 0 |
| Adapter run times, seconds | 14.389, 13.231, 13.026 | 22.035, 21.886, 21.753 |
| Median adapter time, seconds | **13.231** | **21.886** |

The Windows runner was Windows Server 2022. The [Windows workflow](../.github/workflows/tor-whole-windows.yml) compared the Tor Browser portable installer SHA-256 to the checksum list from the Tor Project archive, extracted it, and launched its `firefox.exe` on a local HTML page with a link-only control. It recorded ten browser PIDs by executable path. WinPmem captured a raw memory image; `windows.pslist` recovered all ten recorded PIDs. The validator scanned the recorded browser processes in sequence and found the control in PID 1616. The image SHA-256 was `d60cf356b12e0a8e6e510253185315a44b3009378bd9f7823fc4027465f1b49d`; the Tor Browser executable SHA-256 was `be563401b88e041c8cfdd42bdd594248993a29a19f77c61e850ad5406b61587a`.

The Linux runner was Ubuntu 24.04 with kernel `7.0.0-1017-azure`. The [Linux workflow](../.github/workflows/tor-whole-linux.yml) verified the Tor Browser and geckodriver OpenPGP signatures against the Tor Browser developer key, used Selenium to render a link-only control in `about:blank`, and recorded the browser process from geckodriver's descendant tree. AVML captured an uncompressed LiME image. A matching Volatility profile was generated from the running kernel's BTF and `System.map` with `btf2json`; the installed Volatility JSON schema was patched to accept BTF provenance as required by [btf2json's instructions](https://github.com/vobst/btf2json#volatility-patch). `linux.pslist` recovered the recorded PID 2524. The image SHA-256 was `b64954f79a109332700a73722ec50e1baf52c5f13815eab760da8e145231ed06`; the Tor Browser executable SHA-256 was `cdcd40436a4aef8e3583b1d95fa3b6c18bffe6f26921283e197052c56c8ae593`.

The benchmark timer includes Volatility command startup, symbol and layer setup, VAD/VMA traversal, and string extraction for **one selected browser PID**. It excludes initial image acquisition, native `pslist`, and other PIDs examined before the selected Windows PID. The raw Windows file is sparse and its logical length includes address gaps; it is not a measurement of scanned process bytes. These are three repeat analyses of one capture per OS, so the medians do not measure variation across captures or hosts.

This experiment demonstrates end-to-end extraction of **process-memory strings** from full RAM captures on both OS adapters. The control URL was rendered as a link and deliberately **not visited**. Therefore even a correct hit remains `E1:process_memory_string`; it does not establish a visit, connection, tab, session, or reconstruction of `SessionHistory`, `Document`, or `STREAM`. Neither test measures recall for visited URLs or onion services. The workflows upload only aggregate JSON and delete the raw captures on their runners.
