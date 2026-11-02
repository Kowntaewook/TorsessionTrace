# Research protocol: evidentiary limits of Tor Browser URL strings

Status: **pilot protocol**. This document specifies the analysis before the multi-capture results are interpreted. It is a reproducible experiment design, not a claim that the current data support publication.

## Questions and unit of analysis

1. When a URL is absent, displayed as an unclicked link, or successfully requested after a click, how often does TorSessionTrace recover that exact URL from Tor Browser process memory?
2. How often would the unsound rule “URL string hit means visit” mislabel the **unclicked-link** condition? TorSessionTrace itself makes no visit classification.
3. What is the per-capture analysis time on Windows and Linux when all recorded browser PIDs are examined?

The unit is **one independently captured whole-system RAM image** from a fresh GitHub Actions runner. Repeating analysis on the same image is a timing repeat, not an independent sample. A fresh random URL and browser process are created for each capture. Windows Server 2022 and Ubuntu 24.04 are separate strata; results must not be pooled without stating the OS mixture.

## Controlled conditions

| Condition | URL in landing page | Browser clicks link | Local HTTP server records target request | Expected interpretation |
| --- | --- | --- | --- | --- |
| `absent` | No | No | No | Negative control for browser-memory attribution |
| `link_only` | Yes | No | No | URL string may appear without a visit |
| `clicked` | Yes | Yes | Yes | Request verified; memory hit alone still lacks context |

The browser starts without the target URL on its command line. The Python controller creates the random target and runs a local HTTP server. Tor Browser's default proxy points to port 9150, so the fixture supplies a SOCKS5 relay that permits **only** the experiment's `127.0.0.1` HTTP port. External destinations are rejected. Thus `clicked` means a successful local HTTP request, **not** an onion-service or Tor-network connection. The server request count is the visit ground truth; the browser's URL and page rendering are separately checked. A second random URL is never inserted into the page and must remain absent from the selected browser processes.

## Acquisition and measurement

The [Linux workflow](../.github/workflows/study-linux.yml) uses AVML and a profile generated from the exact running kernel. The [Windows workflow](../.github/workflows/study-windows.yml) uses WinPmem. Both record live browser PIDs, capture RAM while the browser runs, execute Volatility's native `pslist`, and scan every recorded browser PID recovered from the image through the appropriate TorSessionTrace adapter. The [validator](../benchmarks/study_validate.py) writes aggregate JSON even if a scenario expectation fails. Raw RAM, control URLs, and extracted strings are never uploaded; the capture is deleted on the runner.

Primary outcomes per capture are exact-target detection in any recorded browser PID, target HTTP request count, absent-control hit count, and protocol pass/fail. Secondary outcomes are hit count, image SHA-256, process count, `pslist` time, and per-PID adapter time. [Aggregation](../benchmarks/study_aggregate.py) requires every expected OS/condition/replicate cell and reports per-condition detection proportions with Wilson 95% intervals. It does not discard protocol failures. The pilot uses one capture per cell; after pipeline validation, the planned next stage is three independent captures per cell. Such small samples are for feasibility and variability estimates, not a precise population accuracy claim.

## Limits before a paper claim

- A memory string is `E1:process_memory_string`. It is not a visit, tab, session, connection, or timestamp.
- A successful local HTTP request validates the `clicked` fixture, but the plugin does not link a particular memory copy of a URL to that request.
- This protocol does not measure `.onion` visits, real Tor circuit behavior, browser shutdown persistence, other Tor Browser versions, non-headless use, or other hardware. Those require separate fixtures.
- The raw images are not released because runner memory may contain unrelated sensitive material. Workflows, source, checksums, and aggregate outputs permit new captures, but do not provide a fixed public corpus.
- The three conditions alone cannot establish a novel visit classifier. A paper needs larger independent samples, suitable baseline methods, and a clearly bounded contribution relative to prior Tor memory forensics.

## Prior work to compare

- [Alfosail and Norris, *Tor forensics: Proposed workflow for client memory artefacts*, Computers & Security (2021)](https://wrap.warwick.ac.uk/id/eprint/168347/) already study Tor client memory with a Python-assisted workflow.
- [Choi et al., *Chracer: Memory analysis of Chromium-based browsers*, Forensic Science International: Digital Investigation (2023)](https://dfrws.org/wp-content/uploads/2024/04/Chracer-Memory-analysis-of-Chromiu_2023_Forensic-Science-International-Dig.pdf) explain why string matching lacks browser-object context. Chracer targets Chromium, so its object-recovery results cannot be transferred to Tor Browser without new evidence.
