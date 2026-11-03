# Extended onion controls and target-blind baseline: locked protocol

**Status before results:** this protocol and the fixed generic YARA expression are committed before the first extended browser capture. The experiment uses the same Tor Browser 16.0, GitHub-hosted Ubuntu 24.04 and Windows Server 2022 x86-64, AVML/WinPmem, and Volatility 3 2.28.2 setup as the preceding [onion study](onion-study-protocol.md).

## Question and unit

An independent fresh runner and whole-RAM image is one unit. Obtain three analyzable images for each OS × scenario cell, with a one-per-cell pilot before the remaining replicates. Five scenarios yield 30 analyzable images if all cells fill. Failed pre-capture or analysis attempts are recorded and replaced with fresh captures; they are never scored as negative detections. Report both attempt counts and conditional-on-analyzability results.

Every run starts a new v3 onion service and a separate Tor client daemon. Both must bootstrap, a SOCKS5h request to `/ready` must succeed, and Tor Browser must load `/landing`. The HTTP server counts requests to the randomized `/target/<token>` path separately from readiness, landing, and neutral-page requests. The target URL never enters the browser command line. The evaluator publishes hashes, counts, process coverage, and timings, but no raw RAM, target URL, extracted strings, or onion private keys.

## Conditions

| Scenario | Browser exposure before capture | Expected target requests |
| --- | --- | ---: |
| `absent` | Landing page omits target entirely | 0 |
| `text_only` | Target appears as visible paragraph text, without an anchor | 0 |
| `input_field` | Selenium types target into an initially empty text input; server HTML omits it | 0 |
| `background_link` | Landing page contains an unclicked target anchor, then a new foreground tab loads a neutral page while the link tab stays open | 0 |
| `clicked` | Browser clicks the target anchor and navigates to its URL | At least 1 |

The fixture verifies each presentation before acquisition. URL presence is an **outcome**, never a condition for accepting an analyzable image. An absent-scenario hit would likewise be reported rather than silently discarded. Protocol acceptance instead requires request truth to match the scenario, stable browser PIDs in the RAM `pslist`, both Tor daemon PIDs in `pslist`, and independent onion readiness/landing evidence. The original onion study's `link_only` condition remains a separate prior stratum; its raw images are unavailable for the new baseline.

## Methods and comparisons

The adapter scans every stable Tor Browser PID found in the image once. Its image-level outcome is whether it returns the exact randomized target URL as `E1:process_memory_string`. A fixed target-blind YARA regex scans the **same PIDs** in Volatility's VMA/VAD scanner, matching generic ASCII or UTF-16 v3 onion URLs with paths. It contains no run-specific hostname, target path, or token. Only after scanning do we compare matched bytes against the known target for scoring. Publish candidate counts, exact-target hit counts, image-level detection, and elapsed time for both methods. The previous exact-target YARA rule is not a discovery comparator and is omitted here.

The YARA rule is onion-specific while TorSessionTrace scans HTTP(S) URLs more generally, and the two scanners use different memory traversal and rendering paths. A time difference is descriptive, not an optimized speed ranking. Report per-cell fractions and Wilson 95% intervals without pooling transport or OS strata. Target-request ground truth establishes activity for the controlled fixture, not the causal origin of a particular memory copy or general visit reconstruction.

## Limits planned in advance

Only one browser version, headless use, a short capture interval, and same-host service/client daemons are tested. Raw memory is removed from the runner after analysis. A target-blind regex can still exploit the known **URL class** (v3 onion), so results do not cover arbitrary URL discovery. Clipboard-only, bookmark-only, browser-shutdown, remote-host onion service, and long-delay conditions remain distinct experiments; they are not silently inferred from these controls.
