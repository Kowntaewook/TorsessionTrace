# Real Tor v3 onion-service whole-RAM study

**Status:** completed controlled pilot with three analyzable, independent images per condition and OS. This is evidence for a narrowly bounded memory-string inference, not a population accuracy estimate or session reconstruction. The [pre-results protocol](onion-study-protocol.md) was committed before the first browser image. The [network preflight](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461383444) separately verified onion-service reachability before RAM experiments.

## Acquisition and independent ground truth

Each fresh GitHub-hosted runner created a new v3 onion service and a separate Tor SOCKS client daemon. A browser first loaded the onion landing page through that client. A local HTTP server behind the onion service counted only requests to the target path as target requests. In `absent`, the target URL was absent from the page; in `link_only`, it was shown but not clicked; in `clicked`, browser automation clicked it. SOCKS5h readiness requests used `/ready`, not the target path. The fixture required both Tor daemons to log bootstrap 100% before browsing. Every analyzable capture recorded one `/ready` and one browser `/landing` request, and both daemon PIDs appeared in Volatility's process list. Readiness needed 1–12 curl attempts across images. The Tor Browser executable and target URL hashes were recorded, while raw URLs and service keys stayed on the runner.

Tor Browser 16.0 ran headless on Ubuntu 24.04 or Windows Server 2022 x86-64. The Linux runners used Tor 0.4.9.11 and AVML; Windows used bundled Tor 0.4.9.15 and WinPmem. Volatility 3 2.28.2 analyzed whole-RAM images of 7.60–7.73 GB (Linux) or 11.81 GB (Windows). The adapters scanned all stable Tor Browser PIDs found in the image: 10 per Linux image and 9 per Windows image. All 18 images had distinct SHA-256 values, target URL hashes, and onion hostname hashes. In every analyzable image, no recorded browser PID was missing and the separate absent-control URL had zero hits.

## Results conditional on analyzability

| OS | Condition | Target URL detected / images | Target requests / images | Exact URL string hits, replicates 1–3 | Median all-browser-PID adapter time | Exact-target YARA detected / images |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| Linux | absent | 0/3 | 0/3 | 0, 0, 0 | 67.000 s | 0/3 |
| Linux | link only | 3/3 | 0/3 | 4, 5, 3 | 126.638 s | 3/3 |
| Linux | clicked | 3/3 | 3/3 | 27, 22, 30 | 117.155 s | 3/3 |
| Windows | absent | 0/3 | 0/3 | 0, 0, 0 | 118.823 s | 0/3 |
| Windows | link only | 3/3 | 0/3 | 14, 4, 13 | 132.930 s | 3/3 |
| Windows | clicked | 3/3 | 3/3 | 61, 54, 56 | 114.523 s | 3/3 |

All 18 analyzable images passed the scenario checks. For each OS separately, the Wilson 95% interval for 0/3 is **0.0000–0.5615** and for 3/3 is **0.4385–1.0000**. These wide bounds preclude a precise general detection or false-attribution rate. The categorical rule “an onion URL string in browser memory proves a request” would be wrong for all six controlled unclicked-link observations: the URL was present while the onion service recorded zero target requests. TorSessionTrace itself emits only `E1:process_memory_string`, not a visit decision. For clicked images, the service counter verifies a request in that condition; it does not identify which memory copy arose from that request.

The YARA diagnostic used Volatility's process-scoped scanner with the **exact known target URL**. It found the target in all 12 link-present images and none of the 6 absent images, like the adapter's binary result. YARA hit counts and times differ, but it is an oracle-assisted known-marker check rather than a blind URL discovery baseline or a fair speed comparison. Adapter medians include Volatility startup and symbol handling for a single invocation over every selected browser PID; OS hardware and process-memory contents differ.

## Technical attrition

The 18 analyzable images required **21 attempts**. Windows completed 9/9 on the first attempt. Linux completed 9/12: one `absent` and one `link_only` image were acquired, but Volatility `linux.pslist` returned no recorded browser PIDs; a later `link_only` attempt failed when Tor Browser could not load the onion landing page before acquisition. Fresh replacement attempts filled those cells. The [Linux pilot run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461754138), [Linux follow-up run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41463589825), [Windows pilot run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41463589861), and [Windows follow-up run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41465295644) retain the success and failure logs. The [manifest](../research-results/2026-11-02-onion-pilot/manifest.json) maps each result and technical failure to its exact job. Failed attempts are not classified as target-negative. Conditioning detection fractions on analyzability can bias them; the mechanisms of the Volatility failures and browser load failure were not established from retained data.

## Reproduction and limits

The [18 per-capture JSON files](../research-results/2026-11-02-onion-pilot/) and [aggregate](../research-results/2026-11-02-onion-pilot/aggregate.json) contain request counts, image and target hashes, process coverage, Tor daemon evidence, YARA diagnostics, and timings. Recompute the summary with:

```sh
python3 benchmarks/study_aggregate.py research-results/2026-11-02-onion-pilot/linux-*.json research-results/2026-11-02-onion-pilot/windows-*.json --expected-os linux windows --expected-replicates 3
```

The runner deletes the raw RAM image after analysis and does not upload the service private keys, onion hostname, target URL, or extracted strings. Reproduction therefore requires **new acquisitions**, not reanalysis of a fixed public corpus. The service and client ran on the same host as separate Tor processes; the fixture verified bootstrap, SOCKS5h reachability, browser landing requests, and target requests, but did not preserve packet-level circuit paths. The findings cover one browser version, two hosted OS configurations, headless use, and a short capture interval. They do not reconstruct `SessionHistory`, `Document`, `STREAM`, tabs, connections, or timestamps. A stronger paper still needs larger diverse samples, additional nonvisit controls, a blind discovery baseline, and independent context linking a specific URL to a request. The earlier [localhost-only study](study-results-2026-11-02.md) is a separate transport stratum and should not be pooled silently with this onion study.
