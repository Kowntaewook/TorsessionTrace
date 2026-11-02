# Paper plan: what TorSessionTrace can actually support

Status: **research plan, not a submission-ready manuscript**. The pre-results [localhost protocol](research-protocol.md) and [onion protocol](onion-study-protocol.md), their respective [localhost](study-results-2026-11-02.md) and [onion](onion-study-results-2026-11-03.md) results, and the study workflows are the evidence sources. Each transport stratum contains 18 analyzable images and required 21 attempts, including three Linux technical failures and replacements.

## Candidate claim

An unclicked URL rendered by Tor Browser can remain in its process memory and be recovered from a whole-RAM image. Therefore a process-memory URL hit, by itself, cannot establish that the browser requested that URL. TorSessionTrace expresses the narrower observation as `E1:process_memory_string` and makes the Windows and Linux acquisition and measurement repeatable.

This is a **measurement and evidentiary-boundary** contribution. In both analyzable studies, all 3 unclicked-link images per OS contained the URL with zero target HTTP requests. The onion study verified requests to a fresh v3 onion service through separate Tor daemons, but the Wilson interval for each 3/3 cell is still 0.4385–1.0000. URL extraction from Tor memory, YARA scanning, and attempts to infer activity from recovered HTTP artifacts have prior art. A new plugin name or another string scanner alone is not a novel forensic method.

## Draft research questions

- RQ1: Under controlled absent, unclicked-link, and clicked conditions, what fraction of independent Windows and Linux whole-RAM captures contain the exact target URL in the recorded Tor Browser processes, separately for localhost and v3 onion targets?
- RQ2: How often would the rule “URL string present means requested” yield a false visit attribution for the unclicked-link condition? The rule is evaluated as a hypothetical misuse; the plugin never issues a visit verdict.
- RQ3: How do selected-process scan times vary across independent captures and OS strata? The exact-target YARA scan is an oracle-assisted diagnostic, not a blind URL discovery benchmark.

## Methods and reporting checklist

1. Lock the scenario logic and record code revision, Tor Browser version and browser binary hash, acquisition tool, analysis host, and each image hash.
2. Acquire one fresh whole-system RAM image per independent scenario and replicate. Do not count three rescans of one image as three samples.
3. Use each fixture's HTTP server request counter as controlled request ground truth. Keep the restricted localhost relay and the separate-daemon v3 onion setup as distinct transport strata. The onion fixture verified bootstrap and SOCKS5h reachability, but did not preserve a packet-level circuit path.
4. Match recorded browser PIDs to Volatility `pslist`, scan every stable Tor Browser PID found, and retain missing-PID and protocol failures in the report.
5. Publish per-cell numerator/denominator, Wilson 95% intervals, hit counts, scan-time median and range, baseline availability, acquisition failures, and hashes. Avoid pooled accuracy or significance claims from a small convenience sample.
6. Release scripts and aggregate outputs. Explain that raw GitHub runner RAM is deleted and cannot serve as a fixed public evaluation corpus.

## Necessary work before a full research paper

- Increase independent captures across browser versions, OS versions, host sizes, realistic browsing conditions, and capture intervals. Both 3-per-cell matrices demonstrate feasibility and variability, not a population error rate.
- Repeat the onion experiment with a remote service host and preserve independent transport evidence where appropriate; the current service and client are separate daemons on the same runner.
- Include additional negative controls such as copied text, bookmark, background page, and browser shutdown. Change one factor at a time.
- Compare against a **blind** URL-discovery baseline with the same PID set and evaluation unit. A known-target YARA rule answers a different question.
- If claiming visit reconstruction, add and validate independent structural or network evidence that links the specific URL to a request and time window. Do not assume `SessionHistory`, `Document`, or `STREAM` objects are recoverable.
- For a peer-reviewable benchmark, build a consented, redistributable fixed memory corpus or a deterministic acquisition environment with enough public measurements to support replication. Investigate the six Linux technical failures across the two studies.

## Closest literature

- [Alfosail and Norris (2021), *Tor forensics: Proposed workflow for client memory artefacts*](https://wrap.warwick.ac.uk/id/eprint/168347/): prior Tor client memory workflow. Treat URL recovery itself as established prior work.
- [Choi et al. (2023), *Chracer: Memory analysis of Chromium-based browsers*](https://dfrws.org/presentation/chracer-memory-analysis-of-chromium-based-browsers/): explains the context missing from string search and uses Chromium object layouts; the approach has not been validated on Tor Browser by this project.
- [Kim et al. (2024), *Decrypting IndexedDB in private mode of Gecko-based browsers*](https://dfrws.org/presentation/decrypting-indexeddb-in-private-mode-of-gecko-based-browsers/): demonstrates a distinct, more structural Gecko memory contribution and describes earlier Tor memory work.
