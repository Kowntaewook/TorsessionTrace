# Paper plan: what TorSessionTrace can actually support

Status: **locked separate-host replication complete; manuscript not yet submission ready**. Evidence includes the pre-results [localhost](research-protocol.md), [same-host onion](onion-study-protocol.md), [extended onion](extended-study-protocol.md), [separate-host pilot](remote-host-protocol.md), and [separate-host replication](remote-replication-protocol.md) protocols, their linked results, and the study workflows. The first two strata each contain 18 analyzable images from 21 attempts; the extended stratum contains 30 from 44 actual jobs. The earlier separate-host pilot selected one image per OS × link/click cell. The independently locked replication selected 10 per OS × absent/link/click cell, **60/60 images from 78 client attempts**; older pilot images do not enter this denominator.

## Candidate claim

An unclicked URL rendered by Tor Browser can remain in its process memory and be recovered from a whole-RAM image. Therefore a process-memory URL hit, by itself, cannot establish that the browser requested that URL. TorSessionTrace expresses the narrower observation as `E1:process_memory_string` and makes the Windows and Linux acquisition and measurement repeatable.

This is a **measurement and evidentiary-boundary** contribution. In the two original studies, all 3 unclicked-link images per OS contained the URL with zero target HTTP requests. In the extended real-onion study, all 18 selected text-only, typed-input, or unclicked-background-link images contained the URL with zero target requests. In the locked separate-host replication, all 20 unclicked-link images contained the URL while the independent service recorded zero target requests. A fixed target-blind YARA rule agreed with the plugin on image-level target presence in all 30 extended and all 60 replication images, so the claim is not that the plugin uniquely discovers these strings. For each 10/10 replication cell, the Wilson 95% interval is 0.7225–1.0000. URL extraction from Tor memory and YARA scanning have prior art; a new plugin name or string scanner alone is not a novel forensic method.

## Draft research questions

- RQ1: Under absent, text-only, typed-input, unclicked-background-link, and clicked conditions, what fraction of independent Windows and Linux whole-RAM captures contain the exact target URL in recorded Tor Browser processes, separately by fixture?
- RQ2: Under which controlled nonvisit exposures would the rule “URL string present means requested” produce a false attribution? The rule is evaluated as a hypothetical misuse; the plugin never issues a visit verdict.
- RQ3: How do a fixed target-blind generic v3-onion YARA rule and TorSessionTrace compare on image-level target discovery across the same browser PIDs, and how do their descriptive scan times vary? The earlier exact-target YARA rule remains an oracle diagnostic.
- RQ4: Can an independent onion-service host provide request-ground-truth records matching browser-client results? The four-image pilot checked engineering feasibility; the 60-image locked replication provides conditional, per-cell descriptive fractions, not a population error rate.

## Methods and reporting checklist

1. Lock the scenario logic and record code revision, Tor Browser version and browser binary hash, acquisition tool, analysis host, and each image hash.
2. Acquire one fresh whole-system RAM image per independent scenario and replicate. Do not count three rescans of one image as three samples.
3. Use each fixture's HTTP server request counter as controlled request ground truth. Keep restricted localhost, same-host separate-daemon v3 onion, and separate-host v3 onion results as distinct strata. Bootstrap and SOCKS5h reachability were checked, but no packet-level circuit path was preserved.
4. Match recorded browser PIDs to Volatility `pslist`, scan every stable Tor Browser PID found, and retain missing-PID and protocol failures in the report.
5. Publish per-cell numerator/denominator, Wilson 95% intervals for both three- and ten-capture cells, hit counts, scan-time medians, baseline definition, failed and replacement jobs, and hashes. Avoid pooled accuracy or significance claims from convenience runner samples.
6. Release scripts and aggregate outputs. Explain that raw GitHub runner RAM is deleted and cannot serve as a fixed public evaluation corpus.

## Necessary work before a full research paper

- Increase independent captures across browser versions, OS versions, host sizes, realistic browsing conditions, and capture intervals. The completed 10-per-cell [separate-host matrix](remote-replication-results-2026-11-03.md) narrows uncertainty under one controlled setup but does not establish a population error rate.
- Independently audit the released service and client records and, ideally, repeat the locked design in another environment. The present records preserve all five failed client attempts, 13 surplus analyzable images, service request evidence, and source revisions; no post-start outcome-based exclusions were introduced.
- Include still-untested nonvisit sources and states such as bookmark-only, clipboard-only, browser shutdown, and long delay. Change one factor at a time.
- Extend the **target-blind** comparison beyond a generic v3-onion regex to broader URL discovery, with a frozen scoring protocol and the same PID/image unit. The current 30- and 60-image strata establish binary agreement on this URL class, not superiority of either scanner.
- If claiming visit reconstruction, add and validate independent structural or network evidence that links the specific URL to a request and time window. Do not assume `SessionHistory`, `Document`, or `STREAM` objects are recoverable.
- For a peer-reviewable benchmark, build a consented, redistributable fixed memory corpus or a deterministic acquisition environment with enough public measurements to support replication. Investigate the `pslist`/browser-PID misses and workflow failures across all strata; document the effect of conditional-on-analyzability selection.

The [local fixed-image pilot](fixed-corpus-2026-11-16.md) now retains three whole-RAM archives, exact hashes, complete output, and a replay procedure. It used synthetic loopback URLs in one Linux VM and does not add independent onion or Windows samples. The images remain private pending content and distribution review, so the public-corpus requirement above is still open.

## Closest literature

- [Alfosail and Norris (2021), *Tor forensics: Proposed workflow for client memory artefacts*](https://wrap.warwick.ac.uk/id/eprint/168347/): prior Tor client memory workflow. Treat URL recovery itself as established prior work.
- [Choi et al. (2023), *Chracer: Memory analysis of Chromium-based browsers*](https://dfrws.org/presentation/chracer-memory-analysis-of-chromium-based-browsers/): explains the context missing from string search and uses Chromium object layouts; the approach has not been validated on Tor Browser by this project.
- [Kim et al. (2024), *Decrypting IndexedDB in private mode of Gecko-based browsers*](https://dfrws.org/presentation/decrypting-indexeddb-in-private-mode-of-gecko-based-browsers/): demonstrates a distinct, more structural Gecko memory contribution and describes earlier Tor memory work.
