# A URL in Memory Is Not a Visit: Controlled Tor Browser Whole-RAM Studies

**Draft status, 2026-11-03:** controlled measurement manuscript, **not submission ready**. The locked 60-image separate-host matrix is complete, but headless browsing conditions and the absence of a redistributable fixed RAM corpus limit external validation. Findings are restricted to the separately reported [localhost](study-results-2026-11-02.md), [same-host v3 onion](onion-study-results-2026-11-03.md), [extended v3 onion](extended-study-results-2026-11-03.md), [separate-host pilot](remote-host-results-2026-11-03.md), and [separate-host replication](remote-replication-results-2026-11-03.md) strata.

## Abstract

An exact URL string recovered from browser memory can originate from content that never triggered a request to that URL. We present TorSessionTrace, a Volatility 3 plugin that labels recovered Tor Browser URL strings as process-memory observations rather than visits. Two initial Windows/Linux whole-RAM fixtures used restricted localhost and real v3 onion transport; each yielded 18 analyzable images, three per OS × absent, unclicked-link, or clicked condition. A pre-specified real-onion fixture added visible text, typed input, and an unclicked background-tab link, with 30 analyzable images and a target-blind generic v3-onion YARA comparator. A later locked separate-host replication selected 10 independent images per OS × absent/link/click cell, 60 from 78 client attempts across 13 service dispatches. The onion-service host independently counted randomized target-path requests. In the replication, the exact URL was recovered from all 20 unclicked-link images despite zero service-observed target requests, from all 20 clicked images with a request, and from none of 20 absent images. Generic YARA agreed with the plugin's binary target presence in 60/60 images. Five attempts failed technical criteria and 13 eligible images were surplus to the prespecified selection rule. The observations disprove the categorical rule “memory URL implies request” under the tested conditions. Each 10/10 cell has a Wilson 95% interval of 0.7225–1.0000; the study does not estimate a general error rate or reconstruct visits, sessions, tabs, connections, or time order.

## 1. Introduction

Volatile memory can retain browser data that is absent from persistent history. A recovered URL, however, has more than one possible source: an open page, an unclicked link, copied text, a cache, or a stale allocation. The forensic question is therefore not merely whether bytes exist, but what activity those bytes support. Prior Tor client memory work already used process and pattern analysis to recover artifacts [1]. Work on Chromium browser objects explains why string matches lack the context needed to infer visits [2]. This study asks whether the ambiguity can be demonstrated and measured with fresh, ground-truthed Tor Browser whole-RAM images on two operating systems.

TorSessionTrace makes the observational level explicit. Its output records a PID, virtual offset, encoding, string type, and `E1:process_memory_string`. It does not output a `visited` verdict. The research contribution proposed here is a reproducible measurement of the gap between memory-string presence and independently observed requests, together with technical attrition. The plugin implementation alone is not claimed as a novel URL scanner.

## 2. Research questions

**RQ1.** How often is an exact target URL present in Tor Browser process memory when absent, rendered as text, typed into a field, shown as an unclicked link, or requested after a click, separately by fixture and OS?

**RQ2.** Which controlled nonvisit exposures would the interpretation “URL string present means requested” misclassify?

**RQ3.** How does a fixed target-blind v3-onion YARA rule compare with TorSessionTrace on image-level target discovery and descriptive scan time over the same browser PIDs?

**RQ4.** Can an onion-service host on a separate runner provide request counters that match client whole-RAM measurements?

## 3. Method

The [localhost](research-protocol.md), [onion](onion-study-protocol.md), [extended](extended-study-protocol.md), [remote pilot](remote-host-protocol.md), and [locked remote replication](remote-replication-protocol.md) protocols were committed before their respective captures. Each client job ran Tor Browser 16.0 headless on a fresh GitHub-hosted Ubuntu 24.04 or Windows Server 2022 x86-64 runner. A controller generated a random URL and started an HTTP server. In `absent`, the target was omitted from the page; in `link_only`, it was rendered as an anchor but not clicked; in `clicked`, browser automation clicked it. The HTTP server counted target-path requests independently of TorSessionTrace. The localhost fixture used a local-only SOCKS5 relay that rejected nonlocal destinations and did not establish a Tor circuit. The onion fixtures generated a new v3 onion service with separate Tor service and client daemons. They required Tor bootstrap and SOCKS5h readiness, and recorded a browser `/landing` request; neither path was the target. The first onion fixtures placed both daemons on one host. The remote studies placed the service and clients on different hosted runners. Packet-level circuit paths were not retained.

The extended same-host onion fixture additionally placed the target as visible paragraph text without an anchor, typed it into a previously empty form field, or left an unclicked anchor in a background tab. Each OS × scenario cell had three independently acquired images. The separate-host pilot used one selected image per Linux/Windows × unclicked/clicked cell. The subsequent replication locked a new six-cell matrix with ten selected independent images per OS × absent/link/click cell and at most two full service-dispatch replacements per replicate. Each replicate generated a fresh onion service; the first technically eligible image by ascending service-run ID filled each cell, independent of the detection outcome. Service-side and client-reported counters were matched by service run and onion-hostname hash. These counters are not a full network capture.

While Tor Browser was alive, AVML captured Linux whole RAM and WinPmem captured Windows whole RAM. Stable Tor Browser PIDs recorded before and after acquisition were matched to Volatility 3 `pslist` output. The appropriate TorSessionTrace adapter scanned all matched PIDs once per image. The exact target URL was compared with returned strings; a separate random URL absent from the browser page was a negative control. The initial fixtures also used exact-target YARA as an oracle-assisted diagnostic. In the extended and remote fixtures, a fixed generic v3-onion URL regex contained no run-specific URL and scanned the same PIDs; target identity was applied only after scanning. This comparator is blind to the specific target but knows its URL class and uses a different scanner implementation.

The primary unit was an independently acquired image, rather than repeated scans of one image. Per fixture, OS, and condition, we report the fraction of analyzable captures with a target hit and Wilson 95% intervals for three- or ten-image cells. Failed acquisitions or Volatility analyses were retained in attempt records and excluded only from the conditional detection denominator; eligible surplus images were retained separately. Runtime is one Volatility invocation over all selected browser PIDs, including startup and symbol handling; `pslist` was timed separately. The [source workflows](../.github/workflows/), [localhost records](../research-results/2026-11-02/), [onion records](../research-results/2026-11-02-onion-pilot/), [extended records](../research-results/2026-11-03-extended/), and [remote replication records](../research-results/2026-11-03-remote-replication/) permit recalculation; raw RAM, service keys, target URLs, and extracted strings were not uploaded.

## 4. Pilot results, by transport and presentation

The first table describes the restricted localhost relay. The same-host and separate-host v3 onion results follow as distinct strata; no cross-stratum rate is calculated.

| OS | Condition | Target URL in memory | Target HTTP request | Median adapter time |
| --- | --- | ---: | ---: | ---: |
| Linux | absent | 0/3 | 0/3 | 115.623 s |
| Linux | link only | 3/3 | 0/3 | 112.215 s |
| Linux | clicked | 3/3 | 3/3 | 93.512 s |
| Windows | absent | 0/3 | 0/3 | 112.041 s |
| Windows | link only | 3/3 | 0/3 | 109.062 s |
| Windows | clicked | 3/3 | 3/3 | 111.544 s |

All 18 analyzable images had distinct hashes and random target URL hashes. Every analyzable image passed the scenario and absent-control checks. Each `3/3` detection estimate has a Wilson 95% interval of 0.4385–1.0000; each `0/3` estimate has 0.0000–0.5615. The exact-target YARA diagnostic agreed on binary target presence in all 18 images, but its use of the known answer prevents a claim that TorSessionTrace outperforms YARA as a discovery method. The per-capture counts and hashes are in the [result report](study-results-2026-11-02.md).

The localhost fixture's 18 analyzable images required 21 capture attempts. Windows produced 9/9 on the first attempt. Linux produced 6/9 initially. In two failed Linux attempts, Volatility `pslist` did not contain the recorded Tor Browser PIDs; in another, a selected PID had no process memory sections for scanning. Fresh replacement captures succeeded, leaving 9 analyzable images from 12 Linux attempts.

### v3 onion service

| OS | Condition | Target URL in memory | Target HTTP request | Median adapter time |
| --- | --- | ---: | ---: | ---: |
| Linux | absent | 0/3 | 0/3 | 67.000 s |
| Linux | link only | 3/3 | 0/3 | 126.638 s |
| Linux | clicked | 3/3 | 3/3 | 117.155 s |
| Windows | absent | 0/3 | 0/3 | 118.823 s |
| Windows | link only | 3/3 | 0/3 | 132.930 s |
| Windows | clicked | 3/3 | 3/3 | 114.523 s |

In the onion stratum, target-string hits by replicate were Linux `0,0,0` / `4,5,3` / `27,22,30` and Windows `0,0,0` / `14,4,13` / `61,54,56` for absent / link only / clicked. All 18 images had distinct image, target, and onion-hostname hashes; all stable browser PIDs and both Tor daemon PIDs appeared in Volatility's process list, and the absent-control URL had zero hits. Exact-target YARA agreed with binary target presence. The [onion result report](onion-study-results-2026-11-03.md) provides per-capture records and workflow logs.

The onion fixture also required 21 attempts for 18 analyzable images. Windows produced 9/9 on the first attempt. Two failed Linux attempts lacked recorded browser PIDs in `pslist`; another could not load the onion landing page before acquisition. Fresh replacements filled these cells. Across these first two fixtures, failed attempts are technical failures, not target-negative observations. Their mechanisms remain undetermined and may affect which images are analyzable.

### Extended same-host v3 onion conditions and target-blind baseline

The [extended report](extended-study-results-2026-11-03.md) supplies per-image hit counts, request truth, timings, and hashes. Its 30 selected images gave the following image-level results. The YARA column uses the generic rule frozen before acquisition and scored against the target after scanning.

| OS | Condition | TorSessionTrace target present | Generic YARA target present | Target requested | Median adapter / YARA time |
| --- | --- | ---: | ---: | ---: | ---: |
| Linux | absent | 0/3 | 0/3 | 0/3 | 89.751 / 23.230 s |
| Linux | visible text only | 3/3 | 3/3 | 0/3 | 92.120 / 23.392 s |
| Linux | typed input | 3/3 | 3/3 | 0/3 | 67.089 / 17.444 s |
| Linux | unclicked background link | 3/3 | 3/3 | 0/3 | 143.832 / 31.854 s |
| Linux | clicked | 3/3 | 3/3 | 3/3 | 123.201 / 28.966 s |
| Windows | absent | 0/3 | 0/3 | 0/3 | 109.778 / 59.248 s |
| Windows | visible text only | 3/3 | 3/3 | 0/3 | 113.784 / 69.010 s |
| Windows | typed input | 3/3 | 3/3 | 0/3 | 125.963 / 71.357 s |
| Windows | unclicked background link | 3/3 | 3/3 | 0/3 | 99.685 / 64.991 s |
| Windows | clicked | 3/3 | 3/3 | 3/3 | 116.722 / 69.451 s |

Thus, all 18 nonvisit exposure images held the exact URL with zero target requests. The two methods agreed on binary target presence in 30/30 selected images, though individual string-hit counts differed. Each 3/3 cell has a Wilson 95% interval of 0.4385–1.0000; each 0/3 cell has 0.0000–0.5615. Thirty analyzable images required 44 actual job attempts: ten pre-repair pilot jobs failed, including seven stopped by a validator argument bug; four later jobs failed due to PID visibility or browser navigation. The [attempt manifest](../research-results/2026-11-03-extended/manifest.json) records all 14 failures and replacements. Failed jobs are excluded from the conditional image-level fractions, so the results describe analyzable captures only.

### Separate-host v3 onion pilot

The [remote-host report](remote-host-results-2026-11-03.md) evaluates four selected client images against independent service-side request counters from different GitHub runner identities. Each unclicked cell showed a target string with zero target requests; each clicked cell showed a string and positive requests. The fourth service record reports two Windows-clicked target requests, matching its client. A failed `/finish` cleanup notification caused that service job to conclude failure, but its `finally` block and upload step preserved the counter artifact. The [aggregate](../research-results/2026-11-03-remote/aggregate.json) checks service run ID, onion-hostname hash, landing count, and target count for all four planned and five additional analyzable client images.

| Client OS | Condition | Planned images with target string | Service target requests | Adapter / target-blind YARA hits |
| --- | --- | ---: | ---: | ---: |
| Linux | unclicked link | 1/1 | 0 | 4 / 5 |
| Linux | clicked | 1/1 | 1 | 40 / 53 |
| Windows | unclicked link | 1/1 | 0 | 7 / 7 |
| Windows | clicked | 1/1 | 2 | 14 / 22 |

The one-per-cell pilot tests the cross-run measurement path; it cannot provide a meaningful detection-rate estimate. Across four service dispatches, 16 client jobs yielded nine analyzable images and seven technical failures. Five successful later captures are retained as descriptive extras rather than added to the planned denominator. The pilot has no absent-target condition or packet-level Tor circuit record.

### Locked separate-host v3 onion replication

The [pre-capture protocol](remote-replication-protocol.md) fixed six OS × condition cells, ten selected independent images per cell, technical eligibility, and replacement limits. The [full report](remote-replication-results-2026-11-03.md) and [aggregate](../research-results/2026-11-03-remote-replication/aggregate.json) record 60 selected whole-RAM images with unique image and target hashes. Every selected image passed protocol checks, including browser and client Tor PID visibility. The service and client counters agreed for each selected image.

| Client OS | Condition | TorSessionTrace target present | Target-blind YARA present | Service target requested | Wilson 95% interval for presence | Median adapter / YARA time |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Linux | absent | 0/10 | 0/10 | 0/10 | 0.0000–0.2775 | 110.725 / 27.265 s |
| Linux | unclicked link | 10/10 | 10/10 | 0/10 | 0.7225–1.0000 | 105.954 / 25.686 s |
| Linux | clicked | 10/10 | 10/10 | 10/10 | 0.7225–1.0000 | 93.516 / 24.085 s |
| Windows | absent | 0/10 | 0/10 | 0/10 | 0.0000–0.2775 | 114.670 / 73.655 s |
| Windows | unclicked link | 10/10 | 10/10 | 0/10 | 0.7225–1.0000 | 115.017 / 70.150 s |
| Windows | clicked | 10/10 | 10/10 | 10/10 | 0.7225–1.0000 | 119.695 / 71.153 s |

The two scanners agreed on binary target presence in 60/60 selected images. All 20 unclicked-link images contained the target string with no service-observed target request. All 20 clicked images had a service-observed request; all 20 absent images had neither string nor target request. This matrix required 78 client jobs over 13 service dispatches. Five client attempts failed technical criteria, including a protocol-failing Windows image excluded for a missing Tor PID; 13 technically eligible replacement images were surplus to the locked first-eligible selection rule. The intervals describe only analyzable captures in this controlled environment. Sequential scan times are descriptive and cannot establish scanner speed superiority.

## 5. Discussion and threats to validity

The controlled unclicked-link observations in the first two fixtures and in the 20-image separate-host replication, together with the 18 text-only, typed-input, and unclicked-background-link observations in the extended fixture, refute a categorical inference from a URL string hit to a request under these conditions. A URL in the `clicked` condition is also only a string observation; the independent server counter supports the condition's request, not a causal link between a particular memory copy and that request. Accordingly, these studies do not validate session, tab, connection, or temporal reconstruction.

All fixtures are intentionally constrained: headless Tor Browser, one browser version, two GitHub-hosted OS configurations, and a short delay before capture. The remote studies move the service to a separate runner, but no packet-level Tor circuit path was retained; one earlier pilot service job ended in failure after a cleanup notification was lost. The replication increased each cell to ten images, yet its Wilson intervals remain wide and the denominator conditions on technical analyzability. Workflow repairs occurred between attempts and are disclosed, but they limit simple comparability of technical failure rates. Runner hardware and memory allocation may vary, so OS runtime differences cannot be attributed solely to the adapters. The target-blind YARA rule is specific to v3-onion URL syntax and uses different scanner traversal; its shorter measured times do not establish a general speed advantage. Raw RAM is not released because it can contain unrelated runner secrets or personal data; a reader can reproduce new acquisitions but cannot reanalyze an identical public corpus. Prior Tor memory studies [1, 3] limit the novelty of URL recovery, and structural Gecko work [3] shows a different kind of contribution.

## 6. Conclusion and next study

Across the controlled pilots and completed separate-host replication, a recovered Tor Browser URL string was compatible with both an observed request and several forms of unrequested exposure. TorSessionTrace therefore reports the string and its memory location without claiming a visit. The next study should expand browser/OS diversity and capture timing, test bookmark-only, clipboard-only, shutdown, and delayed captures, repeat the locked matrix in another environment, broaden the target-blind baseline beyond onion syntax, and investigate analysis failures. A stronger visit claim would require corroborating structural or network evidence linked to the specific URL and time window.

## References

1. M. Alfosail and P. Norris, “[Tor forensics: Proposed workflow for client memory artefacts](https://wrap.warwick.ac.uk/id/eprint/168347/),” *Computers & Security* 106, 102311 (2021). DOI: 10.1016/j.cose.2021.102311.
2. G. Choi, J. Bang, S. Lee, and J. Park, “[Chracer: Memory analysis of Chromium-based browsers](https://dfrws.org/presentation/chracer-memory-analysis-of-chromium-based-browsers/),” *Forensic Science International: Digital Investigation* 46, 301613 (2023). DOI: 10.1016/j.fsidi.2023.301613.
3. D. Kim, S. Lee, and J. Park, “[Decrypting IndexedDB in private mode of Gecko-based browsers](https://dfrws.org/presentation/decrypting-indexeddb-in-private-mode-of-gecko-based-browsers/),” DFRWS USA (2024).
