# A URL in Memory Is Not a Visit: Two Controlled Tor Browser Whole-RAM Pilots

**Draft status, 2026-11-03:** feasibility and methods manuscript, **not submission ready**. The samples are small and the headless browsing conditions are constrained. Findings are restricted to the separately reported [localhost](study-results-2026-11-02.md) and [v3 onion](onion-study-results-2026-11-03.md) studies.

## Abstract

An exact URL string recovered from browser memory can originate from an unclicked link. We present TorSessionTrace, a Volatility 3 plugin that labels recovered Tor Browser URL strings as process-memory observations rather than visits, and two controlled whole-RAM pilots for Windows and Linux. One fixture used a restricted localhost SOCKS relay; the second used a fresh v3 onion service and separate Tor service and client daemons. In each fixture, three independent analyzable captures were obtained per OS and condition: target absent, target shown as an unclicked link, and target requested by clicking. An independent HTTP server counted target-path requests. In both fixtures and operating systems, the target was recovered in all three unclicked-link images per cell despite zero target requests, in all three clicked images with a recorded request, and in none of the absent images. Each 18-image fixture required 21 attempts, including three Linux technical failures and replacements. The observations refute the categorical rule “memory URL implies request” in these conditions. They do not measure a general error rate or reconstruct visits, sessions, tabs, connections, or time order.

## 1. Introduction

Volatile memory can retain browser data that is absent from persistent history. A recovered URL, however, has more than one possible source: an open page, an unclicked link, copied text, a cache, or a stale allocation. The forensic question is therefore not merely whether bytes exist, but what activity those bytes support. Prior Tor client memory work already used process and pattern analysis to recover artifacts [1]. Work on Chromium browser objects explains why string matches lack the context needed to infer visits [2]. Our pilot asks whether the ambiguity can be demonstrated and measured with fresh, ground-truthed Tor Browser whole-RAM images on two operating systems.

TorSessionTrace makes the observational level explicit. Its output records a PID, virtual offset, encoding, string type, and `E1:process_memory_string`. It does not output a `visited` verdict. The research contribution proposed here is a reproducible measurement of the gap between memory-string presence and independently observed requests, together with technical attrition. The plugin implementation alone is not claimed as a novel URL scanner.

## 2. Research questions

**RQ1.** How often is an exact target URL present in Tor Browser process memory when absent, rendered as an unclicked link, or requested after a click, separately for localhost and v3 onion fixtures?

**RQ2.** Would the interpretation “URL string present means requested” misclassify unclicked-link captures in this fixture?

**RQ3.** What is the measured all-browser-PID analysis time, and how often does the whole-RAM analysis pipeline fail before a target result is produced in each fixture?

## 3. Method

The [localhost](research-protocol.md) and [onion](onion-study-protocol.md) protocols were committed before their respective 3-per-cell results. Each job ran Tor Browser 16.0 headless on a fresh GitHub-hosted Ubuntu 24.04 or Windows Server 2022 x86-64 runner. A controller generated a random URL and started a local HTTP server. In `absent`, the target was omitted from the page; in `link_only`, it was rendered as an anchor but not clicked; in `clicked`, browser automation clicked it. The HTTP server counted target-path requests independently of TorSessionTrace. The localhost fixture used a local-only SOCKS5 relay that rejected nonlocal destinations and did not establish a Tor circuit. The onion fixture generated a new v3 onion service with separate Tor service and client daemons. It required both to log bootstrap 100%, verified SOCKS5h reachability with `/ready`, and recorded a browser `/landing` request; neither path was the target. The service and client ran on the same host, and packet-level circuit paths were not retained.

While Tor Browser was alive, AVML captured Linux whole RAM and WinPmem captured Windows whole RAM. Stable Tor Browser PIDs recorded before and after acquisition were matched to Volatility 3 `pslist` output. The appropriate TorSessionTrace adapter scanned all matched PIDs once per image. The exact target URL was compared with returned strings; a separate random URL absent from the browser page was a negative control. Volatility's process-scoped YARA scanner was also run with the exact known target as an oracle-assisted diagnostic. Its task is different from discovering arbitrary URLs.

The primary unit was an independently acquired image, rather than repeated scans of one image. Per transport, OS, and condition, we report the fraction of analyzable captures with a target hit and Wilson 95% intervals. Failed acquisitions or Volatility analyses were retained in failure manifests and excluded only from the conditional detection denominator. Runtime is one Volatility invocation over all selected browser PIDs, including startup and symbol handling. The [source workflows](../.github/workflows/), [localhost records](../research-results/2026-11-02/), and [onion records](../research-results/2026-11-02-onion-pilot/) permit recalculation; raw RAM, service keys, target URLs, and extracted strings were not uploaded.

## 4. Pilot results, by transport

The following first table describes the restricted localhost relay. The v3 onion results follow separately; the two strata are not pooled.

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

The onion fixture also required 21 attempts for 18 analyzable images. Windows produced 9/9 on the first attempt. Two failed Linux attempts lacked recorded browser PIDs in `pslist`; another could not load the onion landing page before acquisition. Fresh replacements filled these cells. Across both fixtures, failed attempts are technical failures, not target-negative observations. Their mechanisms remain undetermined and may affect which images are analyzable.

## 5. Discussion and threats to validity

The six controlled unclicked-link observations per fixture refute a categorical inference from a URL string hit to a request under these conditions. A URL in the `clicked` condition is also only a string observation; the independent server counter supports the condition's request, not a causal link between a particular memory copy and that request. Accordingly, these studies do not validate session, tab, connection, or temporal reconstruction.

Both fixtures are intentionally constrained: headless Tor Browser, one browser version, two GitHub-hosted OS configurations, and a short delay before capture. The onion service and client were separate Tor processes on the same host; bootstrap, SOCKS5h reachability, and HTTP request counts were checked, but packet-level paths were not retained. Per-cell sample size is three, intervals are wide, and Linux analyzability was imperfect. Runner hardware and memory allocation may vary, so OS runtime differences cannot be attributed solely to the adapters. The exact-target YARA rule is an oracle diagnostic, not a blind discovery baseline. Raw RAM is not released because it can contain unrelated runner secrets or personal data; a reader can reproduce new acquisitions but cannot reanalyze an identical public corpus. Prior Tor memory studies [1, 3] limit the novelty of URL recovery, and structural Gecko work [3] shows a different kind of contribution.

## 6. Conclusion and next study

In these pilots, a recovered Tor Browser URL string was compatible with both an observed request and an unclicked link. TorSessionTrace therefore reports the string and its memory location without claiming a visit. The next study should expand the number and diversity of independent images, test additional nonvisit sources and browser states, repeat the onion fixture with a remote service host and independent transport evidence, compare blind URL-discovery methods on the same capture units, and investigate the Linux analysis failures. A stronger visit claim would require corroborating structural or network evidence linked to the specific URL and time window.

## References

1. M. Alfosail and P. Norris, “[Tor forensics: Proposed workflow for client memory artefacts](https://wrap.warwick.ac.uk/id/eprint/168347/),” *Computers & Security* 106, 102311 (2021). DOI: 10.1016/j.cose.2021.102311.
2. G. Choi, J. Bang, S. Lee, and J. Park, “[Chracer: Memory analysis of Chromium-based browsers](https://dfrws.org/presentation/chracer-memory-analysis-of-chromium-based-browsers/),” *Forensic Science International: Digital Investigation* 46, 301613 (2023). DOI: 10.1016/j.fsidi.2023.301613.
3. D. Kim, S. Lee, and J. Park, “[Decrypting IndexedDB in private mode of Gecko-based browsers](https://dfrws.org/presentation/decrypting-indexeddb-in-private-mode-of-gecko-based-browsers/),” DFRWS USA (2024).
