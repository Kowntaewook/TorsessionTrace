# A URL in Memory Is Not a Visit: A Controlled Tor Browser Whole-RAM Pilot

**Draft status, 2026-11-02:** feasibility and methods manuscript. The sample is too small and the browsing condition too artificial for a full empirical paper. Findings are restricted to the [recorded pilot](study-results-2026-11-02.md).

## Abstract

URL strings recovered from browser memory are often treated as evidence of browsing activity, although their origin may be a link that was only rendered. We present TorSessionTrace, a Volatility 3 plugin that labels recovered Tor Browser URL strings as process-memory observations rather than visits, and a controlled whole-RAM protocol for Windows and Linux. Each operating system was tested with three independent analyzable captures in each of three conditions: target absent, target shown as an unclicked link, and target requested by clicking. A separate localhost HTTP server supplied request ground truth. In both operating systems, the target was recovered in all three unclicked-link images despite zero target requests, and in all three clicked images with an observed local request. No target was recovered in the absent images. Three additional Linux attempts failed during Volatility process identification or mapping and were replaced; these are reported as technical attrition. The observations demonstrate a false visit attribution under the simple rule “URL string implies request” in this controlled setting. They do not establish a general error rate, recover browser sessions, or test actual Tor circuits or onion services.

## 1. Introduction

Volatile memory can retain browser data that is absent from persistent history. A recovered URL, however, has more than one possible source: an open page, an unclicked link, copied text, a cache, or a stale allocation. The forensic question is therefore not merely whether bytes exist, but what activity those bytes support. Prior Tor client memory work already used process and pattern analysis to recover artifacts [1]. Work on Chromium browser objects explains why string matches lack the context needed to infer visits [2]. Our pilot asks whether the ambiguity can be demonstrated and measured with fresh, ground-truthed Tor Browser whole-RAM images on two operating systems.

TorSessionTrace makes the observational level explicit. Its output records a PID, virtual offset, encoding, string type, and `E1:process_memory_string`. It does not output a `visited` verdict. The research contribution proposed here is a reproducible measurement of the gap between memory-string presence and independently observed requests, together with technical attrition. The plugin implementation alone is not claimed as a novel URL scanner.

## 2. Research questions

**RQ1.** How often is an exact target URL present in Tor Browser process memory when the target is absent, rendered as an unclicked link, or requested after a click in the controlled fixture?

**RQ2.** Would the interpretation “URL string present means requested” misclassify unclicked-link captures in this fixture?

**RQ3.** What is the measured all-browser-PID analysis time, and how often does the whole-RAM analysis pipeline fail before a target result is produced?

## 3. Method

The [protocol](research-protocol.md) was committed before the 3-per-cell study results. Each job ran Tor Browser 16.0 headless on a fresh GitHub-hosted Ubuntu 24.04 or Windows Server 2022 x86-64 runner. A controller generated a random URL and started a local HTTP server. In `absent`, the target was omitted from the page; in `link_only`, it was rendered as an anchor but not clicked; in `clicked`, browser automation clicked it and checked navigation. Tor Browser was configured through a local-only SOCKS5 relay because its default proxy points to port 9150. The relay rejected nonlocal destinations. The HTTP server counted target requests independently of TorSessionTrace.

While Tor Browser was alive, AVML captured Linux whole RAM and WinPmem captured Windows whole RAM. Stable Tor Browser PIDs recorded before and after acquisition were matched to Volatility 3 `pslist` output. The appropriate TorSessionTrace adapter scanned all matched PIDs once per image. The exact target URL was compared with returned strings; a separate random URL absent from the browser page was a negative control. Volatility's process-scoped YARA scanner was also run with the exact known target as an oracle-assisted diagnostic. Its task is different from discovering arbitrary URLs.

The primary unit was an independently acquired image, rather than repeated scans of one image. Per OS and condition, we report the fraction of analyzable captures with a target hit and Wilson 95% intervals. Failed acquisitions or Volatility analyses were retained in a failure manifest and excluded only from the conditional detection denominator. Runtime is one Volatility invocation over all selected browser PIDs, including startup and symbol handling. The [source workflows](../.github/workflows/) and [aggregate records](../research-results/2026-11-02/) are public; raw RAM and target URLs were not uploaded.

## 4. Pilot results

| OS | Condition | Target URL in memory | Target HTTP request | Median adapter time |
| --- | --- | ---: | ---: | ---: |
| Linux | absent | 0/3 | 0/3 | 115.623 s |
| Linux | link only | 3/3 | 0/3 | 112.215 s |
| Linux | clicked | 3/3 | 3/3 | 93.512 s |
| Windows | absent | 0/3 | 0/3 | 112.041 s |
| Windows | link only | 3/3 | 0/3 | 109.062 s |
| Windows | clicked | 3/3 | 3/3 | 111.544 s |

All 18 analyzable images had distinct hashes and random target URL hashes. Every analyzable image passed the scenario and absent-control checks. Each `3/3` detection estimate has a Wilson 95% interval of 0.4385–1.0000; each `0/3` estimate has 0.0000–0.5615. The exact-target YARA diagnostic agreed on binary target presence in all 18 images, but its use of the known answer prevents a claim that TorSessionTrace outperforms YARA as a discovery method. The per-capture counts and hashes are in the [result report](study-results-2026-11-02.md).

The 18 analyzable images required 21 capture attempts. Windows produced 9/9 on the first attempt. Linux produced 6/9 initially. In two failed Linux attempts, Volatility `pslist` did not contain the recorded Tor Browser PIDs; in another, a selected PID had no process memory sections for scanning. Fresh replacement captures for those cells succeeded, leaving 9 analyzable images from 12 Linux attempts. These failures are pipeline failures, not negative target observations. Their mechanism remains undetermined and they may affect which images are analyzable.

## 5. Discussion and threats to validity

The controlled unclicked-link observations refute a categorical inference from a URL string hit to a request in this fixture. A URL in the `clicked` condition is also only a string observation; the independent server counter supports the condition's request, not a causal link between a particular memory copy and that request. Accordingly, this study does not validate session, tab, connection, or temporal reconstruction.

The fixture is intentionally constrained. It uses a localhost HTTP target, headless Tor Browser, one browser version, two GitHub-hosted OS configurations, and a short delay before capture. It does not run a Tor circuit or visit an actual `.onion` address. Per-cell sample size is three, intervals are wide, and Linux analyzability was imperfect. Runner hardware and memory allocation may vary, so OS runtime differences cannot be attributed solely to the adapters. Raw RAM is not released because it can contain unrelated runner secrets or personal data; a reader can reproduce new acquisitions but cannot reanalyze an identical public corpus. Prior Tor memory studies [1, 3] limit the novelty of URL recovery, and structural Gecko work [3] shows a different kind of contribution.

## 6. Conclusion and next study

In this pilot, a recovered Tor Browser URL string was compatible with both an observed request and an unclicked link. TorSessionTrace therefore reports the string and its memory location without claiming a visit. The next study should expand the number and diversity of independent images, add real controlled Tor and onion requests with independent ground truth, test additional nonvisit sources and browser states, compare blind URL-discovery methods on the same capture units, and investigate the Linux analysis failures. A stronger visit claim would require corroborating structural or network evidence linked to the specific URL and time window.

## References

1. M. Alfosail and P. Norris, “[Tor forensics: Proposed workflow for client memory artefacts](https://wrap.warwick.ac.uk/id/eprint/168347/),” *Computers & Security* 106, 102311 (2021). DOI: 10.1016/j.cose.2021.102311.
2. G. Choi, J. Bang, S. Lee, and J. Park, “[Chracer: Memory analysis of Chromium-based browsers](https://dfrws.org/presentation/chracer-memory-analysis-of-chromium-based-browsers/),” *Forensic Science International: Digital Investigation* 46, 301613 (2023). DOI: 10.1016/j.fsidi.2023.301613.
3. D. Kim, S. Lee, and J. Park, “[Decrypting IndexedDB in private mode of Gecko-based browsers](https://dfrws.org/presentation/decrypting-indexeddb-in-private-mode-of-gecko-based-browsers/),” DFRWS USA (2024).
