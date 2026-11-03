# A URL in Memory Is Not a Completed Request

Draft research note for a 5–10-minute WinFC 2027 participant talk. The [application draft](winfc-2027-application-and-talk.md) contains the proposed title and abstract.

## The question

Suppose an examiner finds a `.onion` URL in Tor Browser memory. The finding establishes that the string occupied a readable process region when RAM was acquired. It leaves open how the string got there. The controlled test below uses an unclicked HTML link to examine that ambiguity.

Earlier Tor forensics work recovered browser artifacts from memory [1, 2]. This study tests one interpretation of such a hit: whether a URL string alone establishes that a server received a GET for the URL's target path. TorSessionTrace reports the string, process ID, virtual offset, and encoding as `E1:process_memory_string`. The label describes the source of the observation; it is not a visit verdict.

## The controlled test

The main experiment used Tor Browser 16.0 on separate GitHub-hosted Ubuntu 24.04 and Windows Server 2022 clients. A different runner hosted a fresh v3 onion service and counted HTTP GETs received for each randomized target path. Each client loaded a landing page on that onion host in one of three states:

| State | What the landing page showed | Target-path GET expected |
| --- | --- | ---: |
| `absent` | Neutral text; the target URL was withheld | 0 |
| `link_only` | An `<a href>` containing the target URL; no click | 0 |
| `clicked` | The same link, followed by a scripted click | At least 1 |

Each selected capture had at least one service-recorded landing-page request. The service counted the **target path** separately, so a loaded landing page did not count as a target-page request. A fresh onion hostname was generated for each service run.

The predeclared plan selected ten technically eligible whole-RAM images per operating system and state: 60 selected images in six cells. A failed cell could trigger at most two replacement service runs. The first technically eligible image in run order filled each cell; a URL hit was never an eligibility condition. The 60 images came from 78 client attempts across 13 service runs. Five attempts failed technical checks. Metrics from 13 other technically eligible attempts were listed as surplus. [The locked protocol](remote-replication-protocol.md) and [attempt-level report](remote-replication-results-2026-11-03.md) explain the selection and failures.

AVML captured Linux RAM and WinPmem captured Windows RAM while Tor Browser was open. Volatility 3 located recorded Firefox PIDs in each eligible image. TorSessionTrace scanned those browser processes for ASCII and UTF-16LE URL strings. The client Tor daemon PID was checked in the process list but not scanned for URL outcomes. The exact randomized target was compared with scanner output after scanning. A fixed YARA expression for v3 onion URLs also ran on the same browser PIDs; it contained no run-specific hostname, token, or path. The workflow inserted a two-second pause after the final page interaction before PID enumeration and acquisition. The elapsed time from interaction to captured bytes was not measured per image.

## What the images and service recorded

The counts below use one selected image as the unit. “URL in RAM” means the exact target string was found in at least one selected Tor Browser process. “Target GET” means the service's HTTP handler counted an incoming GET to that image's target path. In the [service handler](../benchmarks/study_remote_service.py), the counter increments before the server writes its response, so it does not prove that a response reached the browser.

| Client OS | State | URL in RAM | Images with target GET |
| --- | --- | ---: | ---: |
| Linux | `absent` | 0/10 | 0/10 |
| Linux | `link_only` | 10/10 | 0/10 |
| Linux | `clicked` | 10/10 | 10/10 |
| Windows | `absent` | 0/10 | 0/10 |
| Windows | `link_only` | 10/10 | 0/10 |
| Windows | `clicked` | 10/10 | 10/10 |

Every selected `clicked` image had exactly one service-recorded target GET. The 20 unclicked-link images all contained the target URL while the service recorded zero target-path GETs. The target-blind YARA search agreed with TorSessionTrace on target presence or absence in all 60 images. This checks target presence; it does not establish a detection or speed advantage for TorSessionTrace. The ten-per-cell results describe the eligible captures under this procedure. A 10/10 result has a Wilson 95% interval of 0.7225–1.0000, not a population-wide detection guarantee. The [published aggregate](../research-results/2026-11-03-remote-replication/aggregate.json) contains the cell counts and image hashes.

A smaller [extended fixture](extended-study-results-2026-11-03.md) also placed a target URL in visible text, a scripted input field, or an unclicked background-tab link. All 18 selected nonclicked exposure images held the string while the same-host service recorded no target-path GET. Those conditions used three images per operating-system cell and are kept separate from the 60-image experiment. Selenium supplied the input-field string, so the study cannot attribute every copy to a browser object rather than an automation buffer.

## What an examiner can say

A report can say that a URL-shaped string was recovered from a specified Tor Browser process and memory offset. The main experiment shows why that observation cannot, by itself, establish that the service received a GET for the target path. In the `link_only` state, the browser reached the same onion host to fetch the landing page, yet the service recorded no GET for the linked target path. This test therefore says nothing about the absence of all Tor traffic, onion descriptor lookups, speculative connections, or aborted streams. It also cannot assign a particular memory copy to the DOM link.

The captures used synthetic pages, headless automation, one browser version, and a short programmed wait. The public records include source code, protocols, service counters, selection decisions, failure records, and hashes. Raw RAM images and extracted strings were not included in the released dataset, so a third party can repeat the acquisition protocol but cannot re-scan these exact images from the release. A follow-up study should retain a releasable RAM corpus built with a non-sensitive fixture and record Tor stream events, browser state, and capture timing while varying page state and delay. Until then, TorSessionTrace should continue to report the memory observation without a visit or session label.

## Sources

1. M. Alfosail and P. Norris, “[Tor forensics: Proposed workflow for client memory artefacts](https://doi.org/10.1016/j.cose.2021.102311),” *Computers & Security* 106, article 102311 (2021).
2. M. Muir, P. Leimich, and W. J. Buchanan, “[A forensic audit of the Tor browser bundle](https://doi.org/10.1016/j.diin.2019.03.009),” *Digital Investigation* 29, pp. 118–128 (2019).
3. TorSessionTrace [source, protocol, and per-image metrics](https://github.com/Kowntaewook/TorsessionTrace).
