# Extended v3 onion controls: 30 whole-RAM images

**Result status, 2026-11-03.** The [locked protocol](extended-study-protocol.md) and fixed target-blind YARA expression preceded acquisition. This report covers 30 selected, independent, analyzable Tor Browser 16.0 whole-RAM images: Ubuntu 24.04 and Windows Server 2022 × five scenarios × three fresh runner captures. The service and browser used separate Tor daemons on the *same* runner. The [separate-host pilot](remote-host-results-2026-11-03.md) is a distinct stratum.

## Ground truth and image-level findings

The fixture's HTTP server counted requests to a randomized target path independently of RAM scanning. `text_only` showed a URL as paragraph text, `input_field` typed it into an initially empty form field, and `background_link` left an unclicked link in a background tab. None of those conditions requested the target. `clicked` did; `absent` never placed the target in the landing page. Each entry below is the number of images with the exact target URL in browser process memory, followed by captures with a target HTTP request. Parenthesized values are target-string hit counts by replicate, **not** independent samples.

| OS | Scenario | TorSessionTrace | Target requested | Target-blind YARA | Adapter target hits | YARA target hits | Median adapter / YARA scan |
| --- | --- | ---: | ---: | ---: | --- | --- | ---: |
| Linux | absent | 0/3 | 0/3 | 0/3 | 0, 0, 0 | 0, 0, 0 | 89.751 / 23.230 s |
| Linux | text only | 3/3 | 0/3 | 3/3 | 6, 6, 20 | 6, 6, 20 | 92.120 / 23.392 s |
| Linux | input field | 3/3 | 0/3 | 3/3 | 15, 5, 5 | 15, 5, 5 | 67.089 / 17.444 s |
| Linux | background link | 3/3 | 0/3 | 3/3 | 3, 2, 13 | 4, 2, 13 | 143.832 / 31.854 s |
| Linux | clicked | 3/3 | 3/3 | 3/3 | 40, 41, 37 | 56, 55, 49 | 123.201 / 28.966 s |
| Windows | absent | 0/3 | 0/3 | 0/3 | 0, 0, 0 | 0, 0, 0 | 109.778 / 59.248 s |
| Windows | text only | 3/3 | 0/3 | 3/3 | 17, 21, 24 | 17, 21, 24 | 113.784 / 69.010 s |
| Windows | input field | 3/3 | 0/3 | 3/3 | 12, 7, 20 | 14, 7, 22 | 125.963 / 71.357 s |
| Windows | background link | 3/3 | 0/3 | 3/3 | 10, 13, 3 | 10, 13, 3 | 99.685 / 64.991 s |
| Windows | clicked | 3/3 | 3/3 | 3/3 | 54, 39, 61 | 73, 53, 94 | 116.722 / 69.451 s |

All 18 selected nonvisit exposure images contained the target URL despite **zero target-path requests**. All six absent images had zero target hits; all six clicked images had a recorded request and a target hit. TorSessionTrace and generic YARA agreed on binary target presence in 30/30 images. The YARA rule was fixed before acquisition, contains no run-specific URL, and scans the same selected browser PIDs. Its candidate-string counts and per-image timings are in the JSON records. This is a legitimate target-blind v3-onion discovery comparison, but its onion-specific regex and Volatility scanner differ from TorSessionTrace's general HTTP(S) extractor; the elapsed-time difference is not an optimized speed ranking. The previous exact-target YARA rule is an oracle diagnostic and was not used in these results.

For each 3/3 cell, the Wilson 95% interval is 0.4385–1.0000; for each 0/3 cell, it is 0.0000–0.5615. These wide descriptive intervals and convenience runner sample do not support a population error-rate estimate. A hit is `E1:process_memory_string`, not proof of a visit. The controlled request counter establishes whether this fixture requested its target, not the origin or time of an individual memory copy.

## Acquisition and technical attrition

The selected 30 records have distinct image, randomized target, and onion-hostname SHA-256 hashes; every selected record passes the protocol checks and has all recorded browser and Tor daemon PIDs in Volatility `pslist`. Linux images were 7.09–7.14 GiB; Windows images were 11.00 GiB. The adapter was timed over all stable browser PIDs in one Volatility invocation; `pslist` is separately timed in each record. The YARA timing is also a separate invocation. Linux's median over its 15 selected images was 89.751 s for the adapter and 23.230 s for YARA; Windows's was 113.784 s and 65.778 s. Runner OS, symbol work, traversal, and implementation differ, so neither cross-OS nor cross-method timing identifies a causal speed advantage.

There were **44 actual job attempts for 30 selected images**. Ten initial pilot jobs ran before a validator repair; seven reached analysis and raised a missing `baseline_yara` argument, one Linux image lacked recorded browser PIDs in `pslist`, and two Windows jobs could not load the onion landing page. Of the 34 later job attempts, 30 were accepted. The four failures were two Linux `pslist`/browser-PID misses, one Linux target-navigation failure before capture, and one Windows landing-page failure before capture. The technical failures are never counted as negative URL detections. GitHub's later run-attempt listings show prior successful jobs with new display IDs but their unchanged original start times; these were not new acquisition attempts. The [attempt and selection manifest](../research-results/2026-11-03-extended/manifest.json) identifies the actual jobs, failures, and selected result files; workflow logs remain at the linked run IDs.

## Recalculation and limits

The [aggregate](../research-results/2026-11-03-extended/aggregate.json) derives from the [30 per-image JSON records](../research-results/2026-11-03-extended/). Recalculate with:

```sh
python3 benchmarks/study_extended_aggregate.py research-results/2026-11-03-extended/linux-*.json research-results/2026-11-03-extended/windows-*.json --expected-replicates 3
```

The [Linux pilot](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41550538103), [Windows pilot](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41550538298), [Linux follow-up](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41551406751), and [Windows follow-up](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41551406771) provide acquisition and analysis logs. Raw RAM is deleted on the runners and cannot be reanalyzed as a fixed public corpus. The study used one browser version, headless automation, short capture intervals, and same-host onion service/client daemons. It did not test bookmark-only, clipboard-only, shutdown, long-delay, or structural Firefox objects.
