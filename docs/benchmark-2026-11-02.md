# Tor Browser process-core benchmark — 2026-11-02

## What was tested

[GitHub Actions run 41431911414](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41431911414) completed successfully at commit `843ae439f640017b5da0bd1193299ce16604ffb4`. The [workflow](../.github/workflows/benchmark.yml) downloaded Tor Browser 16.0 for Linux x86_64 and its geckodriver from the Tor Project archive, checked their signatures against the Tor Browser developer key fingerprint, then launched the browser headless on an Ubuntu 24.04 runner. The browser binary SHA-256 was `cdcd40436a4aef8e3583b1d95fa3b6c18bffe6f26921283e197052c56c8ae593`.

Selenium opened `about:blank`, inserted an `<a href>` link with a random `rendered-link.invalid` URL, and confirmed the link appeared in the DOM. It did **not** navigate to that URL. A second random `absent-control.invalid` URL was generated only in the benchmark process, never inserted into the page. `gcore` captured the running Tor Browser Firefox process as an ELF core. The [benchmark script](../benchmarks/tor_core_benchmark.py) scanned its mapped `PT_LOAD` segments through the same `core.scan_layer` function used by the Volatility plugins, with three timed repetitions. Only aggregate JSON was uploaded as a [workflow artifact](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41431911414/artifacts/13135230658); the raw core was deleted on the runner.

## Measured result

| Measure | Result |
| --- | ---: |
| Runner | Linux x86_64, 2 logical CPUs, Azure kernel 7.0.0-1017 |
| Captured browser processes | 1 |
| Core file size | 527,419,080 bytes (503.0 MiB) |
| Mapped bytes scanned | 527,142,912 bytes (502.7 MiB), 805 segments |
| Core capture time | 0.753 s |
| Extraction times | 32.573 s, 31.731 s, 31.882 s |
| Median extraction time | 31.882 s |
| Effective scan rate | 15.77 MiB/s (mapped bytes / median elapsed time) |
| Unvisited, rendered-link string hits | 19 |
| Absent-control string hits | 0 |
| Total accepted URL/onion string hits | 7,605 |

The timed extraction runs scan each core with the extractor's four patterns (ASCII URL, UTF-16LE URL, ASCII onion candidate, UTF-16LE onion candidate). The effective rate divides logical mapped bytes by one full extraction run, rather than counting every pattern pass separately. Counts are occurrences in one core, not unique sites, visits, or a measured population-wide false-positive rate.

## Interpretation and limits

The controlled link was found in real Tor Browser process memory without a visit. This directly supports reporting `E1:process_memory_string` and rules out treating a URL hit alone as proof of browsing. The absent control being undetected is one useful control for this run; it does not establish a general specificity estimate.

This is an **ELF process core**, not a whole-system RAM image. It verifies capture and the shared string extractor against actual Tor Browser memory. Separate [Windows and Linux whole-RAM integration tests](tor-whole-image-integration-2026-11-02.md) verify OS symbol resolution, process identification, and VAD/VMA traversal with Tor Browser running. Neither test reconstructs `SessionHistory`, `Document`, or `STREAM`. The benchmark has no network-visit positive control, so recall for visited pages is unmeasured.

To reproduce the benchmark, run the [Tor Browser memory benchmark workflow](../.github/workflows/benchmark.yml) from GitHub Actions. It generates a fresh random control URL and captures a fresh process core on each run; timings and hit counts can vary.

A [second successful run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41433076755) at commit `42cf9645c7dde0c371f7972ab4edd9cd87b41916` captured a 533,202,544-byte core. Its three extraction times were 33.081, 33.978, and 32.564 s (median 33.081 s; 15.36 MiB/s). The unvisited rendered link appeared 20 times, the absent control 0 times, and total accepted string hits were 6,822. These are occurrences in a different browser process and a fresh random page; they are not directly comparable as unique browsing events.
