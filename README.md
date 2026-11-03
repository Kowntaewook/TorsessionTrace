# TorSessionTrace

TorSessionTrace is a Volatility 3 plugin that extracts URL and v3 `.onion` **strings** from selected processes in Intel 32/64-bit Windows or Linux whole-system memory images. Every result is `E1:process_memory_string`: the bytes were present in a mapped process region. A hit does **not** confirm a visit, a successful connection, or a particular tab or session.

## Validation at a glance

| Test | Fixture | Result |
| --- | --- | --- |
| **Extended real-onion controls** | 30 independent Windows/Linux whole-RAM images; five scenarios × three captures per OS | 18/18 text-only, typed-input, or background-link images contained the target URL with **zero target requests**; target-blind generic YARA agreed on image-level presence in 30/30 |
| **Separate-host onion pilot** | Linux onion service on a different GitHub runner from Linux/Windows Tor Browser clients | **4/4 planned** and **5 additional** analyzable client images cross-checked against independent service counters; see [pilot report](docs/remote-host-results-2026-11-03.md) and its disclosed service-control failure |
| **Windows Tor Browser whole-RAM integration** | Tor Browser 16.0 running on Windows Server 2022; WinPmem raw image | Unvisited link found **2** times per run; absent control **0**; **13.231 s** median over 3 adapter runs |
| **Linux Tor Browser whole-RAM integration** | Tor Browser 16.0 running on Ubuntu 24.04; AVML LiME image | Unvisited link found **3** times per run; absent control **0**; **21.886 s** median over 3 adapter runs |
| Windows adapter | Volatility Foundation Windows 10 whole-system image; `msedge.exe` PID 3952 | 7,112 string hits per run; 31.226 s median over 3 runs |
| Linux adapter | Volatility Foundation Linux whole-system image; `NetworkManager` PID 2363 | 12 string hits per run; 4.310 s median over 3 runs |
| Shared extractor | Real Tor Browser 16.0 Linux process core | Unvisited link URL found 19 and 20 times in two independent runs; absent control 0 |
| Code and plugin registration | GitHub Actions on Ubuntu, Windows, and macOS | All jobs passed |

The [combined whole-RAM tests](docs/tor-whole-image-integration-2026-11-02.md) captured each machine while Tor Browser was running. Volatility identified browser PIDs in the full image, and each OS adapter found a link rendered in browser memory but never opened. The [Foundation image tests](docs/full-image-validation-2026-11-02.md) additionally exercise both adapters on independent public images without Tor Browser. The [process-core benchmark](docs/benchmark-2026-11-02.md) checks the shared extractor separately. Image size is not the number of bytes scanned: each timed adapter run scans only the selected process, after a separate `pslist` run. Each median is from three analyses of **one capture**, not three independent captures.

## Controlled studies for a possible paper

The [localhost study](docs/study-results-2026-11-02.md) and the later [real v3 `.onion` study](docs/onion-study-results-2026-11-03.md) each contain **18 independent, analyzable whole-RAM images**: three captures for every combination of Windows/Linux and absent, unclicked-link, or clicked target. The localhost fixture used a restricted local SOCKS relay. The onion fixture used separate Tor service and client daemons, an ephemeral v3 onion service, SOCKS5h, and an independent target-path request counter. Its [network preflight](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461383444) and [pre-results protocol](docs/onion-study-protocol.md) preceded browser RAM acquisition.

In **each** study and OS, the URL was found in all three unclicked-link images despite **zero target requests**; it was absent in all three absent images and present in all three clicked images with a recorded target request. The onion [aggregate](research-results/2026-11-02-onion-pilot/aggregate.json), [per-image results and failure manifest](research-results/2026-11-02-onion-pilot/), and [full report](docs/onion-study-results-2026-11-03.md) record hashes, process coverage, timing, and 3 Linux technical failures among 21 onion attempts. The localhost study likewise needed 21 attempts.

The newer [extended onion study](docs/extended-study-results-2026-11-03.md) adds visible text, typed input, and an unclicked background-tab link, with a fixed target-blind generic v3-onion YARA baseline over the same browser PIDs. It selected **30 independent whole-RAM images** from **44 actual job attempts**. All 18 nonvisit exposure images held the exact target string although the service recorded zero target requests; both methods agreed on target presence or absence in all 30 images. The [aggregate](research-results/2026-11-03-extended/aggregate.json), [attempt manifest](research-results/2026-11-03-extended/manifest.json), and per-image JSON files permit recalculation. The separate-host [remote pilot](docs/remote-host-results-2026-11-03.md) cross-checked four planned and five additional analyzable client RAM images against service-side counters from distinct hosted runners. Its fourth service job failed to receive a completion notification, but uploaded the final counter artifact; the [remote aggregate](research-results/2026-11-03-remote/aggregate.json) records the matching target requests and the failed notification. These are distinct small transport and presentation strata, not a pooled accuracy estimate or proof that a memory string identifies a visit. A new [preregistered separate-host replication](docs/remote-replication-protocol.md) targets 10 independent images for each of six OS × condition cells, including an absent control. Its results are reported separately from the pilot. The [research plan](docs/paper-plan.md) and [pilot manuscript draft](docs/manuscript-draft.md) state what is still needed for publication.

## Install on Windows, Linux, or macOS

The analysis computer and the image's operating system can differ. For example, a MacBook can analyze an Intel Windows image, and a Linux runner can analyze a Windows image. Use Python 3.12 for the tested setup and install Volatility 3 2.28.2 in a virtual environment.

**Windows PowerShell** (from the repository root):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install volatility3==2.28.2
.\.venv\Scripts\vol.exe -p .\plugins -h
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

**Linux or macOS** (from the repository root):

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install 'volatility3==2.28.2'
.venv/bin/vol -p "$PWD/plugins" -h
.venv/bin/python -m unittest discover -s tests -v
```

The plugin needs no YARA or Capstone dependency. Windows kernel symbols can be fetched by Volatility when network access is available. Linux analysis requires a matching kernel symbol table; pass its directory with `-s`. The [whole-system workflow](.github/workflows/full-image-validation.yml) downloads exact image/symbol pairs from the Volatility Foundation test corpus and verifies their SHA-256 checksums.

## Analyze an image

First hash the original image and inspect processes. Choose PID(s) after checking process paths, command lines, and relationships; a process named `firefox` alone does not prove it belongs to Tor Browser. The examples below use `vol` for the virtual environment's command: `.venv/bin/vol` on Linux/macOS or `.venv\Scripts\vol.exe` on Windows. Replace paths and PIDs with the case's values.

**Windows image:**

```sh
vol -f /path/to/memory.raw windows.info
vol -f /path/to/memory.raw windows.pslist
vol -f /path/to/memory.raw windows.cmdline
vol -p /path/to/TorSessionTrace/plugins -f /path/to/memory.raw -r json tor_session_trace.windows.TorSessionTraceWindows --pid 1234
```

**Linux image:**

```sh
vol -s /path/to/matching-symbols -f /path/to/memory.raw linux.pslist
vol -s /path/to/matching-symbols -f /path/to/memory.raw linux.psaux
vol -p /path/to/TorSessionTrace/plugins -s /path/to/matching-symbols -f /path/to/memory.raw -r json tor_session_trace.linux.TorSessionTraceLinux --pid 1234
```

Pass more than one PID after `--pid` when needed. The default limit is 1,000 hits per process; `--max-hits N` changes it. Output includes PID, process name, virtual offset, encoding, artifact kind, artifact string, and evidence level. A selected process whose mapped regions cannot be scanned now causes an error rather than an empty result that could look successful.

## Interpreting results

- `E1:process_memory_string` identifies a URL or onion-shaped string in a selected process's mapped memory. It can come from an unvisited link, bookmark, page content, copied text, cache, prefetch, or stale allocation. The Tor Browser benchmark recovered a link that was **never visited**.
- `.onion` matching is syntactic: 56 base32 characters plus `.onion`. v0.1 does not verify the v3 checksum or support old v2 addresses.
- An empty result does not prove absence of activity. Relevant bytes may be swapped out, overwritten, encrypted, unavailable in the image, or encoded differently.
- v0.1 does not reconstruct `SessionHistory`, `Document`, or `STREAM` objects and never emits a `visited` or `confirmed` field. A stronger conclusion requires independent evidence tied to the same process and time interval.

Memory images and plugin output can contain sensitive data. The workflows upload aggregate JSON measurements, not raw memory images or extracted strings.

## Reproduce the checks

- [CI workflow](.github/workflows/ci.yml): synthetic extraction tests and plugin registration on Windows, Ubuntu, and macOS. [Passing run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41433076743).
- [Whole-system image workflow](.github/workflows/full-image-validation.yml): verified Foundation Windows/Linux images and matching symbols, baseline `pslist`, then three adapter runs. [Passing run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41433076839) and [measurements](docs/full-image-validation-2026-11-02.md).
- [Tor Browser memory benchmark](.github/workflows/benchmark.yml): signed Tor Browser 16.0 download, offline unvisited-link control, `gcore` capture, then three shared-extractor runs. [Passing run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41433076755) and [measurements](docs/benchmark-2026-11-02.md).
- [Windows Tor Browser whole-RAM workflow](.github/workflows/tor-whole-windows.yml): verify Tor Browser download checksum, render an offline link, capture RAM with WinPmem, run `windows.pslist` and the Windows adapter three times on a Tor Browser PID. [Passing run and aggregate artifact](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41434692131).
- [Linux Tor Browser whole-RAM workflow](.github/workflows/tor-whole-linux.yml): verify Tor Browser signatures, build matching BTF symbols, render an offline link, capture RAM with AVML, run `linux.pslist` and the Linux adapter three times. [Passing run and aggregate artifact](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41436080774). Both sets of [measurements and capture hashes](docs/tor-whole-image-integration-2026-11-02.md) are documented.
- [Controlled study workflows](.github/workflows/study-linux.yml): independent Windows and Linux captures for absent, unclicked-link, and clicked conditions, plus an exact-target YARA diagnostic. [Linux run, including three documented technical failures and successful replacements](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41458890257); [Windows passing run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41458889850); [results and limitations](docs/study-results-2026-11-02.md).
- [Real onion study workflows](.github/workflows/study-onion-linux.yml): independent Linux and [Windows](.github/workflows/study-onion-windows.yml) captures with a fresh v3 onion service and independent request counter. The [Linux pilot](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461754138), [Linux follow-up](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41463589825), [Windows pilot](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41463589861), and [Windows follow-up](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41465295644) document all 21 attempts; the [report](docs/onion-study-results-2026-11-03.md) summarizes the 18 analyzable images. Run `python3 benchmarks/study_aggregate.py research-results/2026-11-02-onion-pilot/linux-*.json research-results/2026-11-02-onion-pilot/windows-*.json --expected-os linux windows --expected-replicates 3` to recalculate its table.
- [Extended onion workflows](.github/workflows/study-extended-linux.yml): the [Linux pilot](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41550538103), [Windows pilot](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41550538298), [Linux follow-up](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41551406751), and [Windows follow-up](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41551406771) produced the 30-image matrix. Current Linux and [Windows](.github/workflows/study-extended-windows.yml) workflows use manual dispatch and all three replicates per scenario, so a fresh dispatch reproduces the full matrix. The [protocol](docs/extended-study-protocol.md), [results](docs/extended-study-results-2026-11-03.md), and [manifest](research-results/2026-11-03-extended/manifest.json) disclose the historical split pilot/follow-up revisions, repairs, and failed attempts. Recalculate with `python3 benchmarks/study_extended_aggregate.py research-results/2026-11-03-extended/linux-*.json research-results/2026-11-03-extended/windows-*.json --expected-replicates 3`.
- [Separate-host workflows](.github/workflows/study-remote-host.yml): a separate onion-service runner dispatches the [client workflow](.github/workflows/study-remote-client.yml). The earlier [pilot protocol](docs/remote-host-protocol.md), [results](docs/remote-host-results-2026-11-03.md), [aggregate](research-results/2026-11-03-remote/aggregate.json), and [per-run JSON](research-results/2026-11-03-remote/) distinguish remote request evidence from browser-memory string observations. The new [replication protocol](docs/remote-replication-protocol.md) defines the six-cell matrix, 10-per-cell target, attempt cap, and branch deployment before new data are interpreted. Subsequent service runs use explicit manual dispatch; the preregistration commit on `research/remote-replication` starts replicate 1.

On Apple Silicon, use the Mac as an **analysis host** for supported Intel images or run the workflows on GitHub Actions. Native Mac live RAM acquisition and Apple Silicon macOS memory analysis are separate problems and are not claimed here. Native ARM Windows/Linux guest images also fall outside these Intel-only plugin requirements.

## References

- [Volatility 3 installation and image analysis](https://github.com/volatilityfoundation/volatility3/blob/develop/README.md)
- [Volatility 3 plugin guide](https://github.com/volatilityfoundation/volatility3/blob/develop/doc/source/simple-plugin.rst)
- [Volatility Foundation test corpus](https://github.com/volatilityfoundation/volatility3-test-data)
- [Tor Project's v3 onion address description](https://community.torproject.org/onion-services/setup/)
