# TorSessionTrace

TorSessionTrace is a Volatility 3 plugin that extracts URL and v3 `.onion` **strings** from selected processes in Intel 32/64-bit Windows or Linux whole-system memory images. Every result is `E1:process_memory_string`: the bytes were present in a mapped process region. A hit does **not** confirm a visit, a successful connection, or a particular tab or session.

## Validation at a glance

| Test | Fixture | Result |
| --- | --- | --- |
| Windows adapter | Volatility Foundation Windows 10 whole-system image; `msedge.exe` PID 3952 | 7,112 string hits per run; 31.226 s median over 3 runs |
| Linux adapter | Volatility Foundation Linux whole-system image; `NetworkManager` PID 2363 | 12 string hits per run; 4.310 s median over 3 runs |
| Shared extractor | Real Tor Browser 16.0 Linux process core | Unvisited link URL found 19 and 20 times in two independent runs; absent control 0 |
| Code and plugin registration | GitHub Actions on Ubuntu, Windows, and macOS | All jobs passed |

The [whole-system validation](docs/full-image-validation-2026-11-02.md) exercises OS symbol resolution, process discovery, VAD/VMA traversal, and extraction through both plugin entry points. Those public images **do not contain Tor Browser**. The [Tor Browser core benchmark](docs/benchmark-2026-11-02.md) uses actual browser memory and the same extraction code, but a process core is not a whole-system image. A whole-system **Tor Browser** fixture has not yet been tested. Image size is not the number of bytes scanned: each adapter scans only the selected process.

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

On Apple Silicon, use the Mac as an **analysis host** for supported Intel images or run the workflows on GitHub Actions. Native Mac live RAM acquisition and Apple Silicon macOS memory analysis are separate problems and are not claimed here. Native ARM Windows/Linux guest images also fall outside these Intel-only plugin requirements.

## References

- [Volatility 3 installation and image analysis](https://github.com/volatilityfoundation/volatility3/blob/develop/README.md)
- [Volatility 3 plugin guide](https://github.com/volatilityfoundation/volatility3/blob/develop/doc/source/simple-plugin.rst)
- [Volatility Foundation test corpus](https://github.com/volatilityfoundation/volatility3-test-data)
- [Tor Project's v3 onion address description](https://community.torproject.org/onion-services/setup/)
