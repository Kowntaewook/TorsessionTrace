# TorSessionTrace v0.1

Volatility 3 plugin proof of concept for **URL and v3 `.onion` string artifacts** in a chosen process's memory. This release supports Intel 32/64-bit Windows and Linux memory images that Volatility 3 can already parse. It does not determine whether a site was visited, whether a connection succeeded, or which tab/session contained the string.

## Scope and evidence

- Input: an acquired Windows/Linux memory image, required PID(s), and readable process VADs/VMAs.
- Output: PID, process name, virtual offset, encoding, string kind, artifact, and `E1:process_memory_string`.
- `E1` means the bytes were found in a memory region mapped to the selected process in the image. The string may be a bookmark, link, page content, cache, prefetch, copied text, or a stale allocation.
- `.onion` matching is **syntactic** (56 base32 characters plus `.onion`); this version does not verify the v3 address checksum. A URL with a `.onion` host must meet that syntax. Older v2 addresses are outside scope.
- PID selection does not itself establish Tor Browser identity. Review process path/command line and parent/child relationships separately, then preserve those findings beside the plugin output. `firefox.exe`/`firefox` alone is insufficient.
- A missing result is not proof that no URL was used: pages may be swapped out, overwritten, encrypted, absent from the image, or represented in an unhandled encoding.

The next evidence level would require independent corroboration tied to the same process and time interval. v0.1 never emits a `visited` or `confirmed` field. `SessionHistory`, `Document`, and `STREAM` structure recovery is outside this version and must be demonstrated on versioned Tor Browser memory samples before being claimed.

## macOS setup

On an Apple Silicon Mac, use a native Python venv to **analyze** an existing Windows/Linux image. Python 3.8+ is required by Volatility 3; Python 3.12 is the tested interpreter here. From this directory:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install 'volatility3==2.28.2'
vol -p "$PWD/plugins" -h
python -m unittest discover -s tests -v
python tests/smoke_cli.py
```

If a native dependency fails on Apple Silicon, use the package's current instructions and isolate that issue in the venv; do not change the system Python. The basic plugin needs no YARA or Capstone dependency. Volatility can download Windows symbols when needed; Linux analysis normally needs a matching kernel symbol table, generated with `dwarf2json` or taken from a verified symbol pack.

## Virtual machines and GitHub Actions

The included [CI workflow](.github/workflows/ci.yml) runs the synthetic tests and Volatility plugin-loading checks on GitHub's **x64 Windows**, **x64 Ubuntu**, and **arm64 macOS** runners. The separate [Tor Browser benchmark workflow](.github/workflows/benchmark.yml) captures a real Linux Tor Browser process core and measures the shared extraction code. See the [measured results](docs/benchmark-2026-11-02.md). The benchmark does not exercise Volatility's Windows/Linux full-image adapters.

For a full image test on the M4 Pro, an **x86_64 Windows or Linux guest must be emulated** (for example with UTM/QEMU), because native virtualization on Apple Silicon uses an arm64 guest. Emulation is slower. A Windows 11 ARM guest in Parallels/UTM is useful for other development, but its ARM kernel image is outside these Intel-only plugin requirements. An existing Intel memory image from an authorized lab is the fastest first end-to-end fixture. Keep real memory images out of a public CI repository; a later private or self-hosted image job can run the same commands below against a controlled fixture.

## Image workflow

First hash the image and identify likely browser processes. Use commands matching the image OS:

```sh
shasum -a 256 /path/to/memory.raw
vol -f /path/to/memory.raw windows.info
vol -f /path/to/memory.raw windows.pslist
vol -f /path/to/memory.raw windows.cmdline
vol -p "$PWD/plugins" -f /path/to/memory.raw -r json tor_session_trace.windows.TorSessionTraceWindows --pid 1234
```

For a Linux image:

```sh
vol -f /path/to/memory.raw linux.pslist
vol -f /path/to/memory.raw linux.psaux
vol -p "$PWD/plugins" -f /path/to/memory.raw -r json tor_session_trace.linux.TorSessionTraceLinux --pid 1234
```

Review the process path/arguments and related processes before choosing PID(s). Pass multiple PIDs after `--pid` if needed. Results may contain sensitive browsing strings; keep image and output under the same evidence-handling rules. The default cap is 1,000 hits per process; `--max-hits N` changes it.

## Validation status and next steps

The synthetic tests cover ASCII/UTF-16LE extraction, v3 `.onion` string matching, malformed URLs, and hit limits. The CI workflow installs Volatility 3 2.28.2 and checks plugin discovery on all three runner platforms. The [real Tor Browser 16.0 process-core benchmark](docs/benchmark-2026-11-02.md) found a controlled URL that appeared only as an unvisited link; this validates string extraction and the conservative `E1` interpretation. Neither operating-system plugin has yet been validated end to end on a **whole-system** Windows/Linux memory image.

For the next validation gate, acquire an authorized Intel Windows or Linux **whole-system** image in a controlled lab while Tor Browser is open. Record Tor Browser version, OS/kernel build, capture tool, acquisition time, process path/arguments, a known test URL, and image SHA-256. Run the matching baseline plugins and TorSessionTrace, then compare hits with the known URL and a link-only control. Do not mark a visit confirmed solely because a string appears.

An M4 Pro can run this analysis locally. It does **not** make its own macOS live RAM easy to acquire. Volatility Foundation states modern Apple memory acquisition is not feasible on demand. Its current macOS tutorial says legacy macOS plugins remain available but analysis support is no longer actively maintained; this project makes no Apple Silicon macOS-image claim. Apple Silicon Windows/Linux **ARM guest images** are also not the current Intel plugin target; use an existing Intel image, a separate Intel lab machine, or an emulated Intel guest for this PoC.

## Primary references

- [Volatility 3 README and installation](https://github.com/volatilityfoundation/volatility3/blob/develop/README.md)
- [Volatility 3 plugin guide](https://github.com/volatilityfoundation/volatility3/blob/develop/doc/source/simple-plugin.rst)
- [Volatility 3 CLI options](https://volatility3.readthedocs.io/en/stable/vol-cli.html)
- [Volatility Foundation's parity release and platform status](https://volatilityfoundation.org/announcing-the-official-parity-release-of-volatility-3/)
- [Current macOS tutorial and deprecation notice](https://volatility3.readthedocs.io/en/stable/getting-started-mac-tutorial.html)
- [Tor Project's v3 onion address description](https://community.torproject.org/onion-services/setup/)
