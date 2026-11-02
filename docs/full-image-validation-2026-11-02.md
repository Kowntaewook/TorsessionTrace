# Whole-system Windows and Linux adapter validation — 2026-11-02

The [GitHub Actions run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41433076839) passed both jobs at commit `42cf9645c7dde0c371f7972ab4edd9cd87b41916`. Both jobs ran Volatility 3 2.28.2 on a Linux x86_64 GitHub runner. **The target operating system is determined by the memory image, not the analysis host.**

The [validation workflow](../.github/workflows/full-image-validation.yml) downloaded whole-system images and matching symbols from the [Volatility Foundation test corpus](https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1). It checked the compressed downloads against the Foundation's [image SHA-256 list](https://github.com/volatilityfoundation/volatility3-test-data/blob/main/images/SHA256SUMS) and [symbol SHA-256 list](https://github.com/volatilityfoundation/volatility3-test-data/blob/main/symbols/SHA256SUMS). It ran the native `pslist` plugin, selected one user process, and then ran the TorSessionTrace OS adapter three times. Each plugin result had the selected PID and `E1:process_memory_string`; nonempty and stable hit counts were required. Adapter errors now fail the command instead of leaving an empty result that could look successful. Only aggregate JSON was uploaded.

| Target image | Selected process | Image size | Plugin times (s) | Median (s) | String hits per run |
| --- | --- | ---: | --- | ---: | ---: |
| `linux-sample-1.bin` | `NetworkManager`, PID 2363 | 536,870,912 B (512 MiB) | 4.310, 4.310, 4.325 | 4.310 | 12 |
| `win-10_19041-2025_03.dmp` | `msedge.exe`, PID 3952 | 2,094,154,496 B (1,997.1 MiB) | 31.226, 31.445, 31.093 | 31.226 | 7,112 |

The uncompressed image SHA-256 hashes were `8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc` (Linux) and `ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460` (Windows). The native `pslist` commands found 133 and 120 processes, respectively. Their separate times were 8.495 s (Linux) and 7.447 s (Windows).

The plugin timings include Volatility CLI startup and analysis of **one selected process** after the baseline `pslist` call; they do not represent a full scan of every byte in the image. The source images contain ordinary Linux and Windows activity, **not Tor Browser**. These runs verify symbol resolution, process discovery, and real VMA/VAD-backed extraction on whole-system images. The separate [Tor Browser process-core benchmark](benchmark-2026-11-02.md) verifies the shared extractor on actual Tor Browser memory. A whole-system image with Tor Browser running remains a distinct integration fixture. No string hit alone establishes that a URL was visited.

Aggregate JSON: [Linux run artifact](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41433076839/artifacts/13134554170), [Windows run artifact](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41433076839/artifacts/13135376567). Re-run the [workflow](../.github/workflows/full-image-validation.yml) to reproduce on fresh runners; timings can vary.
