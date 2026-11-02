# Controlled whole-RAM study: URL strings and requests

**Status:** completed small pilot, not a general accuracy estimate or a claim of actual Tor-network browsing. The [protocol](research-protocol.md) was committed before this 3-per-cell run. Source revision: [`9c3c10e`](https://github.com/Kowntaewook/TorsessionTrace/commit/9c3c10e408240336b956d72f5b17c9ed5117694a). The [Linux run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41458890257) and [Windows run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41458889850) contain the job logs and aggregate artifacts. The 18 per-capture [JSON records](../research-results/2026-11-02/), [aggregate](../research-results/2026-11-02/aggregate.json), and [job manifest](../research-results/2026-11-02/manifest.json) permit independent recalculation.

## Design

Each reported condition has three analyzable captures on fresh GitHub-hosted runners and a new random URL per runner. Tor Browser 16.0 ran headless on Ubuntu 24.04 or Windows Server 2022. AVML or WinPmem captured the whole machine's RAM while the browser was running. Volatility 3 2.28.2 used matching Linux kernel symbols or Windows symbols, then checked all stable Tor Browser PIDs from the image: 10 per Linux capture and 9 per Windows capture in the analyzable set. All 18 images and target URL hashes are distinct; all recorded PIDs were found in their respective analyzable images. Raw RAM was deleted on the runners, and neither raw RAM nor target URLs were uploaded.

`absent` displayed no target, `link_only` displayed an unclicked target link, and `clicked` navigated to the target. A local HTTP server recorded requests. A local-only SOCKS relay accommodated Tor Browser's proxy setting and rejected external destinations. Thus `clicked` is a **localhost request**, not a Tor circuit or `.onion` visit. The server counter is the independent request ground truth. The plugin finds URL strings, not request objects.

## Outcomes conditional on analyzable images

| Target OS | Condition | URL detected / captures | HTTP requests / captures | Target string hits in replicates 1, 2, 3 | Median adapter scan, all browser PIDs | Exact-target YARA detected / captures |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| Linux | absent | 0/3 | 0/3 | 0, 0, 0 | 115.623 s | 0/3 |
| Linux | link only | 3/3 | 0/3 | 4, 4, 4 | 112.215 s | 3/3 |
| Linux | clicked | 3/3 | 3/3 | 28, 8, 21 | 93.512 s | 3/3 |
| Windows | absent | 0/3 | 0/3 | 0, 0, 0 | 112.041 s | 0/3 |
| Windows | link only | 3/3 | 0/3 | 7, 10, 10 | 109.062 s | 3/3 |
| Windows | clicked | 3/3 | 3/3 | 51, 53, 58 | 111.544 s | 3/3 |

All 18 analyzable captures passed the protocol, including zero hits for the separate absent-control URL. For each OS separately, the Wilson 95% interval is **0.0000–0.5615** for 0/3 and **0.4385–1.0000** for 3/3. These wide intervals show why 3 captures per cell cannot support a precise population rate. In both OS strata, all three `link_only` images contained the target URL while the HTTP server recorded zero target requests. Treating each such string hit as a confirmed request would mislabel all six of these controlled observations; TorSessionTrace does not make that inference.

The YARA check invoked Volatility's process-scoped `VmaYaraScan` or `VadYaraScan` with the **exact URL supplied by the experimenter**. It returned the same binary presence/absence pattern, with 0/6 absent and 12/12 present-condition detections across the two OS strata. Its median times by row were 28.683, 28.219, 22.995, 65.341, 71.973, and 65.579 seconds. This is an oracle-assisted marker diagnostic, not a blind URL-discovery baseline and not a speed contest: the methods answer different questions. The adapter medians are one Volatility invocation scanning all selected PIDs per capture; they include setup and vary with runner hardware, image contents, and process memory size. The older three-run benchmarks in the README rescan one image and use a different timing unit.

## Technical attrition and audit trail

The post-protocol matrix required **21** fresh capture attempts for 18 analyzable results. Windows completed 9/9 on the first attempt. Linux completed 6/9 initially and **9/12** after three replacement captures. Two initial Linux images had no recorded Tor Browser PID in Volatility `linux.pslist`; one had a recorded PID for which the adapter found no process memory sections. The [failed Linux job logs](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41458890257/attempts/1) and the [manifest](../research-results/2026-11-02/manifest.json) identify those attempts and replacements. No per-image JSON could be produced for the failures because analysis stopped before measurement; they are **not** counted as negative detections. The mechanism of those Volatility failures was not established from the retained aggregate data. Excluding them from the detection fraction conditions that fraction on analyzability and may bias it.

## Interpretation and next experiments

This pilot supports a narrow statement: in these controlled headless local-page conditions, the same URL-string evidence occurred both with and without an independently observed request. It does not establish that a given memory hit caused a request, nor does it reconstruct a tab, session, or timestamp. The Windows and Linux images were generated in GitHub-hosted x86-64 environments; a MacBook may analyze such images but Apple Silicon macOS RAM was not tested.

A full paper would need larger independent samples, real controlled Tor and `.onion` requests, more negative controls and browser versions, and a blind discovery baseline. A claim to recover visits would additionally require independent structural or network evidence tied to the URL and time window. The [paper plan](paper-plan.md) lists those gates and the relevant prior work. Raw runner RAM was intentionally not released; this package is reproducible through **new acquisitions**, not reanalysis of a fixed public corpus.

To recompute the table after downloading or regenerating the per-capture records:

```sh
python3 benchmarks/study_aggregate.py research-results/2026-11-02/linux-*.json research-results/2026-11-02/windows-*.json --expected-os linux windows --expected-replicates 3
```
