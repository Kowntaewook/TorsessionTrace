# Real Tor v3 onion-service whole-RAM pilot

Status: **cross-OS feasibility result, one analyzable capture per condition and OS**. This is not an estimated detection rate. The [protocol](onion-study-protocol.md) preceded the browser RAM experiment. The [network preflight](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461383444) independently proved an ephemeral v3 onion service could receive a SOCKS5h request from a separate Tor client on a GitHub runner; it was not a browser or RAM test.

## Browser RAM observations

The [Linux run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461754138) used Tor Browser 16.0, two separate Tor 0.4.9.11 daemons, an ephemeral v3 onion service, AVML whole-RAM acquisition, and Volatility 3 2.28.2. The [Windows run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41463589861) used the same Tor Browser release, its bundled Tor 0.4.9.15 daemons, WinPmem, and Volatility 3. The browser loaded its landing page through Tor in each condition. A local HTTP server behind each onion service counted the target requests. Each analyzable RAM image contained both daemon PIDs and all stable Tor Browser PIDs (10 Linux, 9 Windows).

| OS | Condition | Target requests observed by onion service | Exact target URL hits in Tor Browser memory | Exact-target YARA hits | Result |
| --- | --- | ---: | ---: | ---: | --- |
| Linux | absent | 0 | 0 | 0 | pass |
| Linux | unclicked onion link | 0 | 4 | 4 | pass |
| Linux | clicked onion link | 1 | 27 | 32 | pass |
| Windows | absent | 0 | 0 | 0 | pass |
| Windows | unclicked onion link | 0 | 14 | 6 | pass |
| Windows | clicked onion link | 1 | 61 | 77 | pass |

The six [per-capture JSON records](../research-results/2026-11-02-onion-pilot/) contain image and target hashes, request counts, Tor process evidence, browser PID coverage, and timings. YARA searched for the exact known target and is not a blind discovery baseline. The unclicked-link results show that an onion URL string in browser memory does not by itself establish an onion request. The clicked results independently verify a request to each onion service; they do not link any particular memory copy to that request.

There were **seven** whole-RAM attempts for six analyzable images. Windows passed 3/3 on the first attempt. The first Linux `absent` capture completed, but Volatility `linux.pslist` found none of the recorded browser PIDs. The [failed job](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461754138/attempts/1) and [manifest](../research-results/2026-11-02-onion-pilot/manifest.json) retain that technical failure. A fresh replacement image passed; the failure is not counted as a negative detection. The failure mechanism was not established.

## Next measurement

The pilot used one independent analyzable image per condition and OS. The Linux workflow adds replicates 2 and 3 from new runners; the Windows workflow will now add the same. Per-condition rates and intervals should only be reported after the planned matrix is filled and all additional technical failures are retained. Raw runner RAM, service keys, and onion addresses are not published.
