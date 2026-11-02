# Real Tor v3 onion-service whole-RAM pilot

Status: **Linux feasibility result, one analyzable capture per condition**. This is not an estimated detection rate. The [protocol](onion-study-protocol.md) preceded the browser RAM experiment. The [network preflight](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461383444) independently proved an ephemeral v3 onion service could receive a SOCKS5h request from a separate Tor client on a GitHub runner; it was not a browser or RAM test.

## Browser RAM observations

The [Linux run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461754138) used Tor Browser 16.0, two separate Tor 0.4.9.11 daemons, an ephemeral v3 onion service, AVML whole-RAM acquisition, and Volatility 3 2.28.2. The browser loaded its landing page through Tor in each condition. A local HTTP server behind the onion service counted the target requests. Each analyzable RAM image contained both daemon PIDs and all 10 stable Tor Browser PIDs.

| Condition | Target requests observed by onion service | Exact target URL hits in Tor Browser memory | Exact-target YARA hits | Result |
| --- | ---: | ---: | ---: | --- |
| absent | 0 | 0 | 0 | pass |
| unclicked onion link | 0 | 4 | 4 | pass |
| clicked onion link | 1 | 27 | 32 | pass |

The three [per-capture JSON records](../research-results/2026-11-02-onion-pilot/) contain image and target hashes, request counts, Tor process evidence, browser PID coverage, and timings. YARA searched for the exact known target and is not a blind discovery baseline. The unclicked-link result shows that an onion URL string in browser memory does not by itself establish an onion request. The clicked result independently verifies a request to the onion service; it does not link a particular memory copy to that request.

There were **four** whole-RAM attempts for three analyzable images. The first `absent` capture completed, but Volatility `linux.pslist` found none of the recorded browser PIDs. The [failed job](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461754138/attempts/1) and [manifest](../research-results/2026-11-02-onion-pilot/manifest.json) retain that technical failure. A fresh replacement image passed; the failure is not counted as a negative detection. The failure mechanism was not established.

## Next measurement

The pilot used one independent analyzable image per condition. The Linux workflow now adds replicates 2 and 3 from new runners, and the equivalent Windows workflow begins with one per condition. Per-condition rates and intervals should only be reported after the planned matrix is filled and all additional technical failures are retained. Raw runner RAM, service keys, and onion addresses are not published.
