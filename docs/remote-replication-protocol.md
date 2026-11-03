# Separate-host onion replication: locked protocol and sample rule

**Protocol status:** preregistered in the same source revision as the new capture workflow, before inspecting any capture from this replication series. The older [four-cell pilot](remote-host-protocol.md) and its extra jobs are **not** counted in this series. Record the commit SHA and workflow run IDs before interpreting results. Any code or environment change after the first run must be dated as an amendment; report pre- and post-amendment captures separately.

## Question and unit

The primary question is whether a Tor Browser process can contain the exact target v3 onion URL when the remote service observed **zero** target-path HTTP requests. The experimental unit is one newly acquired, whole-system RAM image from one fresh GitHub-hosted client runner. A service runner on a different machine hosts an ephemeral v3 onion service and independently counts requests. Scanning the same image twice never creates a new unit. Linux and Windows client results remain separate strata; no population visit inference is made from a memory string.

## Frozen matrix and sample size

Use Tor Browser 16.0, Ubuntu 24.04 and Windows Server 2022 x86-64 clients, AVML and WinPmem, Volatility 3 2.28.2, and the fixed target-blind YARA rule in `study_extended_validate.py`. Each service dispatch creates a fresh onion hostname and random token. Each of six isolated client jobs captures once:

| Client OS | Browser condition | Target in page | Target-path requests required |
| --- | --- | --- | --- |
| Linux, Windows | `absent` neutral landing page | No | 0 |
| Linux, Windows | `link_only` rendered unclicked link | Yes | 0 |
| Linux, Windows | `clicked` rendered and clicked link | Yes | At least 1 |

Target **10 analyzable images per OS × condition**, or 60 in the complete matrix. Replicate numbers are 1–10; each number calls for a new service dispatch and six new client runners. Ten observations provide a descriptive replication, not a powered estimate of population error rates: even 10/10 positives have a Wilson 95% interval of **0.7225–1.0000**. The primary report gives each cell's exact numerator/denominator and Wilson interval, plus the fraction of `link_only` captures with a string hit despite zero target requests. The `absent` condition measures background target hits; `clicked` confirms a positive-request fixture. Report target-blind YARA on the same browser PIDs, image-level agreement, target hit counts, scan-time medians, and both methods' errors. Do not call the string hit a confirmed visit.

## Capture and eligibility

Before capture, the client Tor daemon must bootstrap and reach `/ready` through SOCKS5h; Tor Browser must load the landing page and present or omit the target as assigned. Browser landing can retry up to three times; clicked navigation can retry up to three times, with counts recorded. Capture starts while the browser and Tor daemon are alive. The client records browser PIDs before and after capture and the service's request counter. Analysis must locate at least one recorded browser PID and the client Tor PID in Volatility `pslist`; every stable browser PID found is scanned. The service's independently uploaded counter, service run ID, and hashed hostname must match the client record. A missing PID, failed acquisition, route failure, wrong page, or ground-truth mismatch is a **technical failure**. `finish` notification failure is a service-control failure and is disclosed; it does not by itself erase an otherwise cross-checked image.

**Detection is an outcome, never an eligibility gate.** An absent-page target hit or an exposed-page miss stays in the denominator if the capture meets the technical criteria. The first technically eligible image for each replicate × OS × condition is selected by increasing service-run ID, without looking at detection. After a failed cell, at most two new full service dispatches may be made for that replicate (three attempts total); all jobs, including surplus successful cells, remain in the attempt manifest. If a cell is still missing, publish the incomplete matrix and its failures rather than silently extending the run cap. Old pilot images and rescans are excluded from the 60-image denominator.

## Evidence and release

The service publishes request counts and hashed hostname. Each client job publishes an `attempt.json` even when capture or analysis fails, plus `study-result.json` when measurement reaches validation. Retain the service and client workflow URLs, attempts, source SHA, OS/browser/tool versions and browser binary hash, RAM hash and size, recorded and observed PIDs, request counts, retries, scanner definitions, and timings. Release these JSON records and a complete selection/failure manifest. Raw RAM, onion private keys, target URLs, and extracted strings are not uploaded and cannot form a redistributable fixed corpus. GitHub-hosted headless runners and a single browser version limit external validity; the service counter measures requests to this controlled endpoint, not all Tor activity or a packet-level circuit trace.

## Deployment

The [service workflow](../.github/workflows/study-remote-host.yml) runs once on the preregistration commit pushed to `research/remote-replication`, with replicate 1. It dispatches the [client workflow](../.github/workflows/study-remote-client.yml) at the same branch. Later replicates are started explicitly through **Actions → Remote-host onion study - service runner → Run workflow**, selecting that branch and entering replicate 2–10. One service run launches six client jobs; allow the previous service/client runs to finish and save their artifacts before starting the next. A workflow file edit on that branch can trigger another automatic run, so record any such run as an amendment attempt rather than quietly counting it as a new planned replicate.
