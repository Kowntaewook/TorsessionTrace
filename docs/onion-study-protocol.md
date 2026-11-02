# Pre-results protocol: real Tor v3 onion-service memory study

Status: **locked before the first browser whole-RAM run**. The [network preflight](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41461383444) proved that two separate Tor daemons on a GitHub-hosted Linux runner could bootstrap and deliver one SOCKS5h request to an ephemeral v3 onion service. That preflight did not involve Tor Browser or RAM and is not counted as a study image.

## Research question

For Tor Browser browsing a real v3 onion service over the Tor network, does a process-memory URL string distinguish an unclicked onion link from an independently recorded onion HTTP request? The existing [localhost study](study-results-2026-11-02.md) cannot answer this because it used a restricted local SOCKS relay rather than a Tor circuit.

## Controlled design

Each fresh runner creates its own temporary onion service and a **separate Tor client daemon**. The service maps virtual port 80 to a local HTTP server; Tor Browser uses the client daemon's SOCKS port 9150. Both daemons must log bootstrap 100%. Before launching the browser, `curl` through SOCKS5h must reach the service's `/ready` endpoint. Then the browser loads `/landing` through the same Tor client. The service counts `/landing` and target-path requests independently. The onion hostname and target path are fresh for every capture.

| Scenario | Target URL in landing page | Browser click | Expected target HTTP requests |
| --- | --- | --- | ---: |
| `absent` | No | No | 0 |
| `link_only` | Yes | No | 0 |
| `clicked` | Yes | Yes | At least 1 |

The initial feasibility matrix is one whole-RAM image per scenario on Linux. If all three scenarios pass, expand to three **independent analyzable images** per scenario, then implement the equivalent Windows matrix. Failed attempts remain in the report, with the stage and observed cause, and replacement captures are counted as additional attempts. Do not use repeat scans of one image as independent samples.

## Acquisition and validation

Tor Browser 16.0 is verified against Tor Project signatures, AVML against its pinned SHA-256, and Linux kernel symbols are generated for the running kernel. The browser, the service Tor daemon, and the client Tor daemon remain alive through RAM acquisition. Stable browser PIDs before and after acquisition must appear in Volatility `pslist`; both Tor daemon PIDs must also appear. TorSessionTrace scans all stable browser PIDs and reports only `E1:process_memory_string` hits. An absent-control URL is never shown in the browser and must not be found. The target URL is compared exactly; a process-memory hit is never called a visit.

Primary outcomes are target detection per image, server-side target request count, protocol pass/fail, and technical attrition. Secondary outcomes are hit counts, process coverage, image hash, adapter time, and exact-known-target YARA diagnostic. The YARA rule knows the target URL and is not a blind URL discovery baseline. A separate blind baseline is needed before performance claims about discovery.

## Scope and safeguards

The service is ephemeral, and the client only requests its own generated onion hostname. The service's private key, hostname, target URL, raw RAM, and extracted strings are not uploaded. The runner deletes the raw image after analysis. Aggregate JSON records the hostname and target hashes, Tor version, Tor daemon PIDs in the image, request counts, and image hash. Raw images are therefore not a fixed public corpus. Successful browser and server requests support an onion request in this controlled setting, but do not by themselves link any particular memory copy to that request or reconstruct a session history. If Tor network access or Volatility analysis fails, report the failure rather than treating it as a negative target result.

Tor Project [onion service setup](https://community.torproject.org/onion-services/setup/) documents `HiddenServiceDir`, `HiddenServicePort`, and the v3 hostname; the [onion protocol overview](https://community.torproject.org/onion-services/overview/index.html) describes the network path. Tor's [configuration manual](https://manpages.debian.org/trixie/tor/torrc.5.en.html) documents the SOCKS listener and separate data directories.
