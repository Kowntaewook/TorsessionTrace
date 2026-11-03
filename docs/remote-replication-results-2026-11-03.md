# Separate-host replication: interim results

**Status: 6/60 planned analyzable images (replicate 1 only).** This is an interim measurement under the [locked protocol](remote-replication-protocol.md), not the completed 10-per-cell study. Replicate 1 used source revision [`c0a8927`](https://github.com/Kowntaewook/TorsessionTrace/commit/c0a8927aa3948c459e4f0c266b0229e4258b1614). The [service run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41561713585) and [six-client run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41561768611) both completed successfully. The six `attempt.json` records report successful capture and analysis; there were no technical exclusions or replacement jobs in this replicate.

The independent service recorded one landing request in every condition, **zero** target requests for both OSs in `absent` and `link_only`, and **one** target request for both OSs in `clicked`. All six clients reported the same counter and hashed onion hostname as the service. Every recorded browser PID and the client Tor PID were present in the captured image. All six service completion notifications arrived.

| Client OS | Condition | Service target requests | Adapter target hits | Target-blind YARA target hits | Adapter / YARA scan seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| Linux | absent | 0 | 0 | 0 | 131.217 / 30.607 |
| Linux | link only | 0 | 13 | 13 | 121.740 / 28.527 |
| Linux | clicked | 1 | 50 | 66 | 128.628 / 29.550 |
| Windows | absent | 0 | 0 | 0 | 116.866 / 70.585 |
| Windows | link only | 0 | 15 | 15 | 69.038 / 47.333 |
| Windows | clicked | 1 | 58 | 87 | 155.875 / 76.805 |

The image-level target presence decision agreed between methods in **6/6** images. The unclicked-link condition again demonstrates an `E1:process_memory_string` target hit without a service-observed request. It does not establish a visit, a generic false-positive rate, or a speed advantage: there is only one image per cell, and adapter and YARA scans run sequentially with different implementations and cache conditions. Linux images were about 7.09–7.10 GiB; Windows images were 11.00 GiB. The target-blind YARA rule contains no run-specific URL. Its generic candidate hits are scored against the target only after scanning.

The [aggregate](../research-results/2026-11-03-remote-replication/aggregate.json) and [per-image/attempt/service records](../research-results/2026-11-03-remote-replication/) preserve hashes, PID coverage, request counts, timing, and the **54 still-missing planned cells**. The JSON copies were recovered from the Actions job logs, which print the same JSON after writing the uploaded artifact files. GitHub Actions retains the original metric artifacts. Raw RAM and extracted strings were not uploaded. The full study remains incomplete until the other preregistered replicates and any allowed technical retries are recorded.
