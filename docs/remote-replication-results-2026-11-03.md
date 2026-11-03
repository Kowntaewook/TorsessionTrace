# Separate-host replication: interim results

**Status: 18/60 planned analyzable images (replicates 1–3).** This is an interim measurement under the [locked protocol](remote-replication-protocol.md), not the completed 10-per-cell study. Replicate 1 used source revision [`c0a8927`](https://github.com/Kowntaewook/TorsessionTrace/commit/c0a8927aa3948c459e4f0c266b0229e4258b1614). The [service run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41561713585) and [six-client run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41561768611) both completed successfully. The six `attempt.json` records report successful capture and analysis; there were no technical exclusions or replacement jobs in this replicate.

The independent service recorded one landing request in every condition, **zero** target requests for both OSs in `absent` and `link_only`, and **one** target request for both OSs in `clicked`. All six clients reported the same counter and hashed onion hostname as the service. Every recorded browser PID and the client Tor PID were present in the captured image. All six service completion notifications arrived.

| Client OS | Condition | Service target requests | Adapter target hits | Target-blind YARA target hits | Adapter / YARA scan seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| Linux | absent | 0 | 0 | 0 | 131.217 / 30.607 |
| Linux | link only | 0 | 13 | 13 | 121.740 / 28.527 |
| Linux | clicked | 1 | 50 | 66 | 128.628 / 29.550 |
| Windows | absent | 0 | 0 | 0 | 116.866 / 70.585 |
| Windows | link only | 0 | 15 | 15 | 69.038 / 47.333 |
| Windows | clicked | 1 | 58 | 87 | 155.875 / 76.805 |

The image-level target presence decision agreed between methods in **6/6** replicate-1 images. The unclicked-link condition again demonstrates an `E1:process_memory_string` target hit without a service-observed request. It does not establish a visit, a generic false-positive rate, or a speed advantage: adapter and YARA scans run sequentially with different implementations and cache conditions. Linux images were about 7.09–7.10 GiB; Windows images were 11.00 GiB. The target-blind YARA rule contains no run-specific URL. Its generic candidate hits are scored against the target only after scanning.

## Replicate 2 and technical replacement

The [second service](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41562876333) and [client run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41562921012) used source `db31657` (only summary-code/test changes since the acquisition revision). Five images passed. The first Windows `link_only` image contained 14 adapter target hits with zero service requests, but its live-recorded client Tor daemon PID **was absent from Volatility `pslist`**. The validator marked it `protocol_pass: false` and the job failed; this image is excluded for a technical criterion fixed before capture, not for its detection result. Its JSON and failed `attempt.json` remain published.

The [replacement service](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41564036102) and [client run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41564093360) used revision `923e742`. A fresh Windows `link_only` image had the client Tor PID in RAM, zero service target requests, and 14 adapter hits. It completes the sixth planned cell for replicate 2. The other five successful images from that replacement run are released in `extras/`, and the preselected first eligible images from the original second dispatch remain the selected units.

Across the **12 selected images**, both methods agree on image-level target presence in 12/12: each OS has 0/2 detections in `absent`, 2/2 in `link_only` with zero target requests, and 2/2 in `clicked` with positive target requests. The median adapter / YARA scan times over the two selected captures per cell are 131.196 / 30.156 s (Linux absent), 124.172 / 28.563 s (Linux link), 98.596 / 23.788 s (Linux clicked), 121.950 / 73.804 s (Windows absent), 79.108 / 54.019 s (Windows link), and 136.989 / 76.698 s (Windows clicked). These are descriptive sequential timings. A 2/2 detection cell still has a wide Wilson 95% interval of 0.3424–1.0000.

## Replicate 3

The [third service](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41565273311) and [six-client run](https://github.com/Kowntaewook/TorsessionTrace/actions/runs/41565320836) completed successfully on revision `923e742`. All six images passed the locked protocol, with the browser and client Tor PIDs found in their RAM images. The service recorded zero target requests for `absent` and `link_only`, and one for `clicked`, for both client operating systems. Adapter target hits were Linux 0/10/40 and Windows 0/14/41 across the three conditions; target-blind YARA agreed on target presence in all six images. This yields 0/3 `absent`, 3/3 `link_only`, and 3/3 `clicked` image-level detections per OS. The 3/3 Wilson 95% interval remains wide at 0.4385–1.0000.

The [aggregate](../research-results/2026-11-03-remote-replication/aggregate.json) and [per-image/attempt/service records](../research-results/2026-11-03-remote-replication/) preserve hashes, PID coverage, request counts, timing, **one excluded technical result**, **five surplus analyzable captures**, and the **42 still-missing planned images**. There were 24 client jobs over four service dispatches. The JSON copies were recovered from the Actions job logs, which print the same JSON after writing the uploaded artifact files. GitHub Actions retains the original metric artifacts. Raw RAM and extracted strings were not uploaded. The full study remains incomplete until the other preregistered replicates and any allowed technical retries are recorded.
