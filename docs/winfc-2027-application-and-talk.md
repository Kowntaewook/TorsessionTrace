# WinFC 2027 participant talk draft

The [WinFC 2027 call](https://www.cybercrime.fau.de/winfc2027/) asks for a title and abstract with the workshop registration by 1 March 2027. Participant talks run for 5–10 minutes and may be delivered online. The organizers make the selection. The text below is a proposal draft; it has not been submitted or accepted. Its results come from the [research note](winfc-2027-research-note.md) and the [locked replication](remote-replication-results-2026-11-03.md).

## Title for the application form

A URL in Memory Is Not a Completed Request: A Tor Browser Case Study

## Abstract for the application form

A URL recovered from browser memory records bytes at an offset. It does not show whether a request for that URL completed. We tested the distinction in Tor Browser 16.0 on Linux and Windows. In each capture, the browser loaded a page on a controlled v3 onion service. The page either withheld a target URL, displayed it as an unclicked link, or displayed and clicked the link. A service on a separate machine counted completed HTTP requests to each target path.

We selected ten technically valid whole-RAM images for each operating system and page state. TorSessionTrace found the exact target URL in all 20 unclicked-link images, although the service received no request for those target paths. The URL also appeared in all 20 clicked images, each with one recorded target request, and in none of the 20 absent images. A target-blind YARA search agreed on target presence in all 60 images.

The talk shows how the page controls and service log narrow the meaning of a memory hit. TorSessionTrace records a process-memory string without marking the URL as visited. The result concerns completed requests to the controlled target paths; it does not measure every Tor connection or ordinary browsing.

## Seven-minute speaking plan

**1. The finding (about 45 seconds).** Show a single Tor Browser memory result: a URL string, process ID, and offset. Ask what the record supports. The scanner saw bytes in a browser process. The request history remains unknown until another source is checked.

**2. The three page states (about 90 seconds).** Draw the client browser and the onion service on separate machines. Show the neutral page, the unclicked `<a href>`, and the clicked link. All three pages load from the onion host. Explain that the service counts requests to distinct target paths, so a landing-page load cannot be mistaken for the linked target page.

**3. RAM capture and selection (about 75 seconds).** Name the two operating systems, Tor Browser 16.0, AVML, WinPmem, and Volatility 3. Explain one image per fresh client job and ten selected images per OS × state. Mention 78 attempts, five technical failures, and the predeclared first-eligible selection rule. Put the full failure details in a backup slide rather than reading them aloud.

**4. The result (about 90 seconds).** Put the six-row table from the research note on screen. In 20 unclicked-link images the exact URL was present, but the service saw zero target-path GETs. In 20 clicked images the URL was present and the service saw one target-path GET per image. In 20 absent images the URL was absent. The fixed, target-blind YARA search agreed on presence in all 60 images. It did not validate a visit classifier or show a scanner advantage.

**5. The reporting boundary (about 60 seconds).** Explain `E1:process_memory_string` in plain language: “This string was in the selected process memory.” A forensic report needs another source before attributing a completed target request. Do not claim the experiment excluded descriptor lookups, aborted streams, or other Tor traffic.

**6. Limits and next test (about 60 seconds).** State the largest limits: headless synthetic pages, one browser version, short post-interaction wait, and no retained public RAM corpus. A new study should keep a safe fixed corpus and capture Tor stream events and timing so others can test whether additional context separates requested from merely displayed URLs.

The six segments total seven minutes. If questions must fit in the slot, shorten the methods and result segments. At ten minutes, expand the methods and limitations rather than adding new claims.

## Claim check before submission

| Claim in the abstract | Checkable record |
| --- | --- |
| Ten selected images per OS × state; 60 total | [Locked protocol](remote-replication-protocol.md) and [aggregate](../research-results/2026-11-03-remote-replication/aggregate.json) |
| 20/20 unclicked-link URL hits and zero completed target-path requests | [Cell results and service counters](remote-replication-results-2026-11-03.md) |
| 20/20 clicked hits with one target request each; 0/20 absent hits | [Cell results and service counters](remote-replication-results-2026-11-03.md) |
| Target-blind YARA agreed on image-level presence in 60/60 | [Comparator method and results](remote-replication-results-2026-11-03.md) |
| Scope excludes general Tor activity and natural browsing | [Research note](winfc-2027-research-note.md) and [locked protocol](remote-replication-protocol.md) |

The public records do not contain raw RAM or extracted target strings. Keep that qualification in the final talk even if the abstract is shortened.
