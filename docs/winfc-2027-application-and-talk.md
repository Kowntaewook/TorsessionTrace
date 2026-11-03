# WinFC 2027 participant talk draft

The [WinFC 2027 call](https://www.cybercrime.fau.de/winfc2027/) asks for a title and abstract with the workshop registration by 1 March 2027. Participant talks run for 5–10 minutes and may be delivered online. The organizers select the speakers. This draft has not been submitted. Its results come from the [research note](winfc-2027-research-note.md) and the [locked replication](remote-replication-results-2026-11-03.md).

## Title for the application form

A URL in Memory Is Not a Completed Request: A Tor Browser Case Study

## Abstract for the application form

Finding a URL in browser memory establishes that its bytes were present at a process offset during capture. It does not establish that a server received a GET for that URL. We tested this distinction with Tor Browser 16.0 on Linux and Windows. In each capture, the browser loaded a page on a controlled v3 onion service. The page either withheld a target URL, displayed it as an unclicked link, or displayed and clicked the link. The service ran on a separate machine and counted HTTP GETs to each target path.

We selected ten technically eligible whole-RAM images for each operating system and page state. TorSessionTrace found the exact target URL in all 20 unclicked-link images, although the service recorded no GET for those target paths. The URL also appeared in all 20 clicked images, each with one recorded target GET, and in none of the 20 absent images. A target-blind YARA search agreed with TorSessionTrace on target presence or absence in all 60 images.

These controls separate a memory string from a service-observed GET. TorSessionTrace therefore reports the string without assigning a visit label. The study does not test ordinary browsing or every kind of Tor connection.

## Seven-minute speaking plan

**1. The finding (about 45 seconds).** Show a single Tor Browser memory result: a URL string, process ID, and offset. Ask what the record supports. The scanner saw bytes in a browser process. The request history remains unknown until another source is checked.

**2. The three page states (about 90 seconds).** Draw the client browser and the onion service on separate machines. Show the neutral page, the unclicked `<a href>`, and the clicked link. All three pages load from the onion host. Explain that the service counts GETs to distinct target paths, so a landing-page load cannot be mistaken for the linked target page.

**3. RAM capture and selection (about 75 seconds).** Name the two operating systems, Tor Browser 16.0, AVML, WinPmem, and Volatility 3. Explain one image per fresh client job and ten selected images per OS × state. Mention 78 attempts, five technical failures, and the predeclared first-eligible selection rule. Put the full failure details in a backup slide rather than reading them aloud.

**4. The result (about 90 seconds).** Put the six-row table from the research note on screen. In 20 unclicked-link images the exact URL was present, but the service saw zero target-path GETs. In 20 clicked images the URL was present and the service saw one target-path GET per image. In 20 absent images the URL was absent. The fixed, target-blind YARA search agreed on presence or absence across all 60 images. It did not validate a visit classifier or show a scanner advantage.

**5. The reporting boundary (about 60 seconds).** Explain `E1:process_memory_string` in plain language: “This string was in the selected process memory.” A forensic report needs another source before asserting that the linked page was requested. Do not claim the experiment excluded descriptor lookups, aborted streams, or other Tor traffic.

**6. Limits and next test (about 60 seconds).** State the largest limits: headless synthetic pages, one browser version, short post-interaction wait, and no released RAM corpus. A follow-up should retain a releasable RAM corpus from a non-sensitive fixture and record Tor stream events and capture timing so others can test whether additional context separates requested from merely displayed URLs.

The six segments total seven minutes. If questions must fit in the slot, shorten the methods and result segments. At ten minutes, expand the methods and limitations rather than adding new claims.

## Claim check before submission

| Claim in the abstract | Checkable record |
| --- | --- |
| Ten selected images per OS × state; 60 total | [Locked protocol](remote-replication-protocol.md) and [aggregate](../research-results/2026-11-03-remote-replication/aggregate.json) |
| 20/20 unclicked-link URL hits and zero service-observed target-path GETs | [Cell results and service counters](remote-replication-results-2026-11-03.md) |
| 20/20 clicked hits with one target GET each; 0/20 absent hits | [Cell results and service counters](remote-replication-results-2026-11-03.md) |
| Target-blind YARA agreed on target presence or absence in 60/60 images | [Comparator method and results](remote-replication-results-2026-11-03.md) |
| Scope excludes general Tor activity and natural browsing | [Research note](winfc-2027-research-note.md) and [locked protocol](remote-replication-protocol.md) |

The public records do not contain raw RAM or extracted target strings. Keep that qualification in the final talk even if the abstract is shortened.
