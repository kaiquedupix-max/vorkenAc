# Public module coverage

This document maps publicly documented anti-cheat/screenshare capabilities to Vorken's own implementation. It is a behavior-level compatibility map, not a copy of proprietary code, private signatures or databases.

| Public capability | Vorken implementation |
|---|---|
| Generic loader / suspicious loader detection | Rust IOC catalog, random-name EXE detection, unsigned/unknown app detection, PE indicators |
| KeyAuth/eAuth/network indicators | DNS cache IOC matching and process-associated current TCP metadata |
| Packed/protected executable | PE entropy, section-name and public packer/protector indicators |
| Process injection / suspicious APIs | PE import/string indicators plus loaded-module integrity correlation |
| Streamproof | WDA_EXCLUDEFROMCAPTURE/window display-affinity inventory and signature correlation |
| Executed + deleted | Prefetch/BAM/Event 4688 + missing file + Recycle Bin/USN correlation |
| Executed + modified | Prefetch evidence + file modification timestamp correlation |
| Prefetch deleted/modified | USN JournalTrace + Prefetch directory/MFT-parent correlation + Prefetch integrity |
| External-device execution | Prefetch volume correlation, Event 4688 drive type and USB timeline |
| Network-path execution | UNC-path execution correlation |
| RAR temporary execution | temporary WinRAR/RAR path heuristics |
| Virtual disks / mounting bypass context | virtual-disk inventory, hidden volumes, BCD/EFI context |
| Service manipulation | service state/start type plus recent SCM events |
| Log clearing / time changes | Event Log clear signals and time-change events |
| Defender / antivirus integrity | Defender history/exclusions plus SecurityCenter2 product inventory |
| Secure Boot / BCD integrity | Secure Boot state, BCD current and firmware enumeration |
| SavedFiles / Mark-of-the-Web | Zone.Identifier ADS HostUrl/ReferrerUrl/ZoneId |
| Browser downloads | Chromium/Firefox download databases including URL chains and browser danger flags |
| Browser history | suspicious search/site history plus deleted SQLite/WAL recovery |
| Autoruns | Run/RunOnce, startup folders and scheduled tasks with signature/path checks |
| String/PE explorer | PE compile time, sections, entropy, packer/API/environment indicators |
| PowerShell parser | PSReadLine and PowerShell event log filtering |
| Paths/MFT-style historical evidence | NTFS USN Journal activity and deletion records |
| ADS explorer | alternate NTFS stream enumeration on candidate files |
| JournalTrace | USN create/delete/rename/data-change records |
| Crash viewer | Windows Error Reporting and minidump metadata |
| USB viewer | current PnP, registry USB history, SetupAPI and USB event timeline |
| BAM parser | BAM/DAM collector |
| Amcache parser | Amcache collector |
| Prefetch viewer | basic + detailed native Prefetch correlation |
| Multi-engine reputation | optional SHA-256-only VirusTotal reputation lookup |
| Live-memory/module review | targeted live process/module/window metadata; Vorken intentionally does not upload or dump arbitrary RAM |

## Privacy boundary

Vorken does not collect credentials, cookies, private messages, document contents or arbitrary raw RAM. Where a public tool exposes a broad memory dump, Vorken uses targeted process/module metadata instead.
