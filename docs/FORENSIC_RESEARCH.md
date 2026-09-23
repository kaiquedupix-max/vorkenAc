# Vorken Forensic Research Notes

This document records public research used to shape Vorken's read-only collectors and detection model.

## Important licensing rule

Vorken does not copy proprietary or source-unavailable code.

The public Detect.ac free-tools repository currently exposes a README and distributed executables, not the source for the listed ++ tools. Their public feature descriptions are useful for identifying Windows artifacts worth investigating, but their implementation is not copied into Vorken.

Where open-source projects are referenced below, Vorken currently implements its own collectors unless a dependency is explicitly listed in the project files. If source code is later reused directly, its upstream license and attribution must be preserved.

## Public references

### Detect.ac tools and documentation

- https://detect.ac/tools
- https://detect.ac/docs
- https://github.com/detect-ac/Detect.ac-Free-Tools

Publicly described investigation areas include Prefetch, BAM, Amcache, USB history, USN Journal, startup entries, signatures, YARA, SRUM and anti-forensic indicators.

Vorken currently uses these descriptions only as research input, not copied implementation.

### Re:Trace

- https://github.com/0x90TM/Re-Trace
- License: MIT

Useful architectural ideas:

- Collect -> Normalize -> Evaluate Rules -> Correlate -> Package Evidence.
- Keep collectors separate from game-specific rules.
- Treat evidence as evidence, not as an automatic verdict.

### GhostTrace

- https://github.com/Devzinh/GhostTrace
- License: MIT

Useful Windows artifact coverage:

- Prefetch
- Shimcache/AppCompatCache
- BAM/DAM
- UserAssist
- MUICache
- PowerShell history
- USBSTOR
- services/drivers
- persistence and scheduled tasks

Vorken follows the same read-only forensic principle but uses its own implementation.

### Eric Zimmerman Registry / Amcache tooling

- https://github.com/EricZimmerman/Registry
- https://github.com/EricZimmerman/AmcacheParser
- MIT licensed
- NuGet packages maintained by Eric Zimmerman include Registry and Amcache.

These are candidates for a future full offline Amcache parser rather than inventing a fragile hive parser.

### usb-forensic

- https://github.com/SecurityRonin/usb-forensic

Useful research concept:

- correlate multiple independent USB evidence sources instead of treating one registry key as complete history;
- retain provenance/source information for each observation;
- conclusions should be reviewable and reproducible.

## Implemented in Vorken 0.2

- Current USB/PnP devices.
- USBSTOR registry history.
- SetupAPI USB evidence.
- Serial/Arduino/CH340/CH341/CP210/FTDI indicators.
- Prefetch metadata.
- Prefetch integrity checks:
  - duplicate SHA-256 across .pf files;
  - read-only .pf files;
  - Prefetch directory/config state.
- BAM/DAM execution paths and timestamps when available.
- UserAssist decoded entry names.
- MUICache traces.
- PCA Compatibility Assistant Store/Persisted traces.
- Running processes with hashes/signatures when readable.
- Services and drivers.
- Startup entries.
- Candidate executable/script metadata and SHA-256.
- PowerShell history is privacy-filtered: only lines matching an administrator-defined rule are uploaded.
- Volumes without a drive letter are listed for review.
- Recent Windows Event Log clear signals (24-hour window) are surfaced for review.
- Custom server-side rules can match artifacts across the above sources.

## Planned high-value additions

These should be added only with tested parsers and clear provenance:

- Full Amcache parsing through a maintained MIT-licensed parser.
- Shimcache/AppCompatCache.
- USN Journal timeline.
- MFT metadata and NTFS Alternate Data Streams.
- SRUM.
- LNK/Jump List correlation for removable-media paths.
- YARA/YARA-X rules with per-rule source and license tracking.
- Cross-artifact correlation scoring.
- Signed rule-pack updates.

## Interpretation

A single unusual artifact is not proof of cheating.

Examples:

- an Arduino or USB serial adapter has many legitimate uses;
- a volume without a drive letter can be a recovery partition;
- Prefetch can be disabled by some system configurations or optimization software;
- an unsigned executable can be completely legitimate.

Vorken should surface evidence, provenance and correlation so a human administrator can review the result.


## Additional research supplied for Vorken

### Ocean / anticheat.ac

Public feature and detection documentation reviewed:

- https://anticheat.ac/features
- https://anticheat.ac/docs
- https://anticheat.ac/docs/detections/detection-systems
- https://anticheat.ac/docs/detections/integrity-checks

High-value ideas adopted as independent Vorken implementations:

- correlate Prefetch, Amcache, ShimCache, BAM, PCA, EVTX and live process state;
- executed-and-deleted correlation;
- external/removable-device execution;
- network-path execution context;
- modified-extension / PE-header mismatch review;
- Microsoft Defender detection history correlation;
- Activity History / forensic-source integrity checks;
- USN Journal state checks;
- boot-integrity checks;
- virtual-disk indicators;
- loaded DLL/module inspection in the Rust process.

Ocean is not open source. Vorken does not copy Ocean code or proprietary databases. Public documentation is used only to identify forensic concepts worth implementing independently.

### SLAUC91/AntiCheat

- https://github.com/SLAUC91/AntiCheat
- useful research ideas: process/module enumeration, PEB vs virtual-memory comparison, handle/thread/driver inspection and USN scanning.
- no repository license was visible during review, so Vorken does not copy source from this project.

### Likon69/WardenScanner

- https://github.com/Likon69/WardenScanner
- useful read-only concepts: executable-memory regions, hidden PE/module discovery and process module integrity.
- the project is specialized for WoW/Warden and includes anti-detection research that is not appropriate to copy into Vorken.
- no repository license was visible during review, so Vorken uses only high-level defensive concepts.

### ThiagoSales17/op1br-anticheat

- https://github.com/ThiagoSales17/op1br-anticheat
- README describes MIT licensing, but no root LICENSE file was visible during review.
- useful coverage ideas: Prefetch, Amcache, ShimCache, BAM, Recent LNKs, Security event 4688 and anti-tampering checks.
- Vorken implements these concepts independently or through clearly MIT-licensed upstream parsers.

### PickAngE/AntiCheat-Scanner

- https://github.com/PickAngE/AntiCheat-Scanner
- repository source is public but its LICENSE explicitly marks it proprietary.
- useful architectural ideas: normalized detections, multi-source attribution, metadata/signature correlation, scheduled tasks, Defender exclusions, named pipes and boot configuration.
- no source code from this repository is copied into Vorken.

### MIT parsers now used directly

The following upstream libraries have explicit MIT licensing and are integrated as NuGet dependencies:

- EricZimmerman/Prefetch -> NuGet `Prefetch`
- EricZimmerman/AmcacheParser -> NuGet `Amcache`
- EricZimmerman/AppCompatCacheParser -> NuGet `AppCompatCache`

These parsers are preferable to fragile hand-written binary parsing and improve support across Windows 10/11 versions.
