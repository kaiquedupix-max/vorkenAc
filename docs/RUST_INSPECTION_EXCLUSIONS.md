# Rust inspection exclusions

The agent no longer collects Rust modules. The legacy rustModules report property is retained as an empty list for server compatibility.

Before any MainModule, Modules, OpenProcess or ReadProcessMemory access, process collectors exclude Rust, RustClient, RustDedicated and EasyAntiCheat processes. Reading process names for exclusion remains necessary; excluded processes are not inspected further.

All existing file collectors use a shared inspection boundary for traversal, file metadata, hashes, PE samples, signatures and alternate data streams. It excludes:

- Every steamapps tree, including custom Steam libraries, to avoid entering game storage.
- Rust Steam app ID 252490 folders, including Steam userdata.
- Rust / RustClient / RustDedicated directories, executables and Unity data folders.
- Facepunch Studios data folders.
- Custom Rust InstallLocation paths recorded under the Steam uninstall key (HKLM/HKCU, 32/64-bit views), read from the registry without opening the installation directory.
- UNC/device paths, reparse points and DOS short-name aliases, so traversal cannot use these aliases to enter excluded folders.

Historical information in Windows logs, Prefetch, registry and browser records may still mention Rust; those collectors read Windows/browser artifacts rather than the game files. A manually copied, renamed installation outside Steam without an InstallLocation registration cannot be identified by path alone. Keep such installations outside the scan roots. This change is a scope restriction, not an EAC compatibility certification. Existing installed agents must be replaced with a build containing this change.

Validation: dotnet build agent/Vorken.Agent.csproj -c Release and dotnet run --project tests/InspectionScope.Tests/InspectionScope.Tests.csproj -c Release. Tests create synthetic fixtures; they do not open the game.
