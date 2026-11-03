# Q25-F191 — null fields in desktop profile stores

Status: fixed and locally verified on 1 October 2026.

System.Text.Json accepts explicit null for properties declared non-nullable in C#. A corrupt or legacy profile store could therefore pass ID validation, enter the Windows/macOS profile list, and throw later in UI getters such as Protocol.ToUpperInvariant() or while sending collections to the native core.

Shared ProfileStorePayload now checks required scalar fields, collections, collection elements and dictionary values on both Decode and Encode. Missing fields still receive the model defaults; intentionally nullable fields remain allowed. Existing quarantine preserves the bytes of an invalid store.

Targeted conformance cases for null Protocol, IncludeRoutes, a DnsServers element and a CarriedKeys value on load, plus null Protocol on save, all passed. Full QeliConformance selftest with host native ABI 1.16: ALL PASS. QeliWin and QeliMac --no-restore builds: zero warnings and errors. Physical Windows/macOS runtime remains outside the available lab scope; D08 remains IN_PROGRESS.
