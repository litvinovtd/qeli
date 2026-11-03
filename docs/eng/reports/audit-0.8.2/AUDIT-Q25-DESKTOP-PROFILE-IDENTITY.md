# Q25-F189: stable desktop profile IDs

1 October 2026. Base: 780bfc3a. D08 remains **IN_PROGRESS**.

Windows/macOS profile stores detected legacy JSON migration by searching for Id anywhere in the whole container. In a mixed list where one profile already had Id but another did not, migration did not run. Deserialization assigned the latter a new GUID on each load. Auto/service-profile settings and log buffers refer to Id, so selections could lose stability. This is an internal encrypted list container; user configs remain INI.

Shared ProfileStorePayload now inspects each JSON object before deserialization. A missing Id in any entry triggers a one-time write of the migrated list. Explicit null/empty and duplicate Id values are rejected before UI sees them; shared Encode prevents clients from writing such a container. macOS .bak recovery uses the same Decode and then saves the recovered list. An empty array remains valid.

Shared QeliConformance selftest reported ALL PASS, including a mixed list, stable repeated decode, three invalid-Id cases and refusal to write a duplicate. QeliWin/QeliMac --no-restore builds had zero warnings and errors; git diff --check passed. The first selftest used an older DLL from bin and did not reach profile checks; rerunning with only the local build copy replaced by ABI 1.16 passed. Real desktop UI runtime was not tested because Windows VM and Mac were unavailable by user decision.
