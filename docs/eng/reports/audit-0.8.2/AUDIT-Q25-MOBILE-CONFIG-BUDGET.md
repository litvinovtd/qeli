# Q25-F170: mobile client INI size budget

1 October 2026. Base: 8dabbac7. D08 remains **IN_PROGRESS**.

Android allowed 1 MiB for file import and individual profile writes; iOS used the same 1 MiB for file import and archive writes. The shared config editor and native client accept at most 256 KiB. Mobile clients therefore read and held up to 1 MiB before the core rejected the same profile. This delayed error also created needless divergence between store and backup limits.

Early mobile limits for an individual configuration now match 256 KiB. Whole-backup container limits of 8/12 MiB are unchanged. Android displays the correct KiB units for files below 1 MiB. Exactly 256 KiB reaches the shared parser; larger input is rejected before text is sent to the core.

Android :app:compileDebugKotlin and 34 ConfigImportRangesTest cases passed with the previously verified ABI 1.16 host DLL; git diff --check passed. iOS was not built because Mac/Xcode is unavailable in the agreed lab scope. Real device file-picker and backup-restore paths were not tested in this package. D08 remains open.
