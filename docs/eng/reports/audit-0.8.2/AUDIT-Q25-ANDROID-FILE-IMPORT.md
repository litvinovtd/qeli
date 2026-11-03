# Q25-F167: byte-faithful Android client INI import

1 October 2026. Base: b902ffcf. D08 remains **IN_PROGRESS**.

Android file import decoded malformed UTF-8 with U+FFFD replacement and trimmed the entire document before calling the shared parser. A changed password or other value could be saved without an encoding error. Trimming the end also defeated exact validation of the input INI.

File import now decodes UTF-8 strictly and passes the complete text to the shared config core. A separate view without permissible leading whitespace/BOM is used only to detect file type and the initial comment; stored INI text is unchanged. The picker no longer advertises application/json as a configuration type. Restore still accepts the internal JSON backup container.

On Windows, :app:compileDebugKotlin --offline and 34 targeted ConfigImportRangesTest cases passed with the previously verified ABI 1.16 host DLL. The first test attempt without the DLL failed to load the native core as expected; setting QELI_CONFIG_NATIVE_LIBRARY made the run pass. ContentResolver streaming E2E on an emulator was not run in this package. iOS/desktop and full D08 remained open.
