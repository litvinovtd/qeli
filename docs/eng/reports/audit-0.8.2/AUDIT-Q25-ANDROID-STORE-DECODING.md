# Q25-F176: strict Android profile-store loading

1 October 2026. Base: ebd15feb. D08 remains **IN_PROGRESS**.

On load, Android replaced a missing or wrong-type profiles array with an empty JSONArray. The Activity then created a template and saved it over the damaged store. An empty array and out-of-range active index were also accepted. Separately, AES-GCM and legacy Tink stores decoded plaintext with replacement UTF-8, turning malformed credential or INI bytes into U+FFFD without an error.

Load now requires 1..256 profiles and a valid active index before changing the live list. Invalid containers enter the previously added failure state, preserving original data against ordinary writes. Both decryption paths use one strict UTF-8 decoder and clear the plaintext buffer afterwards. User configuration remains INI; JSON is an encrypted-store container here.

Android compileDebugKotlin and 156 JVM tests passed with the verified host DLL; two new cases check malformed UTF-8 rejection and valid Unicode preservation. git diff --check passed. Android emulator UI fault injection for a damaged store was not run. D08 remains open for concurrent transactions, other adapters and reconnect.
