# Q25-F175: protect mobile profiles after load failure

1 October 2026. Base: a6a93c35. D08 remains **IN_PROGRESS**.

Android read the encrypted profile store outside error handling, so damaged ciphertext or a Keystore failure could crash the Activity. If decryption succeeded but validation failed, it showed a temporary template and did not save it at startup; a later Add/Edit/Import could nevertheless overwrite the original store. iOS showed a temporary initial archive after any ProfileStore.load error, which normal saving could write over the unreadable value. UserDefaults.string(forKey:) also treated a value of the wrong type as a missing key and initialized a new archive.

Android now catches read failures, records a failure flag, shows a localized warning and blocks ordinary writes until a successful restart. An explicitly confirmed backup Restore can still replace the store. Failure to write an initially empty store enters the same state. iOS distinguishes a missing key from a wrong-type value; AppModel blocks saving and exporting the temporary archive after load failure. Only confirmed Restore can replace an unreadable store. An iOS test checks that a wrong-type UserDefaults value survives failed load. User configs remain INI; JSON is only an internal container and backup format.

Android compileDebugKotlin and 154 JVM tests passed with the verified host DLL; git diff --check passed. The iOS test/build was not run because Mac/Xcode is unavailable. Android UI fault injection was not run either. iOS UserDefaults.set durability and concurrent profile-store scenarios remain in D08.
