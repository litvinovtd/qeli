# Q25-F180: empty iOS profile archives are not replaced by a template

1 October 2026. Base: f56a9ee7. D08 remains **IN_PROGRESS**.

ProfileStore.load decrypted an archive and called ProfileArchive.normalize before checking profile count. normalize turned an empty set into a template. Thus a damaged but correctly encrypted empty archive appeared to load successfully, and a later edit could replace its bytes with the template. save and exportJSON hid empty input in the same way. Android Restore and the iOS validator require 1..256 profiles.

load, save and exportJSON now reject an empty set before normalization. Legacy duplicate-ID correction and normal deletion of the last profile in AppModel keep their existing logic: AppModel creates a template before saving. An XCTest checks save/export refusal and absence of a write for empty input; the error names the 1..256 range. README describes refusal of an empty stored archive.

Static review of all three normalization paths and git diff --check passed. Swift/XCTest was not run because the user excluded Mac/Xcode/iOS from the current lab scope. D12 therefore has no iOS PASS; a future Mac run would need to build and execute the test.
