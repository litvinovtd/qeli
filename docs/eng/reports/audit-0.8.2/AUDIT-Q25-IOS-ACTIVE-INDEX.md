# Q25-F187: active-profile index on iOS Restore

1 October 2026. Base: d4688564. D08 remains **IN_PROGRESS**.

iOS importJSON converted the internal backup active field through NSNumber.intValue. Booleans and fractions could become zero or one, while a wrong type silently selected the first profile. Restore could therefore choose the wrong server even when each INI profile was valid.

A missing active field still uses legacy default zero, but a present one must be a JSON number with an exact integer value within the profile array. Validation rejects CFBoolean, strings, null, fractions, overflow and out-of-range indexes before selecting a profile. Numeric 1 and 1.0 produce the same index, matching Android Q25-F186. This JSON is a backup envelope; configuration remains INI.

An XCTest was added through real importJSON with two INI profiles and valid/invalid active values. Static diff review passed. XCTest and iOS build were not run because Mac/Xcode was unavailable under the previously agreed limits; no platform PASS is claimed.
