# Q25-F195 — share-link errors in client UI

Status: Windows/macOS sources built on 1 October 2026; iOS reviewed statically, XCTest awaits Mac/Xcode (D12).

After Q25-F194, the shared editor correctly refuses `qeli://` export for a profile with no inline `pass`. Windows and macOS constructed the QR window without handling the exception, potentially interrupting the UI command instead of telling the user. Both clients now show the error in their existing dialogs. Android already catches it and shows a toast.

iOS used `try?` to turn an export error into an empty string, then offered to copy and share that empty link. The screen now retains the generation result and displays the error without creating a QR or offering Copy/Share. The refusal heading was added to EN/RU localization.

`dotnet build` for Windows and macOS: both builds PASS with zero warnings/errors. iOS runtime/XCTest was not run without Mac/Xcode and remains in D12.
