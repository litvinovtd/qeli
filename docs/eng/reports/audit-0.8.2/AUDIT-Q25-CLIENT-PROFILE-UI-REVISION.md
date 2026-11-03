# Q25-F177: client UI revisions and active-profile application

1 October 2026. Base: dfa4f022. D08 remains **IN_PROGRESS**.

The Android editor, per-app picker, popup menu and Delete confirmation retained only a profile index. A pending dialog or app-list result could act on another row after import/save reordered the list. Windows/macOS Edit/Delete waited for modal UI and asynchronous tunnel stop, and could apply a stale result after list changes. Android saved changes to an active profile's INI/per-app policy while VpnService kept its old snapshot without telling the user.

Android increments a revision after every successful save and checks it before deferred actions. Desktop clients check revisions before and after stopping; on a conflict after stop, they try to restore the previous tunnel if the profile remains and no tunnel runs. A shared EN/RU message explains rejection. Android shows an EN/RU reminder to reconnect manually after an active profile's config changes; README documents it.

Android compileDebugKotlin and 156 JVM tests passed with the verified host DLL. QeliWin and QeliMac dotnet builds with --no-restore passed without warnings or errors; git diff --check passed. UI fault injection on Android, Windows VM and Mac was not run. Revisions cover operations within one window/process only; external desktop-store edits, cross-process conflict resolution and complete reconnect runtime confirmation remain in D08.
