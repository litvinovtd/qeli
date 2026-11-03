# Q25-F173: desktop UI profile transactions

1 October 2026. Base: 216e7795. D08 remains **IN_PROGRESS**.

Windows and macOS changed ObservableCollection before persisting added, imported or duplicated profiles; Edit and Delete likewise changed the visible list before ProfileStore.Save. Disk or encryption failures could leave the UI showing an unsaved change or hiding a still-saved profile. Windows New/Duplicate/Edit/Delete exceptions could escape UI handlers without useful recovery.

Both desktop UIs now persist the proposed list before changing the visible collection. Failures are shown to the user and leave the list unchanged. If Edit/Delete stopped the active profile before a failed write, they attempt to restart the previous configuration. The edited profile index is recomputed after the asynchronous stop so the change cannot target an old list position. Internal profile-store format is unchanged; user configuration remains INI.

QeliWin and QeliMac dotnet builds with --no-restore passed without warnings or errors; git diff --check passed. UI fault injection on Windows VM and Mac is unavailable under the agreed lab limits. Concurrent edits and reconnect remain open in D08.
