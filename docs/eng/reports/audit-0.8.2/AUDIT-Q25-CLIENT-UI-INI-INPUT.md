# Q25-F169: preserve client INI text until the shared parser

1 October 2026. Base: 81a9edae. D08 remains **IN_PROGRESS**.

Windows/macOS text import, both desktop manual editors, the Android editor and iOS import trimmed the whole document before the shared parser. That could erase a trailing invalid control character which the Rust INI parser would otherwise reject. The stored version could therefore differ from pasted text.

All six entry points now pass original text to the shared parser. Normalizing the profile name or using a trimmed copy only for the iOS label does not alter the config. Permissible leading whitespace and trailing qeli:// link whitespace are still handled by the shared config core; it checks INI without prior loss of content.

QeliWin and QeliMac --no-restore builds passed without warnings or errors. Android :app:compileDebugKotlin --offline passed with an existing deprecated-API warning. iOS was not built because Mac/Xcode is unavailable under the agreed lab scope. Live device UI paths were not tested; D08 remains open.
