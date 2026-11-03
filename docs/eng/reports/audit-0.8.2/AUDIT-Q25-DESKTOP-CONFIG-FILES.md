# Q25-F168: file-based client INI in desktop CLI

1 October 2026. Base: f396c34b. D08 remains **IN_PROGRESS**.

Windows and macOS CLI commands used File.ReadAllText. Its default UTF-8 decoder can replace malformed bytes with U+FFFD, passing an altered password or value to the shared parser. The full file was also read before any configuration-size check.

Both CLIs now use VpnConfig.ParseFile in the shared C# layer. It reads at most 256 KiB plus one byte, rejects oversize input before parsing, strictly decodes UTF-8 and passes the INI to the same parser. The temporary config buffer is cleared afterwards. Text input and qeli:// links still use VpnConfig.Parse.

Shared C# conformance reported ALL PASS, including new normal-INI, malformed-UTF-8 and over-256-KiB cases. QeliWin and QeliMac built with --no-restore without warnings or errors. Conformance used a previously verified ABI 1.16 host DLL. macOS runtime on Mac and Windows network runtime were not tested; other import paths and runtime adapters remain in D08.
