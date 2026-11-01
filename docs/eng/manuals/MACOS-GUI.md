# macOS interface rendering and memory

[Русский](../../ru/manuals/MACOS-GUI.md) · English

Starting with development version **0.8.4**, the macOS Qeli interface explicitly
uses Avalonia/Skia software rendering (`Software`). It takes effect after rebuilding
and installing the new application; updating the server does not enable it.

## How the mode works

The interface is rendered on the CPU into an image buffer. The Avalonia Native
renderer list contains only `Software`: OpenGL or Metal is no longer selected
automatically for Qeli rendering. macOS still handles windows, menus, the tray
and presenting the image onscreen. This does not disable the system GPU or window
compositor.

The choice belongs to the application, not a VPN profile: there is no separate
INI parameter or settings toggle. It applies to Intel and Apple Silicon.
The Rust transport, cryptography, utun, DNS, routes and service permissions are
unchanged. The headless launchd service runs before Avalonia initialization and
does not create a GUI.

The goal is to reduce memory spent on a hardware graphics context and its resources
for a comparatively simple VPN interface. The possible cost is extra CPU work
when updating the log, resizing the window or animating. Evaluate memory savings
alongside responsiveness, CPU and energy use.

## Logs and the hidden window

The log is limited to 256 Ki characters per profile; buffers of used profiles
accumulate. Presentation updates at most once per 250 ms, and only when changed.
Log undo/redo is disabled. Hiding or minimizing releases displayed text and pauses
statistics and animation timers. Log collection and VPN operation continue;
closing to the tray does not terminate the application process.

## Measuring memory use

Compare builds on the same Mac with the same architecture, profile, window size,
display scaling and log level. On Apple Silicon compare arm64 builds; running
x86_64 through Rosetta is a separate measurement variant.

1. Fully exit the previous GUI and launch the new Release build without a debugger.
2. Measure after warm-up and after 10 minutes: disconnected, connected with ordinary
   logging, and with the window hidden.
3. Repeatedly open settings, resize and hide/show the window. Check whether memory
   settles after repeated actions.
4. Record GUI and launchd service separately, together with CPU and responsiveness.

For the selected PID, this read-only command is available:

```sh
vmmap -summary PID
```

Compare physical footprint and native/graphics memory categories, rather than only
the .NET managed heap or virtual address space. Use Instruments Allocations/VM Tracker
when more detail is needed.

**170 MB is neither a guaranteed outcome nor a measurement of this build.**
Actual RAM/CPU and Intel/Apple Silicon behavior require testing on a Mac. Compilation
and the headless self-test do not replace that measurement.

## Developer checks

From the repository root with the SDK pinned in `global.json`:

```sh
dotnet build qeli-mac/QeliMac/QeliMac.csproj -c Release -r osx-arm64
dotnet build qeli-mac/QeliMac/QeliMac.csproj -c Release -r osx-x64
dotnet build qeli-mac/QeliMac/QeliMac.csproj -c Release -p:QeliBuildTools=true
dotnet qeli-mac/QeliMac/bin/Release/net10.0/QeliMac.dll ui-memory-selftest
```

The self-test exercises a real Avalonia TextBox, batched presentation, release of
old text and retention of log messages. It does not read profiles, start a VPN
or establish a macOS GPU/RSS reduction. Changing the renderer does not qualify
or publish a new release.
