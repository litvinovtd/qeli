namespace Qeli.Shared;

/// <summary>
/// Single source of truth for the qeli brand + status-dot palette, as raw RGB. Shared
/// by the Windows brand renderer (System.Drawing.Color) and the macOS one (SkiaSharp
/// SKColor) — each builds its own colour type from these triples, so the values live in
/// one place. The rendering itself stays per-client (GDI+ vs Skia). See docs/REFACTOR-PLAN.md (R6).
/// </summary>
public static class BrandPalette
{
    public readonly record struct Rgb(byte R, byte G, byte B);

    // brand mark (ring gradient + node + field)
    public static readonly Rgb RingBlue = new(0x49, 0x90, 0xFF);
    public static readonly Rgb RingGreen = new(0x21, 0xC8, 0x6A);
    public static readonly Rgb NodeGreen = new(0x10, 0xE0, 0x77);
    public static readonly Rgb FieldDark = new(0x14, 0x1E, 0x33);
    public static readonly Rgb FieldGlow = new(0x1B, 0x3C, 0x6E);

    // status dot
    public static readonly Rgb StatusDisconnected = new(0x9A, 0xA4, 0xB0);
    public static readonly Rgb StatusConnecting = new(0xF2, 0xC0, 0x44);
    public static readonly Rgb StatusConnected = new(0x35, 0xC7, 0x59);
    public static readonly Rgb StatusError = new(0xE5, 0x53, 0x4B);
}

/// <summary>Toast severity, shared by the per-client toast presenters (WPF / Avalonia).</summary>
public enum ToastKind { Success, Info, Error }
