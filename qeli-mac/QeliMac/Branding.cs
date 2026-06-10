using System.IO;
using System.Text;
using SkiaSharp;
using Qeli.Shared;

namespace QeliMac;

/// <summary>
/// Single source of truth for the Qeli brand mark, ported from the Android vector
/// logo (res/drawable/ic_logo.xml) and the qeli-win GDI+ renderer: a blue "Q" ring +
/// tail with a green link-node, on a dark navy field. Rendered with SkiaSharp so it is
/// pixel-identical across platforms. Produces the app icon, the in-window logo and the
/// menu-bar status indicator. All methods return PNG bytes; <see cref="Ui"/> turns
/// those into Avalonia bitmaps/icons.
/// </summary>
public static class Branding
{
    // Brand palette. The "Q" is a gradient ring (blue → green) with a glowing
    // link-node endpoint, evoking a secure tunnel from carrier to node.
    private static readonly SKColor RingBlue = FromRgb(BrandPalette.RingBlue);
    private static readonly SKColor RingGreen = FromRgb(BrandPalette.RingGreen);
    private static readonly SKColor NodeGreen = FromRgb(BrandPalette.NodeGreen);
    private static readonly SKColor FieldDark = FromRgb(BrandPalette.FieldDark);
    private static readonly SKColor FieldGlow = FromRgb(BrandPalette.FieldGlow);

    // Status colors: green = connected, yellow = connecting, gray = disconnected, red = error.
    public static readonly SKColor StatusDisconnected = FromRgb(BrandPalette.StatusDisconnected);
    public static readonly SKColor StatusConnecting = FromRgb(BrandPalette.StatusConnecting);
    public static readonly SKColor StatusConnected = FromRgb(BrandPalette.StatusConnected);
    public static readonly SKColor StatusError = FromRgb(BrandPalette.StatusError);

    private static SKColor FromRgb(BrandPalette.Rgb c) => new(c.R, c.G, c.B);

    // ── public renderers ────────────────────────────────────────────────────────

    /// <summary>The brand mark alone on a transparent field (for the in-window header).</summary>
    public static byte[] LogoPng(int size)
    {
        using var surface = NewSurface(size);
        DrawMark(surface.Canvas, size * 0.06f, size * 0.06f, size * 0.88f);
        return Encode(surface);
    }

    /// <summary>The full app icon: brand mark on a rounded dark-navy field.</summary>
    public static byte[] AppIconPng(int size)
    {
        using var surface = NewSurface(size);
        var g = surface.Canvas;
        float pad = size * 0.04f;
        var field = new SKRect(pad, pad, size - pad, size - pad);
        using (var fill = new SKPaint { IsAntialias = true, Shader = LinearGradient(field, FieldGlow, FieldDark, 55f) })
            g.DrawRoundRect(field, size * 0.20f, size * 0.20f, fill);
        DrawMark(g, size * 0.16f, size * 0.16f, size * 0.68f);
        return Encode(surface);
    }

    /// <summary>Menu-bar status indicator: a bold "Q" in the status color with a soft
    /// contrast outline so it stays legible on light and dark menu bars.</summary>
    public static byte[] TrayPng(SKColor status)
    {
        const int S = 32;
        using var surface = NewSurface(S);
        var g = surface.Canvas;
        using var typeface = SKTypeface.FromFamilyName(".AppleSystemUIFont", SKFontStyle.Bold)
                             ?? SKTypeface.Default;
        using var text = new SKPaint { IsAntialias = true, Typeface = typeface, TextSize = 27f, TextAlign = SKTextAlign.Left };
        using var path = text.GetTextPath("Q", 0, 0);

        // Centre the glyph within the 32×32 field.
        var b = path.Bounds;
        path.Transform(SKMatrix.CreateTranslation(
            (S - b.Width) / 2f - b.Left, (S - b.Height) / 2f - b.Top - 1f));

        using (var outline = new SKPaint
        {
            IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = 2.4f,
            StrokeJoin = SKStrokeJoin.Round, Color = new SKColor(0, 0, 0, 150),
        })
            g.DrawPath(path, outline);
        using (var fill = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Fill, Color = status })
            g.DrawPath(path, fill);
        return Encode(surface);
    }

    /// <summary>
    /// Write a macOS <c>.icns</c> icon from the app-icon renderer — a pure-managed
    /// container of PNG entries, so the .app icon is produced cross-platform without
    /// the macOS <c>sips</c>/<c>iconutil</c> tools. Each entry is an OSType + a
    /// big-endian length + PNG data (the format macOS 10.7+ reads).
    /// </summary>
    public static void WriteIcns(string path, params (string type, int size)[] entries)
    {
        var rendered = entries.Select(e => (e.type, png: AppIconPng(e.size))).ToList();
        int total = 8 + rendered.Sum(r => 8 + r.png.Length);

        using var fs = File.Create(path);
        void U32Be(uint v) { fs.WriteByte((byte)(v >> 24)); fs.WriteByte((byte)(v >> 16)); fs.WriteByte((byte)(v >> 8)); fs.WriteByte((byte)v); }

        fs.Write(Encoding.ASCII.GetBytes("icns"), 0, 4);
        U32Be((uint)total);
        foreach (var (type, png) in rendered)
        {
            fs.Write(Encoding.ASCII.GetBytes(type), 0, 4);
            U32Be((uint)(png.Length + 8));
            fs.Write(png, 0, png.Length);
        }
    }

    /// <summary>Canonical icon-set entries for the app bundle (.icns).</summary>
    public static (string type, int size)[] IcnsEntries => new[]
    {
        ("icp4", 16), ("icp5", 32), ("icp6", 64),
        ("ic07", 128), ("ic08", 256), ("ic09", 512), ("ic10", 1024),
        ("ic11", 32), ("ic12", 64), ("ic13", 256), ("ic14", 512),
    };

    // ── primitives ──────────────────────────────────────────────────────────────

    /// <summary>Draw the brand mark inside the given square (logical 48-unit viewport).</summary>
    private static void DrawMark(SKCanvas g, float x, float y, float size)
    {
        int saved = g.Save();
        g.Translate(x, y);
        g.Scale(size / 48f);

        var bbox = new SKRect(2f, 2f, 46f, 46f);

        // Q ring: gradient stroke (blue top-left → green bottom-right).
        using (var ring = new SKPaint
        {
            IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = 6.5f,
            Shader = LinearGradient(bbox, RingBlue, RingGreen, 55f),
        })
            g.DrawOval(new SKRect(24f - 16.5f, 24f - 16.5f, 24f + 16.5f, 24f + 16.5f), ring);

        // Glassy inner highlight on the upper-left arc for a bit of depth.
        using (var hi = new SKPaint
        {
            IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = 1.5f,
            Color = new SKColor(255, 255, 255, 70),
        })
        using (var arc = new SKPath())
        {
            arc.AddArc(new SKRect(24f - 13f, 24f - 13f, 24f + 13f, 24f + 13f), 145f, 120f);
            g.DrawPath(arc, hi);
        }

        // Tail: bold rounded segment flowing out toward the node.
        using (var tail = new SKPaint
        {
            IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = 6.5f,
            StrokeCap = SKStrokeCap.Round, Color = RingGreen,
        })
            g.DrawLine(30.5f, 30.5f, 42f, 42f, tail);

        // Link-node endpoint with a glowing light core.
        using (var glow = new SKPaint { IsAntialias = true, Color = new SKColor(NodeGreen.Red, NodeGreen.Green, NodeGreen.Blue, 70) })
            g.DrawCircle(42f, 42f, 7.5f, glow);
        using (var node = new SKPaint { IsAntialias = true, Color = NodeGreen })
            g.DrawCircle(42f, 42f, 5f, node);
        using (var core = new SKPaint { IsAntialias = true, Color = new SKColor(240, 255, 245, 235) })
            g.DrawCircle(42f, 42f, 1.9f, core);

        g.RestoreToCount(saved);
    }

    /// <summary>A linear gradient across <paramref name="r"/> at the given angle (degrees),
    /// matching GDI+ <c>LinearGradientBrush(rect, c1, c2, angle)</c> semantics.</summary>
    private static SKShader LinearGradient(SKRect r, SKColor c1, SKColor c2, float angleDeg)
    {
        double rad = angleDeg * Math.PI / 180.0;
        float dx = (float)Math.Cos(rad), dy = (float)Math.Sin(rad);
        var center = new SKPoint(r.MidX, r.MidY);
        float half = (Math.Abs(dx) * r.Width + Math.Abs(dy) * r.Height) / 2f;
        var p0 = new SKPoint(center.X - dx * half, center.Y - dy * half);
        var p1 = new SKPoint(center.X + dx * half, center.Y + dy * half);
        return SKShader.CreateLinearGradient(p0, p1, new[] { c1, c2 }, null, SKShaderTileMode.Clamp);
    }

    private static SKSurface NewSurface(int size)
    {
        var surface = SKSurface.Create(new SKImageInfo(size, size, SKColorType.Rgba8888, SKAlphaType.Premul));
        surface.Canvas.Clear(SKColors.Transparent);
        return surface;
    }

    private static byte[] Encode(SKSurface surface)
    {
        using var image = surface.Snapshot();
        using var data = image.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }
}
