using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

namespace QeliWin;

/// <summary>
/// Single source of truth for the Qeli brand mark, ported from the Android vector
/// logo (res/drawable/ic_logo.xml): a blue "Q" ring + tail with a green link-node,
/// on a dark navy field. Renders the app icon, the in-window logo and the
/// OpenVPN-style "little window" tray indicator (status shown by the window chrome).
/// </summary>
public static class Branding
{
    // Brand palette. The "Q" is a gradient ring (blue → green) with a glowing
    // link-node endpoint, evoking a secure tunnel from carrier to node.
    private static readonly Color RingBlue = Color.FromArgb(0x49, 0x90, 0xFF);
    private static readonly Color RingGreen = Color.FromArgb(0x21, 0xC8, 0x6A);
    private static readonly Color NodeGreen = Color.FromArgb(0x10, 0xE0, 0x77);
    private static readonly Color FieldDark = Color.FromArgb(0x14, 0x1E, 0x33);
    private static readonly Color FieldGlow = Color.FromArgb(0x1B, 0x3C, 0x6E);

    // Tray status colors: green = connected, yellow = connecting/disconnecting,
    // gray = disconnected/offline, red = error.
    public static readonly Color StatusDisconnected = Color.FromArgb(0x9A, 0xA4, 0xB0);
    public static readonly Color StatusConnecting = Color.FromArgb(0xF2, 0xC0, 0x44);
    public static readonly Color StatusConnected = Color.FromArgb(0x35, 0xC7, 0x59);
    public static readonly Color StatusError = Color.FromArgb(0xE5, 0x53, 0x4B);

    // ── public renderers ────────────────────────────────────────────────────────

    /// <summary>The brand mark alone on a transparent field (for the in-window header).</summary>
    public static byte[] LogoPng(int size)
    {
        using var bmp = new Bitmap(size, size);
        using (var g = NewGraphics(bmp))
            DrawMark(g, size * 0.06f, size * 0.06f, size * 0.88f, withTail: true);
        return ToPng(bmp);
    }

    /// <summary>The full app icon: brand mark on a rounded dark-navy field.</summary>
    public static byte[] AppIconPng(int size)
    {
        using var bmp = new Bitmap(size, size);
        using (var g = NewGraphics(bmp))
        {
            float pad = size * 0.04f;
            var field = new RectangleF(pad, pad, size - 2 * pad, size - 2 * pad);
            using (var path = RoundedRect(field, size * 0.20f))
            using (var fill = new LinearGradientBrush(field, FieldGlow, FieldDark, 55f))
                g.FillPath(fill, path);
            DrawMark(g, size * 0.16f, size * 0.16f, size * 0.68f, withTail: true);
        }
        return ToPng(bmp);
    }

    /// <summary>OpenVPN-style tray indicator: a little app "window" whose title bar and
    /// border carry the status color, with the Qeli mark on the screen.</summary>
    public static Icon TrayIcon(Color status)
    {
        using var bmp = RenderTray(status);
        return BitmapToIcon(bmp);
    }

    /// <summary>Same tray indicator as a PNG (for previews/documentation).</summary>
    public static byte[] TrayPng(Color status)
    {
        using var bmp = RenderTray(status);
        return ToPng(bmp);
    }

    private static Bitmap RenderTray(Color status)
    {
        const int S = 32;
        var bmp = new Bitmap(S, S);
        using (var g = NewGraphics(bmp))
        {
            // A single bold "Q" glyph in the status color. A soft contrast outline keeps
            // it legible on both light and dark taskbars.
            using var family = new FontFamily("Segoe UI");
            using var fmt = new StringFormat
            {
                Alignment = StringAlignment.Center,
                LineAlignment = StringAlignment.Center,
            };
            using var path = new GraphicsPath();
            path.AddString("Q", family, (int)FontStyle.Bold, 27f, new RectangleF(0, -1, S, S), fmt);

            using (var outline = new Pen(Color.FromArgb(150, 0, 0, 0), 2.4f) { LineJoin = LineJoin.Round })
                g.DrawPath(outline, path);
            using (var fill = new SolidBrush(status))
                g.FillPath(fill, path);
        }
        return bmp;
    }

    /// <summary>Write a multi-size .ico (PNG-compressed entries) for the exe file icon.</summary>
    public static void WriteIco(string path, params int[] sizes)
    {
        var pngs = sizes.Select(AppIconPng).ToArray();
        using var fs = File.Create(path);
        using var bw = new BinaryWriter(fs);
        bw.Write((short)0);              // reserved
        bw.Write((short)1);              // type: icon
        bw.Write((short)sizes.Length);   // image count
        int offset = 6 + 16 * sizes.Length;
        for (int i = 0; i < sizes.Length; i++)
        {
            int s = sizes[i];
            bw.Write((byte)(s >= 256 ? 0 : s)); // width  (0 = 256)
            bw.Write((byte)(s >= 256 ? 0 : s)); // height
            bw.Write((byte)0);   // palette
            bw.Write((byte)0);   // reserved
            bw.Write((short)1);  // color planes
            bw.Write((short)32); // bits per pixel
            bw.Write(pngs[i].Length);
            bw.Write(offset);
            offset += pngs[i].Length;
        }
        foreach (var p in pngs) bw.Write(p);
    }

    // ── primitives ──────────────────────────────────────────────────────────────

    /// <summary>Draw the brand mark inside the given square (logical 48-unit viewport).</summary>
    private static void DrawMark(Graphics g, float x, float y, float size, bool withTail)
    {
        var state = g.Save();
        g.TranslateTransform(x, y);
        g.ScaleTransform(size / 48f, size / 48f);

        var bbox = new RectangleF(2f, 2f, 44f, 44f);

        // Q ring: gradient stroke (blue top-left → green bottom-right).
        using (var grad = new LinearGradientBrush(bbox, RingBlue, RingGreen, 55f))
        using (var ring = new Pen(grad, 6.5f))
            g.DrawEllipse(ring, 24f - 16.5f, 24f - 16.5f, 33f, 33f);

        // Glassy inner highlight on the upper-left arc for a bit of depth.
        using (var hi = new Pen(Color.FromArgb(70, 255, 255, 255), 1.5f))
            g.DrawArc(hi, 24f - 13f, 24f - 13f, 26f, 26f, 145f, 120f);

        // Tail: bold rounded segment flowing out toward the node.
        if (withTail)
            using (var tail = new Pen(RingGreen, 6.5f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                g.DrawLine(tail, 30.5f, 30.5f, 42f, 42f);

        // Link-node endpoint with a glowing light core.
        using (var glow = new SolidBrush(Color.FromArgb(70, NodeGreen.R, NodeGreen.G, NodeGreen.B)))
            g.FillEllipse(glow, 42f - 7.5f, 42f - 7.5f, 15f, 15f);
        using (var node = new SolidBrush(NodeGreen))
            g.FillEllipse(node, 42f - 5f, 42f - 5f, 10f, 10f);
        using (var core = new SolidBrush(Color.FromArgb(235, 240, 255, 245)))
            g.FillEllipse(core, 42f - 1.9f, 42f - 1.9f, 3.8f, 3.8f);

        g.Restore(state);
    }

    private static GraphicsPath RoundedRect(RectangleF r, float radius)
    {
        float d = radius * 2f;
        var p = new GraphicsPath();
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    private static Graphics NewGraphics(Bitmap bmp)
    {
        var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.Clear(Color.Transparent);
        return g;
    }

    private static byte[] ToPng(Bitmap bmp)
    {
        using var ms = new MemoryStream();
        bmp.Save(ms, ImageFormat.Png);
        return ms.ToArray();
    }

    private static Icon BitmapToIcon(Bitmap bmp)
    {
        IntPtr h = bmp.GetHicon();
        using var tmp = Icon.FromHandle(h);
        return (Icon)tmp.Clone();
    }
}
