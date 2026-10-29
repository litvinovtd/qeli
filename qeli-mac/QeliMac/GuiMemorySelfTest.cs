using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Themes.Fluent;
using Qeli.Shared.Model;
using System.Runtime.CompilerServices;

namespace QeliMac;

/// <summary>Build-tools-only tests. No profiles, privileged helpers or VPN are opened.</summary>
internal static class GuiMemorySelfTest
{
    internal static int Run()
    {
        AppBuilder.Configure<Application>()
            .UseSkia()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = true })
            .SetupWithoutStarting();
        Application.Current!.Styles.Add(new FluentTheme());
        int count = 0, failed = 0;
        void Check(string name, bool ok)
        {
            count++;
            Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}");
            if (!ok) failed++;
        }

        var logs = new DesktopLogBuffer();
        var text = new TextBox { IsReadOnly = true };
        string key = "a";
        using var view = new BufferedLogView(text, logs, () => key);
        logs.SetTarget(key);
        view.SetActive(true);
        int paints = 0;
        text.PropertyChanged += (_, change) => { if (change.Property == TextBox.TextProperty) paints++; };

        for (int i = 0; i < 10_000; i++) logs.AppendCurrent($"message {i}\n");
        Check("log bursts do not enqueue/perform per-message text updates", paints == 0);
        view.Flush();
        Check("one flush paints the complete latest log", paints == 1 && text.Text!.EndsWith("message 9999\n"));
        for (int i = 0; i < 100; i++) view.Flush();
        Check("unchanged frames do not replace textbox text", paints == 1);
        for (int i = 0; i < 100; i++) { logs.AppendCurrent($"tail {i}\n"); view.Flush(); }
        Check("read-only log never retains undo/redo history", !text.IsUndoEnabled && !text.CanUndo && !text.CanRedo);

        view.SetActive(false);
        int hiddenPaints = paints;
        logs.AppendCurrent("last message while hidden\n");
        view.Flush();
        Check("hidden presentation releases text but collection continues",
            text.Text == "" && paints == hiddenPaints && logs.Read(key).EndsWith("last message while hidden\n"));
        view.SetActive(true);
        Check("show restores the latest diagnostics without losing hidden messages",
            text.Text!.EndsWith("last message while hidden\n") && !text.CanUndo);
        key = "b";
        logs.Append(key, "other profile\n");
        view.Flush();
        Check("profile switch renders only the selected profile", text.Text == "other profile\n");
        logs.Append(key, "not yet painted\n");
        Check("copy source includes messages not yet painted", logs.Read(key).EndsWith("not yet painted\n") && text.Text == "other profile\n");
        logs.Clear(key);
        view.Flush();
        Check("clear also clears the visible text", text.Text == "" && !text.CanUndo);

        // A/B on the actual Avalonia property path, independent of process RSS:
        // the default undo host retains the old string; the optimized host does not.
        var baseline = new TextBox { IsReadOnly = true };
        var optimized = new TextBox { IsReadOnly = true, IsUndoEnabled = false };
        var baselineOld = ReplaceText(baseline);
        var optimizedOld = ReplaceText(optimized);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Check("undo-disabled textbox releases old full-text snapshots",
            baselineOld.TryGetTarget(out _) && !optimizedOld.TryGetTarget(out _));
        GC.KeepAlive(baseline);
        GC.KeepAlive(optimized);

        Console.WriteLine($"MAC_GUI_MEMORY_CHECKS={count}; FAILED={failed}");
        return failed == 0 ? 0 : 1;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference<string> ReplaceText(TextBox box)
    {
        string old = new('x', 4096);
        var weak = new WeakReference<string>(old);
        box.Text = old;
        box.Text = "replacement";
        return weak;
    }
}
