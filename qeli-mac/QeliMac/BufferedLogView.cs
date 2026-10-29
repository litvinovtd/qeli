using Avalonia.Controls;
using Avalonia.Threading;
using Qeli.Shared.Model;

namespace QeliMac;

/// <summary>UI-thread owner of the log presentation; never owns VPN/log collection.</summary>
internal sealed class BufferedLogView : IDisposable
{
    private readonly TextBox _view;
    private readonly DesktopLogBuffer _logs;
    private readonly Func<string> _key;
    private readonly DispatcherTimer _timer;
    private string? _renderedKey;
    private long _revision = -1;
    private bool _active;

    internal BufferedLogView(TextBox view, DesktopLogBuffer logs, Func<string> key)
    {
        _view = view;
        _logs = logs;
        _key = key;
        // Read-only does not disable Avalonia's programmatic-text undo snapshots.
        _view.IsUndoEnabled = false;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _timer.Tick += Tick;
    }

    internal void SetActive(bool active)
    {
        if (_active == active) return;
        _active = active;
        if (active)
        {
            Flush();
            _timer.Start();
        }
        else
        {
            _timer.Stop();
            _view.Text = ""; // Release text layout/history, NOT the diagnostic buffer.
            _renderedKey = null;
            _revision = -1;
        }
    }

    private void Tick(object? sender, EventArgs e) => Flush();

    internal void Flush()
    {
        if (!_active) return;
        string key = _key();
        if (!_logs.TryRead(key, key == _renderedKey ? _revision : -1, out long revision, out var text)) return;
        _view.Text = text;
        _view.CaretIndex = text!.Length;
        _renderedKey = key;
        _revision = revision;
    }

    public void Dispose()
    {
        SetActive(false);
        _timer.Stop();
        _timer.Tick -= Tick;
    }
}
