using System.Diagnostics;
using System.IO;
using System.Text;

namespace QeliWin;

internal readonly record struct WindowsCommandResult(int ExitCode, string Output, string Error);

internal static class WindowsCommand
{
    private const int MaximumDiagnosticChars = 4096;
    internal static async Task<WindowsCommandResult> RunAsync(ProcessStartInfo info, TimeSpan budget)
    {
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        using var deadline = new CancellationTokenSource(budget);
        using var process = Process.Start(info) ?? throw new IOException("Cannot launch command");
        // Drain both pipes concurrently. Capture only a bounded prefix; continue draining.
        var stdout = DrainAsync(process.StandardOutput, deadline.Token);
        var stderr = DrainAsync(process.StandardError, deadline.Token);
        try
        {
            await Task.WhenAll(process.WaitForExitAsync(deadline.Token), stdout, stderr).ConfigureAwait(false);
            return new(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
        catch
        {
            bool timedOut = deadline.IsCancellationRequested;
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            deadline.Cancel();
            // Observe cancelled/faulted drain tasks too; no unobserved failure escapes disposal.
            try { await Task.WhenAll(stdout, stderr).ConfigureAwait(false); } catch { }
            if (timedOut)
            {
                var error = new TimeoutException($"Command exceeded {budget.TotalSeconds:g} seconds: {info.FileName} (pid {process.Id})");
                error.Data["ProcessId"] = process.Id;
                throw error;
            }
            throw;
        }
    }

    private static async Task<string> DrainAsync(StreamReader reader, CancellationToken cancellation)
    {
        var result = new StringBuilder();
        var buffer = new char[2048];
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellation).ConfigureAwait(false)) != 0)
        {
            int keep = Math.Min(read, MaximumDiagnosticChars - result.Length);
            if (keep > 0) result.Append(buffer, 0, keep);
        }
        return result.ToString();
    }
}
