using System.Diagnostics;
using System.Text;

namespace QeliMac;

internal readonly record struct ToolResult(string Output, string Error, int ExitCode);

// Bounds the process AND pipe EOF; inherited descriptors cannot outlive the deadline.
internal static class ToolProcess
{
    internal static ToolResult Run(ProcessStartInfo start, int milliseconds = 20_000,
        Func<bool>? completed = null, int maximumChars = 64 * 1024)
    {
        start.UseShellExecute = false; start.CreateNoWindow = true;
        start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        start.StandardOutputEncoding = start.StandardErrorEncoding = new UTF8Encoding(false, true);
        start.Environment["LC_ALL"] = "C";
        using var deadline = new CancellationTokenSource(milliseconds);
        using var process = Process.Start(start) ?? throw new IOException("Could not start tool");
        var stdout = ReadCapped(process.StandardOutput, maximumChars, deadline.Token);
        var stderr = ReadCapped(process.StandardError, maximumChars, deadline.Token);
        try
        {
            var wait = process.WaitForExitAsync(deadline.Token);
            var all = Task.WhenAll(wait, stdout, stderr);
            while (!all.IsCompleted)
            {
                if (completed?.Invoke() == true)
                {
                    // Only the querying tool is stopped; the verified daemon remains launchd-owned.
                    try { if (!process.HasExited) process.Kill(); } catch { }
                    return new("", "", 0);
                }
                if (stdout.IsFaulted || stderr.IsFaulted)
                    throw new InvalidDataException("Tool output exceeds its budget or is invalid UTF-8");
                Task.WhenAny(all, Task.Delay(25, deadline.Token)).GetAwaiter().GetResult();
                deadline.Token.ThrowIfCancellationRequested();
            }
            all.GetAwaiter().GetResult();
            // A successful command exit alone does not prove the requested daemon outcome.
            if (completed is not null)
            {
                while (!completed())
                {
                    deadline.Token.ThrowIfCancellationRequested();
                    Task.Delay(25, deadline.Token).GetAwaiter().GetResult();
                }
                // launchctl may exit nonzero for an already-loaded job; only the outcome decides.
                return new(stdout.Result, stderr.Result, 0);
            }
            return new(stdout.Result, stderr.Result, process.ExitCode);
        }
        catch (Exception error)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            return new("", error is OperationCanceledException ? "Tool timed out before process and pipes completed" : error.Message, -1);
        }
        finally
        {
            deadline.Cancel();
            // Disposing redirected readers unblocks any outstanding reads after an early outcome.
            process.StandardOutput.Dispose(); process.StandardError.Dispose();
            _ = stdout.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            _ = stderr.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
        }
    }
    private static async Task<string> ReadCapped(StreamReader reader, int maximum, CancellationToken token)
    {
        var text = new StringBuilder(); var buffer = new char[4096];
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), token)) != 0)
        {
            if (text.Length + read > maximum) throw new InvalidDataException("Tool output exceeds its budget");
            text.Append(buffer, 0, read);
        }
        return text.ToString();
    }
    internal static void RequireSuccess(ToolResult result, string operation)
    {
        if (result.ExitCode != 0) throw new InvalidOperationException($"{operation} failed: {result.Error}");
    }
}
