using System.Text;
using System.Text.Json;
using Qeli.Shared;

namespace Qeli.Conformance;

internal static class UpdateMetadataConformance
{
    internal static void Run(Action<string, bool> check)
    {
        using var ordinary = new MemoryStream(Encoding.UTF8.GetBytes("[{\"tag_name\":\"v0.8.2\"}]"));
        using var doc = UpdateChecker.ReadMetadataAsync(ordinary, CancellationToken.None).GetAwaiter().GetResult();
        check("update metadata: ordinary JSON body loads", doc.RootElement[0].GetProperty("tag_name").GetString() == "v0.8.2");

        var exact = new byte[UpdateChecker.MaximumMetadataBytes];
        Array.Fill(exact, (byte)' ');
        exact[0] = (byte)'['; exact[1] = (byte)']';
        using var exactBody = new MemoryStream(exact);
        using var exactDoc = UpdateChecker.ReadMetadataAsync(exactBody, CancellationToken.None).GetAwaiter().GetResult();
        check("update metadata: exactly 1 MiB is accepted", exactDoc.RootElement.GetArrayLength() == 0);

        using var infinite = new EndlessStream();
        bool bounded = false;
        try { using var ignored = UpdateChecker.ReadMetadataAsync(infinite, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (InvalidDataException) { bounded = true; }
        check("update metadata: an endless body stops at budget plus one byte",
            bounded && infinite.BytesRead == UpdateChecker.MaximumMetadataBytes + 1);

        using var stalled = new StalledStream();
        using var cancel = new CancellationTokenSource();
        var read = UpdateChecker.ReadMetadataAsync(stalled, cancel.Token);
        cancel.Cancel();
        bool cancelled = false;
        try { using var ignored = read.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { cancelled = true; }
        check("update metadata: body cancellation wakes a stalled read after headers", cancelled);

        using var malformed = new MemoryStream([0xff]);
        bool invalidRejected = false;
        try { using var ignored = UpdateChecker.ReadMetadataAsync(malformed, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (JsonException) { invalidRejected = true; }
        check("update metadata: malformed UTF-8/JSON is rejected", invalidRejected);
    }

    private class EndlessStream : Stream
    {
        internal long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => BytesRead; set => throw new NotSupportedException(); }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            buffer.Span.Fill((byte)' ');
            BytesRead += buffer.Length;
            return ValueTask.FromResult(buffer.Length);
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class StalledStream : EndlessStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return 0;
        }
    }
}
