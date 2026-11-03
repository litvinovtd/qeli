using Qeli.Shared.Vpn;

namespace Qeli.Conformance;

internal static class RouteReaderConformance
{
    internal static void Run(Action<string, bool> check)
    {
        using var mixed = new StringReader("one\r\ntwo\rthree\n\nlast");
        check("route reader: CRLF, CR, LF, empty and final lines retain their shape",
            RouteFileParser.ReadBoundedLines(mixed, CancellationToken.None)
                .SequenceEqual(new[] { "one", "two", "three", "", "last" }));
        using var exact = new StringReader(new string('#', RouteFileParser.MaximumLineCharacters));
        check("route reader: a line exactly at the budget is accepted",
            RouteFileParser.ReadBoundedLines(exact, CancellationToken.None).Single().Length
                == RouteFileParser.MaximumLineCharacters);
        using var oversized = new StringReader(new string('#', RouteFileParser.MaximumLineCharacters + 1));
        bool refused = false;
        try { _ = RouteFileParser.ReadBoundedLines(oversized, CancellationToken.None).ToArray(); }
        catch (InvalidDataException) { refused = true; }
        check("route reader: a long line is refused before unbounded ReadLine allocation", refused);

        using var cancellation = new CancellationTokenSource();
        using var endless = new CancellingReader(cancellation);
        bool cancelled = false;
        try { _ = RouteFileParser.ReadBoundedLines(endless, cancellation.Token).ToArray(); }
        catch (OperationCanceledException) { cancelled = true; }
        check("route reader: cancellation interrupts a line before its newline", cancelled && endless.Reads == 1);

        var comments = Enumerable.Repeat("#" + new string('Ж', 60_000), 8);
        check("route reader: Unicode comment batches remain below the native request budget",
            RouteFileParser.ParseLines(comments.Concat(new[] { "192.0.2.0/24" }))
                .SequenceEqual(new[] { "192.0.2.0/24" }));
    }

    private sealed class CancellingReader(CancellationTokenSource cancellation) : TextReader
    {
        internal int Reads { get; private set; }
        public override int Read(char[] buffer, int index, int count)
        {
            Reads++;
            Array.Fill(buffer, '#', index, count);
            cancellation.Cancel();
            return count;
        }
    }
}
