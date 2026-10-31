using System.Globalization;

namespace QeliCli;

internal sealed class CliFailure(int exitCode, string code, string message) : Exception(message)
{
    internal int ExitCode { get; } = exitCode;
    internal string Code { get; } = code;
}

internal sealed record CommandLine(string Command, IReadOnlyDictionary<string,string> Values,
    bool Json, bool JsonLines, bool Follow)
{
    internal string? Config => Values.GetValueOrDefault("config");
    internal int Timeout => Number("timeout", 60, 3600);
    internal int? Duration => Values.ContainsKey("duration") ? Number("duration", 0, 86400) : null;
    private int Number(string name, int fallback, int maximum)
    {
        if (!Values.TryGetValue(name, out var text)) return fallback;
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int value)
            || value < 1 || value > maximum) throw Usage($"--{name} must be 1..{maximum} seconds");
        return value;
    }
    internal static CliFailure Usage(string message) => new(2,"usage",message);
    internal static CommandLine Parse(string[] args)
    {
        var values = new Dictionary<string,string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);
        var words = new List<string>();
        for (int i=0;i<args.Length;i++)
        {
            string arg=args[i];
            if (!arg.StartsWith('-')) { words.Add(arg); continue; }
            if (arg is "--json" or "--json-lines" or "--follow" or "--help" or "--version")
            { if(!flags.Add(arg)) throw Usage($"Duplicate option {arg}"); continue; }
            if (arg is not ("--config" or "--timeout" or "--duration" or "--state" or "--export"))
                throw Usage("Unknown option; use --help");
            if (++i>=args.Length || args[i].StartsWith("--")) throw Usage($"Missing value for {arg}");
            if (!values.TryAdd(arg[2..],args[i])) throw Usage($"Duplicate option {arg}");
        }
        string command=string.Join(' ',words);
        if(flags.Contains("--help") || args.Length==0) command="help";
        else if(flags.Contains("--version")) command="version";
        string[] allowed=command switch {
            "help" or "version" or "status" or "disconnect" => command=="disconnect" ? ["timeout"] : [],
            "config validate" or "probe" => ["config"],
            "run" => ["config","timeout","duration"],
            "connect" => ["config","timeout"],
            "wait" => ["timeout","state"],
            "logs" => [],
            "service install" or "service start" or "service stop" or "service uninstall" => ["timeout"],
            "licenses" => ["export"],
            _=>throw Usage("Unknown command; use --help")
        };
        if(values.Keys.Except(allowed).Any()) throw Usage("Option is not supported by this command");
        bool json=flags.Contains("--json"), lines=flags.Contains("--json-lines"),follow=flags.Contains("--follow");
        if(json && lines) throw Usage("Choose --json or --json-lines");
        if(follow && command!="logs") throw Usage("--follow is supported by logs only");
        if(lines && command is not ("logs" or "run")) throw Usage("--json-lines is supported by logs and run only");
        if(json && follow) throw Usage("Use --json-lines with logs --follow");
        if(command is "config validate" or "probe" or "run" or "connect" && !values.ContainsKey("config"))
            throw Usage("--config FILE is required (use - for redirected INI input)");
        if(command=="wait" && values.GetValueOrDefault("state") is not ("connected" or "disconnected"))
            throw Usage("wait requires --state connected|disconnected");
        var result=new CommandLine(command,values,json,lines,follow);
        _=result.Timeout;_=result.Duration;
        return result;
    }
}
