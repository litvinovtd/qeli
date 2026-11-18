using System.Reflection;

namespace Qeli.Shared.Vpn;

internal static class ClientApplicationLog
{
    // Use the GUI/CLI entry assembly, not the shared runtime library's version.
    internal static string BuildDescription(Assembly? application = null)
    {
        application ??= Assembly.GetEntryAssembly() ?? typeof(ClientApplicationLog).Assembly;
        string version = application.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? application.GetName().Version?.ToString() ?? "unknown";
        return $"Qeli application={application.GetName().Name} version={version} " +
            $"platform={System.Runtime.InteropServices.RuntimeInformation.OSDescription}";
    }
}
