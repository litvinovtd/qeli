using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace QeliWin.Service;

internal sealed record ServiceRegistration(string Command, string Account, uint Type, byte[] Security)
{
    internal static void Validate(ServiceRegistration registration, string executable, Action<string> protectedLocation)
    {
        // Accept exactly the registration created by Qeli; do not parse arbitrary SCM
        // command lines or silently migrate another executable/account into this GUI.
        string expected = $"\"{executable}\" --service";
        if (!registration.Command.Equals(expected, StringComparison.OrdinalIgnoreCase)
            || !registration.Account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase)
            || registration.Type != 0x10)
            throw new InvalidOperationException("Service registration differs from this Qeli executable/LocalSystem worker. Stop and reinstall from the protected installed copy.");
        var unsafeAccess = UntrustedAccess(registration.Security);
        if (unsafeAccess != null)
            throw new InvalidOperationException($"Refusing untrusted service registration: {unsafeAccess}. Stop and repair/reinstall the service.");
        protectedLocation(executable); // Re-check actual file, ancestors, owner and ACL.
    }

    internal static string? UntrustedAccess(byte[] security)
    {
        static bool Trusted(SecurityIdentifier? sid) => sid != null &&
            (sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
             || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
             || sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        var descriptor = new RawSecurityDescriptor(security, 0);
        if (!Trusted(descriptor.Owner)) return "untrusted service owner";
        if (descriptor.DiscretionaryAcl == null) return "unrestricted service DACL";
        // Service-object rights, not filesystem rights: CHANGE_CONFIG, DELETE,
        // WRITE_DAC, WRITE_OWNER and generic write/all can redirect SYSTEM startup.
        const int dangerous = 0x0002 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
        foreach (GenericAce ace in descriptor.DiscretionaryAcl)
        {
            if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
            if (ace is not QualifiedAce qualified) return "unsupported service ACE";
            if (qualified.AceQualifier == AceQualifier.AccessAllowed
                && (qualified.AccessMask & dangerous) != 0 && !Trusted(qualified.SecurityIdentifier))
                return qualified.SecurityIdentifier.Value;
        }
        return null;
    }

    internal static ServiceRegistration Read(string name)
    {
        var scm = OpenSCManager(null, null, 0x0001); // CONNECT only
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager(query) failed");
        try
        {
            var service = OpenService(scm, name, 0x0001 | 0x20000); // QUERY_CONFIG + READ_CONTROL
            if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService(query) failed");
            try
            {
                // Microsoft's QueryServiceConfig contract caps this buffer at 8 KiB.
                var buffer = Marshal.AllocHGlobal(8192);
                try
                {
                    if (!QueryServiceConfig(service, buffer, 8192, out _))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryServiceConfig failed");
                    var cfg = Marshal.PtrToStructure<Config>(buffer);
                    var security = new byte[64 * 1024];
                    if (!QueryServiceObjectSecurity(service, 1 | 4, security, (uint)security.Length, out uint required))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryServiceObjectSecurity failed");
                    if (required == 0 || required > security.Length) throw new InvalidOperationException("Invalid service security size");
                    Array.Resize(ref security, (int)required);
                    return new(Marshal.PtrToStringUni(cfg.Binary) ?? "", Marshal.PtrToStringUni(cfg.Account) ?? "", cfg.Type, security);
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(scm); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Config
    {
        internal uint Type, StartType, ErrorControl;
        internal IntPtr Binary, LoadOrder;
        internal uint Tag;
        internal IntPtr Dependencies, Account, Display;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(IntPtr service, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceObjectSecurity(IntPtr service, uint information, byte[] buffer, uint size, out uint needed);
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
