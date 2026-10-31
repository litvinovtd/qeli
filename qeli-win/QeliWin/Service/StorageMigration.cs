using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;

namespace QeliWin.Service;

// Never silently promote legacy data into trusted LocalSystem input. This is a GUI-only,
// explicit, one-time quarantine; no old profile, intent flag or native image is imported.
internal static class StorageMigration
{
    internal const string MigrationMutex = @"Global\QeliWin.StorageMigration.v1";
    internal static IDisposable EnterGate()
    {
        var mutex = new Mutex(false, MigrationMutex);
        try
        {
            bool acquired;
            try { acquired = mutex.WaitOne(TimeSpan.FromSeconds(2)); }
            catch (AbandonedMutexException)
            {
                // Ownership is acquired, but a previous interrupted transaction needs inspection.
                mutex.ReleaseMutex();
                throw new IOException("Previous storage migration was interrupted; inspect its backup before retrying.");
            }
            if (!acquired) throw new IOException("Another Qeli storage transition is in progress.");
            return new Gate(mutex);
        }
        catch { mutex.Dispose(); throw; }
    }

    private sealed class Gate(Mutex mutex) : IDisposable
    {
        public void Dispose() { mutex.ReleaseMutex(); mutex.Dispose(); }
    }

    // The callback seam permits filesystem regression tests without touching SCM,
    // firewall, actual product storage, user profiles or recovery journals.
    internal static string Quarantine(string root, Action requireRecovery)
    {
        StorageLayout.RequireAncestors(root);
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0 || !Directory.Exists(root))
            throw new IOException("Storage migration refuses linked or non-directory storage.");
        return ExecuteTransaction(requireRecovery, () =>
        {
            string backup = root + ".backup-" + DateTime.UtcNow.ToString("yyyyMMddTHHmmss")
                + "-" + Guid.NewGuid().ToString("N");
            // A private wrapper also protects permissive legacy files. No tree traversal.
            new DirectoryInfo(backup).Create(StorageLayout.PrivateAcl());
            ServiceState.RequireTrusted(backup, privateFile: true);
            return backup;
        }, backup => Directory.Move(root, Path.Combine(backup, "legacy")), () =>
        {
            StorageLayout.EnsureDirectory(root);
            StorageLayout.EnsureDirectory(Path.Combine(root, "service"), privateData: true);
        });
    }

    internal static string ExecuteTransaction(Action requireRecovery, Func<string> createBackup,
        Action<string> archive, Action initialize)
    {
        requireRecovery(); // Fail before creating anything or changing the source.
        string backup = createBackup();
        requireRecovery(); // Recheck live ownership immediately before rename.
        archive(backup);
        try { initialize(); }
        catch (Exception error)
        {
            // Never roll unsafe data over a partially initialized trusted root.
            throw new IOException("Storage initialization failed; original data is retained at " + backup, error);
        }
        return backup;
    }

    internal static void CheckReadiness()
    {
        if (ServiceManager.IsInstalled())
        {
            using var service = new ServiceController(ServiceManager.ServiceName);
            if (service.Status != ServiceControllerStatus.Stopped)
                throw new IOException("Stop Qeli VPN Service and complete network recovery before migration.");
        }
        if (EventWaitHandle.TryOpenExisting(@"Global\Qeli.KillSwitch.Owner.v1", out var owner))
        {
            owner.Dispose();
            throw new IOException("A Qeli tunnel still owns the firewall; complete Disconnect first.");
        }
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id == Environment.ProcessId) continue;
                string name;
                try { name = process.ProcessName; }
                catch (InvalidOperationException) { continue; } // process exited
                if (name.StartsWith("QeliWin", StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Close other Qeli clients before migration: " + name);
                // Renamed portable EXEs keep their managed assembly filename/product identity.
                try
                {
                    var info = process.MainModule?.FileVersionInfo;
                    if (info?.OriginalFilename?.Equals("QeliWin.dll", StringComparison.OrdinalIgnoreCase) == true
                        || info?.OriginalFilename?.Equals("QeliWin.exe", StringComparison.OrdinalIgnoreCase) == true
                        || info?.ProductName?.Equals("QeliWin", StringComparison.OrdinalIgnoreCase) == true)
                        throw new IOException("Close the other Qeli client before migration (pid " + process.Id + ").");
                }
                catch (System.ComponentModel.Win32Exception) { } // unrelated protected OS processes
                catch (InvalidOperationException) { } // exited during enumeration
            }
        }
        foreach (string local in new[] {
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "config", "systemprofile", "AppData", "Local") })
            if (StorageLayout.Exists(Path.Combine(local, "qeli", "killswitch.state")))
                throw new IOException("A Qeli firewall recovery journal remains; finish recovery with its owning client/account first.");

        // Read-only: do not reset DNS, routes or firewall merely to pass migration.
        // Unknown/failed inspection blocks migration. The user also confirms successful
        // recovery in the prompt; an absent process is not proof of restored DNS/routes.
        string script = "$ErrorActionPreference='Stop'; " +
            "$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Group -eq 'qeli_ks' }); " +
            "$adapters=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -like '*Wintun*' }); " +
            "if($rules.Count -or $adapters.Count){exit 2}; 'QELI_RECOVERY_CHECK_OK'";
        var command = new ProcessStartInfo(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"));
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script)) }) command.ArgumentList.Add(arg);
        var result = WindowsCommand.RunAsync(command, TimeSpan.FromSeconds(15)).GetAwaiter().GetResult();
        if (result.ExitCode != 0 || result.Output.Trim() != "QELI_RECOVERY_CHECK_OK")
            throw new IOException("Network recovery is incomplete or cannot be verified (firewall rules / Wintun adapter). No migration was performed.");
    }
}
