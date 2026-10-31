using System.Windows;
using System.Security.Principal;
using Qeli.Shared;
namespace QeliWin.Service;
internal static class StorageMigrationGui
{
    internal static bool PreparedThisLaunch { get; private set; }

    internal static async Task<bool> PrepareGuiAsync(bool automaticStartup)
    {
        try
        {
            if (!StorageLayout.MigrationNeeded(StorageLayout.Root)) return true;
            if (automaticStartup)
                throw new InvalidOperationException(Loc.T("StorageMigrationManual"));
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException(Loc.T("StorageMigrationAdmin"));
            if (MessageBox.Show(Loc.T("StorageMigrationPrompt"), Loc.T("StorageMigrationTitle"),
                    MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel)
                != MessageBoxResult.OK) return false;
            // SCM/process/PowerShell probes must not block the WPF dispatcher. The
            // thread-affine mutex is acquired and released entirely on this worker.
            string? backup = await Task.Run(() =>
            {
                using var gate = StorageMigration.EnterGate();
                if (!StorageLayout.MigrationNeeded(StorageLayout.Root)) return null;
                return StorageMigration.Quarantine(StorageLayout.Root, StorageMigration.CheckReadiness);
            });
            PreparedThisLaunch = true;
            if (backup != null)
                MessageBox.Show(Loc.F("StorageMigrationDone", backup), Loc.T("StorageMigrationTitle"),
                    MessageBoxButton.OK, MessageBoxImage.Information);
            return true;
        }
        catch (Exception error)
        {
            MessageBox.Show(Loc.F("StorageMigrationFailed", error.Message), Loc.T("StorageMigrationTitle"),
                MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
    }

}
