using System;
using System.IO;

namespace Qeli.Shared.Model;

/// <summary>Moves an unreadable profile store aside before an empty store can be opened.</summary>
public static class ProfileStoreRecovery
{
    public static string PreserveUnreadable(string path)
    {
        var preserved = path + ".corrupt-" + Guid.NewGuid().ToString("N");
        try
        {
            File.Move(path, preserved);
        }
        catch (Exception ex)
        {
            throw new IOException(
                "The unreadable profile store could not be preserved; refusing to open an empty store.",
                ex);
        }
        return preserved;
    }
}
