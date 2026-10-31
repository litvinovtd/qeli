namespace QeliWin.Vpn;

internal static class PersistentWintunCommands
{
    internal static int Run(string[] args)
    {
        try
        {
            if(args.Length==1 && args[0]=="list")
            {
                foreach(var key in PersistentWintunDevice.Store.Keys())
                {
                    var record=PersistentWintunDevice.Store.Read(key)!;
                    Console.WriteLine($"{key:D}  {record.InterfaceGuid:D}  {record.Name}  {(record.Network==null?"idle":"network recovery pending")}");
                }
                return 0;
            }
            if(args.Length>=2 && Guid.TryParse(args[1],out var id) && id!=Guid.Empty)
            {
                if(args[0]=="recover" && args.Length==2)
                {
                    var lease=PersistentWintunDevice.OpenExisting(id);
                    try {PersistentWintunNetwork.Recover(lease,VpnTunnel.RunPersistentCommand);}
                    finally {lease.CloseRecoveryHandle();}
                    Console.WriteLine("Persistent adapter network recovery verified; device remains installed");return 0;
                }
                if(args[0]=="remove" && args.Length==3 && args[2]=="--yes")
                {
                    PersistentWintunDevice.Remove(id,lease=>PersistentWintunNetwork.Recover(lease,VpnTunnel.RunPersistentCommand));
                    Console.WriteLine("Selected owned persistent adapter removed; shared Wintun driver retained");return 0;
                }
            }
            Console.Error.WriteLine("Administrator required. Usage: QeliWin.exe persistent-adapter list | recover KEY | remove KEY --yes");
            return 2;
        }
        catch(Exception error) {Console.Error.WriteLine("Persistent adapter: "+error.Message);return 1;}
    }
}
