using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace QeliWin.Vpn;

/// <summary>Supported Software Device API + public Wintun exports. No private DLL layout.
/// https://learn.microsoft.com/windows/win32/api/swdevice/nf-swdevice-swdevicesetlifetime
/// The name property is coupled to the bundled Wintun 0.14.1 implementation; audit
/// it and requalify PnP when updating Wintun. It is not a version-independent contract.
/// Wintun's public source defines the name property used by WintunOpenAdapter:
/// https://git.zx2c4.com/wintun/tree/api/adapter.c</summary>
internal sealed class PersistentWintunNative : PersistentWintunDevice.IPlatform
{
    [StructLayout(LayoutKind.Sequential)] internal struct Key {internal Guid Id;internal uint Pid;}
    [StructLayout(LayoutKind.Sequential)] internal struct CompKey {internal Key Key;internal uint Store;internal IntPtr Locale;}
    [StructLayout(LayoutKind.Sequential)] internal struct Property {internal CompKey CompKey;internal uint Type,Size;internal IntPtr Buffer;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] internal struct CreateInfo
    {
        internal uint Size;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Instance;
        internal IntPtr HardwareIds,CompatibleIds,Container;
        internal uint Capabilities;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Description;
        internal IntPtr Location,Security;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct DevInfo {internal uint Size;internal Guid ClassGuid;internal uint DevInst;internal IntPtr Reserved;}
    private static readonly Guid NetClass = new("4d36e972-e325-11ce-bfc1-08002be10318");
    private static readonly Key NameKey = new() {Id=new("3361c968-2f2e-4660-b47e-699cdc4c32b9"),Pid=3};
    private static readonly Key OwnerKey = new() {Id=new("7a8e96cf-15d0-4d65-ad97-feb5f9071266"),Pid=2};
    private static readonly Key FriendlyKey = new() {Id=new("a45c254e-df1c-4efd-8020-67d146a850e0"),Pid=14};
    private static readonly Key HardwareKey = new() {Id=new("a45c254e-df1c-4efd-8020-67d146a850e0"),Pid=3};
    private const int WaitMs=30_000;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void Created(IntPtr device,int result,IntPtr context,IntPtr instance);
    // One process-rooted callback remains valid even after a timed-out operation. Contexts
    // are monotonic numeric IDs, not pointers to freed managed memory/GCHandles.
    private static readonly Created Callback=OnCreated;
    private static readonly ConcurrentDictionary<IntPtr,TaskCompletionSource<(int result,string id)>> Pending=new();
    private static long _nextContext;
    private static void OnCreated(IntPtr device,int result,IntPtr context,IntPtr instance)
    {
        try
        {
            if(Pending.TryGetValue(context,out var completion))
                completion.TrySetResult((result,Marshal.PtrToStringUni(instance) ?? ""));
        }
        catch { /* Never let a managed exception cross a native callback boundary. */ }
    }

    [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern int SwDeviceCreate(string enumerator,string parent,ref CreateInfo info,uint count,[In] Property[] properties,Created callback,IntPtr context,out IntPtr device);
    [DllImport("cfgmgr32.dll",ExactSpelling=true)] private static extern int SwDeviceSetLifetime(IntPtr device,int lifetime);
    [DllImport("cfgmgr32.dll",ExactSpelling=true)] private static extern void SwDeviceClose(IntPtr device);
    [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern uint CM_Locate_DevNodeW(out uint node,string? id,uint flags);
    [DllImport("cfgmgr32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern uint CM_Get_Device_IDW(uint node,StringBuilder id,uint length,uint flags);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern IntPtr SetupDiGetClassDevsW(in Guid guid,string enumerator,IntPtr parent,uint flags);
    [DllImport("setupapi.dll",SetLastError=true)] private static extern bool SetupDiEnumDeviceInfo(IntPtr list,uint index,ref DevInfo info);
    [DllImport("setupapi.dll")] private static extern bool SetupDiDestroyDeviceInfoList(IntPtr list);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern bool SetupDiGetDeviceInstanceIdW(IntPtr list,ref DevInfo info,StringBuilder text,uint size,out uint required);
    [DllImport("setupapi.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern bool SetupDiGetDevicePropertyW(IntPtr list,ref DevInfo info,in Key key,out uint type,[Out] byte[] buffer,uint size,out uint required,uint flags);
    [DllImport("setupapi.dll",SetLastError=true)] private static extern IntPtr SetupDiOpenDevRegKey(IntPtr list,ref DevInfo info,uint scope,uint profile,uint type,uint access);
    [DllImport("wintun.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern IntPtr WintunOpenAdapter(string name);
    [DllImport("wintun.dll",ExactSpelling=true)] private static extern void WintunCloseAdapter(IntPtr adapter);
    [DllImport("wintun.dll",ExactSpelling=true)] private static extern void WintunGetAdapterLUID(IntPtr adapter,out ulong luid);
    [DllImport("wintun.dll",ExactSpelling=true,SetLastError=true)] private static extern uint WintunGetRunningDriverVersion();
    [DllImport("iphlpapi.dll")] private static extern uint ConvertInterfaceLuidToGuid(in ulong luid,out Guid guid);
    [DllImport("iphlpapi.dll",CharSet=CharSet.Unicode)] private static extern uint ConvertInterfaceLuidToAlias(in ulong luid,StringBuilder alias,UIntPtr length);

    public PersistentWintunDevice.Node? Find(string name)
    {
        var list=SetupDiGetClassDevsW(NetClass,"SWD\\Wintun",IntPtr.Zero,2); // DIGCF_PRESENT: phantom registry nodes are not live devices.
        if(list==new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot inspect persistent Wintun devices");
        try
        {
            PersistentWintunDevice.Node? found=null;
            for(uint i=0;;i++)
            {
                var info=new DevInfo {Size=(uint)Marshal.SizeOf<DevInfo>()};
                if(!SetupDiEnumDeviceInfo(list,i,ref info))
                {
                    int error=Marshal.GetLastWin32Error();
                    if(error==259) break;
                    throw new Win32Exception(error,"Cannot enumerate Wintun device identity");
                }
                if(TextProperty(list,ref info,NameKey)!=name) continue;
                if(found!=null) throw new InvalidOperationException("Ambiguous persistent Wintun name");
                var hardware=TextProperty(list,ref info,HardwareKey,listValue:true);
                if(info.ClassGuid!=NetClass || !hardware.Split('\0').Contains("Wintun",StringComparer.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Named device is not an authentic Wintun hardware identity");
                var text=new StringBuilder(201);
                if(!SetupDiGetDeviceInstanceIdW(list,ref info,text,(uint)text.Capacity,out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot read Wintun device instance");
                Guid.TryParse(TextProperty(list,ref info,OwnerKey),out var token);
                var guid=Guid.Empty;
                var key=SetupDiOpenDevRegKey(list,ref info,1,0,2,0x20019);
                if(key!=new IntPtr(-1))
                {
                    using var handle=new SafeRegistryHandle(key,ownsHandle:true);
                    using var registry=RegistryKey.FromHandle(handle);
                    Guid.TryParse(registry.GetValue("NetCfgInstanceId") as string,out guid);
                }
                found=new(text.ToString(),name,token,guid);
            }
            return found;
        }
        finally {SetupDiDestroyDeviceInfoList(list);}
    }

    private static string TextProperty(IntPtr list,ref DevInfo info,Key key,bool listValue=false)
    {
        var bytes=new byte[4096];
        if(!SetupDiGetDevicePropertyW(list,ref info,key,out uint type,bytes,(uint)bytes.Length,out uint size,0))
        {
            int error=Marshal.GetLastWin32Error();
            if(error==1168) return ""; // Property not found is NOT permission denied.
            throw new Win32Exception(error,"Cannot read Wintun device property");
        }
        if(type!=(listValue?0x2012u:0x12u) || size>bytes.Length || size%2!=0)
            throw new InvalidOperationException("Unexpected Wintun device property type/length");
        return Encoding.Unicode.GetString(bytes,0,(int)size).TrimEnd('\0');
    }

    public (IntPtr device,string deviceId) Create(PersistentWintunDevice.Record record)
    {
        // Installing the bundled signed driver uses its public installer entrypoint.
        // Existing devices are never removed or replaced explicitly by this implementation.
        if(Find(record.Name)==null)
        {
            uint running=WintunGetRunningDriverVersion();
            int versionError=Marshal.GetLastWin32Error();
            if(running==0 && versionError is not (0 or 2 or 3 or 1062 or 1168))
                throw new Win32Exception(versionError,"Cannot establish whether a shared Wintun driver is in use");
            if(running!=0 && running!=0x000e0001)
                throw new InvalidOperationException("A different Wintun driver is in use; stop its VPN before installing a persistent Qeli adapter");
            using var bootstrap=new WintunAdapter();
            bootstrap.Open("Qeli-DriverInit-"+Guid.NewGuid().ToString("N")[..12],Guid.NewGuid());
        }
        if(CM_Locate_DevNodeW(out uint root,null,0)!=0) throw new InvalidOperationException("Cannot locate the Windows PnP root");
        var parent=new StringBuilder(201);
        if(CM_Get_Device_IDW(root,parent,(uint)parent.Capacity,0)!=0) throw new InvalidOperationException("Cannot read the Windows PnP root");
        var allocated=new List<IntPtr>();
        IntPtr Allocate(string text) {var p=Marshal.StringToHGlobalUni(text);allocated.Add(p);return p;}
        Property StringProperty(Key key,string text) => new() {CompKey=new() {Key=key},Type=0x12,Size=checked((uint)(text.Length+1)*2),Buffer=Allocate(text)};
        var info=new CreateInfo {Size=(uint)Marshal.SizeOf<CreateInfo>(),Instance=record.Instance,
            HardwareIds=Allocate("Wintun\0\0"),Capabilities=0xA,Description="Qeli Persistent Tunnel"};
        var properties=new[] {StringProperty(NameKey,record.Name),StringProperty(OwnerKey,record.Token.ToString("D")),StringProperty(FriendlyKey,"Qeli Persistent Tunnel")};
        var context=new IntPtr(Interlocked.Increment(ref _nextContext));
        var completion=new TaskCompletionSource<(int result,string id)>(TaskCreationOptions.RunContinuationsAsynchronously);
        if(!Pending.TryAdd(context,completion)) throw new InvalidOperationException("Persistent creation context collision");
        IntPtr device=IntPtr.Zero;
        try
        {
            Marshal.ThrowExceptionForHR(SwDeviceCreate("Wintun",parent.ToString(),ref info,(uint)properties.Length,properties,Callback,context,out device));
            if(!completion.Task.Wait(WaitMs)) throw new TimeoutException("Persistent Wintun enumeration timed out");
            var created=completion.Task.GetAwaiter().GetResult();
            Marshal.ThrowExceptionForHR(created.result);
            if(!created.id.StartsWith("SWD\\Wintun\\",StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unexpected software device identity");
            var watch=Stopwatch.StartNew();
            while(true)
            {
                var node=Find(record.Name);
                if(node!=null && node.DeviceId.Equals(created.id,StringComparison.OrdinalIgnoreCase)
                    && node.Token==record.Token && node.InterfaceGuid!=Guid.Empty) break;
                if(watch.ElapsedMilliseconds>=WaitMs) throw new TimeoutException("Persistent Wintun driver did not become ready");
                Thread.Sleep(100);
            }
            var result=device; device=IntPtr.Zero;
            return (result,created.id);
        }
        finally
        {
            if(device!=IntPtr.Zero) SwDeviceClose(device);
            Pending.TryRemove(context,out _);
            foreach(var pointer in allocated) Marshal.FreeHGlobal(pointer);
        }
    }

    public void SetLifetime(IntPtr device,bool persistent) => Marshal.ThrowExceptionForHR(SwDeviceSetLifetime(device,persistent?1:0));
    public void CloseDevice(IntPtr device) => SwDeviceClose(device);
    public PersistentWintunDevice.Handle OpenAdapter(string name)
    {
        var adapter=WintunOpenAdapter(name);
        if(adapter==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot open persistent Wintun");
        try
        {
            WintunGetAdapterLUID(adapter,out ulong luid);
            uint error=ConvertInterfaceLuidToGuid(luid,out var guid);
            if(error!=0) throw new Win32Exception((int)error,"Cannot verify persistent Wintun LUID/GUID");
            var alias=new StringBuilder(257);
            error=ConvertInterfaceLuidToAlias(luid,alias,new UIntPtr((uint)alias.Capacity));
            if(error!=0 || alias.Length==0) throw new Win32Exception((int)error,"Cannot resolve persistent interface alias");
            return new(adapter,luid,guid,alias.ToString());
        }
        catch {WintunCloseAdapter(adapter);throw;}
    }
    public void CloseAdapter(IntPtr adapter) => WintunCloseAdapter(adapter);
}
