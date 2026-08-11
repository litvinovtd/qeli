using System.Runtime.InteropServices;

namespace QeliMac.Model;

/// <summary>Minimal Security.framework binding for one generic-password item.
/// The item is created with an explicit SecAccess ACL whose sole trusted
/// application is the current signed Qeli process.</summary>
internal static class MacKeychain
{
    private const string Security = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundation =
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const int Utf8 = 0x08000100;
    private const int Success = 0;
    private const int DuplicateItem = -25299;

    private static IntPtr _securityHandle;
    private static IntPtr _coreHandle;

    public static byte[]? Find(string service, string account)
    {
        if (!OperatingSystem.IsMacOS()) return null;
        try
        {
            var owned = new List<IntPtr>();
            IntPtr query = Dictionary(
                owned,
                (Sec("kSecClass"), Sec("kSecClassGenericPassword")),
                (Sec("kSecAttrService"), String(service, owned)),
                (Sec("kSecAttrAccount"), String(account, owned)),
                (Sec("kSecReturnData"), Core("kCFBooleanTrue")),
                (Sec("kSecMatchLimit"), Sec("kSecMatchLimitOne")));
            try
            {
                int status = SecItemCopyMatching(query, out IntPtr result);
                if (status != Success || result == IntPtr.Zero) return null;
                try
                {
                    nint length = CFDataGetLength(result);
                    if (length <= 0 || length > 4096) return null;
                    var bytes = new byte[(int)length];
                    Marshal.Copy(CFDataGetBytePtr(result), bytes, 0, bytes.Length);
                    return bytes;
                }
                finally { CFRelease(result); }
            }
            finally { ReleaseDictionary(query, owned); }
        }
        catch { return null; }
    }

    public static bool Store(string service, string account, byte[] secret)
    {
        if (!OperatingSystem.IsMacOS() || secret.Length == 0) return false;
        try
        {
            IntPtr access = CreateCurrentApplicationAccess();
            if (access == IntPtr.Zero) return false;
            try
            {
                var addOwned = new List<IntPtr>();
                IntPtr add = Dictionary(
                    addOwned,
                    (Sec("kSecClass"), Sec("kSecClassGenericPassword")),
                    (Sec("kSecAttrService"), String(service, addOwned)),
                    (Sec("kSecAttrAccount"), String(account, addOwned)),
                    (Sec("kSecValueData"), Data(secret, addOwned)),
                    (Sec("kSecAttrAccess"), access));
                int status;
                try { status = SecItemAdd(add, IntPtr.Zero); }
                finally { ReleaseDictionary(add, addOwned); }
                if (status == Success) return true;
                if (status != DuplicateItem) return false;

                // Idempotent update for an item already created by this signed app.
                var queryOwned = new List<IntPtr>();
                IntPtr query = Dictionary(
                    queryOwned,
                    (Sec("kSecClass"), Sec("kSecClassGenericPassword")),
                    (Sec("kSecAttrService"), String(service, queryOwned)),
                    (Sec("kSecAttrAccount"), String(account, queryOwned)));
                var updateOwned = new List<IntPtr>();
                IntPtr update = Dictionary(
                    updateOwned,
                    (Sec("kSecValueData"), Data(secret, updateOwned)),
                    (Sec("kSecAttrAccess"), access));
                try { return SecItemUpdate(query, update) == Success; }
                finally
                {
                    ReleaseDictionary(update, updateOwned);
                    ReleaseDictionary(query, queryOwned);
                }
            }
            finally { CFRelease(access); }
        }
        catch { return false; }
    }

    private static IntPtr CreateCurrentApplicationAccess()
    {
        // A null path means the application containing this call. Security.framework
        // stores its designated code requirement, so Developer-ID releases retain
        // access across upgrades while unrelated processes cannot silently read it.
        if (SecTrustedApplicationCreateFromPath(IntPtr.Zero, out IntPtr trusted) != Success
            || trusted == IntPtr.Zero)
            return IntPtr.Zero;
        IntPtr values = IntPtr.Zero;
        IntPtr descriptor = IntPtr.Zero;
        try
        {
            values = CFArrayCreate(
                IntPtr.Zero,
                new[] { trusted },
                1,
                Export(CoreHandle(), "kCFTypeArrayCallBacks"));
            descriptor = CFStringCreateWithCString(
                IntPtr.Zero, "Qeli profile encryption key", Utf8);
            if (values == IntPtr.Zero || descriptor == IntPtr.Zero) return IntPtr.Zero;
            return SecAccessCreate(descriptor, values, out IntPtr access) == Success
                ? access
                : IntPtr.Zero;
        }
        finally
        {
            if (descriptor != IntPtr.Zero) CFRelease(descriptor);
            if (values != IntPtr.Zero) CFRelease(values);
            CFRelease(trusted);
        }
    }

    private static IntPtr Dictionary(
        List<IntPtr> owned, params (IntPtr Key, IntPtr Value)[] entries)
    {
        IntPtr value = CFDictionaryCreate(
            IntPtr.Zero,
            entries.Select(entry => entry.Key).ToArray(),
            entries.Select(entry => entry.Value).ToArray(),
            entries.Length,
            Export(CoreHandle(), "kCFTypeDictionaryKeyCallBacks"),
            Export(CoreHandle(), "kCFTypeDictionaryValueCallBacks"));
        if (value == IntPtr.Zero) throw new InvalidOperationException("CFDictionaryCreate failed");
        return value;
    }

    private static IntPtr String(string value, List<IntPtr> owned)
    {
        IntPtr result = CFStringCreateWithCString(IntPtr.Zero, value, Utf8);
        if (result == IntPtr.Zero) throw new InvalidOperationException("CFStringCreate failed");
        owned.Add(result);
        return result;
    }

    private static IntPtr Data(byte[] value, List<IntPtr> owned)
    {
        IntPtr result = CFDataCreate(IntPtr.Zero, value, value.Length);
        if (result == IntPtr.Zero) throw new InvalidOperationException("CFDataCreate failed");
        owned.Add(result);
        return result;
    }

    private static void ReleaseDictionary(IntPtr dictionary, List<IntPtr> owned)
    {
        if (dictionary != IntPtr.Zero) CFRelease(dictionary);
        foreach (IntPtr value in owned) CFRelease(value);
    }

    private static IntPtr Sec(string name) =>
        Marshal.ReadIntPtr(Export(SecurityHandle(), name));
    private static IntPtr Core(string name) =>
        Marshal.ReadIntPtr(Export(CoreHandle(), name));
    private static IntPtr Export(IntPtr library, string name) =>
        NativeLibrary.GetExport(library, name);
    private static IntPtr SecurityHandle() =>
        _securityHandle != IntPtr.Zero
            ? _securityHandle
            : _securityHandle = NativeLibrary.Load(Security);
    private static IntPtr CoreHandle() =>
        _coreHandle != IntPtr.Zero
            ? _coreHandle
            : _coreHandle = NativeLibrary.Load(CoreFoundation);

    [DllImport(Security)]
    private static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);
    [DllImport(Security)]
    private static extern int SecItemAdd(IntPtr attributes, IntPtr result);
    [DllImport(Security)]
    private static extern int SecItemUpdate(IntPtr query, IntPtr attributesToUpdate);
    [DllImport(Security)]
    private static extern int SecTrustedApplicationCreateFromPath(
        IntPtr path, out IntPtr application);
    [DllImport(Security)]
    private static extern int SecAccessCreate(
        IntPtr descriptor, IntPtr trustedList, out IntPtr access);

    [DllImport(CoreFoundation)]
    private static extern IntPtr CFStringCreateWithCString(
        IntPtr allocator, [MarshalAs(UnmanagedType.LPUTF8Str)] string value, int encoding);
    [DllImport(CoreFoundation)]
    private static extern IntPtr CFDataCreate(
        IntPtr allocator, byte[] bytes, nint length);
    [DllImport(CoreFoundation)]
    private static extern nint CFDataGetLength(IntPtr data);
    [DllImport(CoreFoundation)]
    private static extern IntPtr CFDataGetBytePtr(IntPtr data);
    [DllImport(CoreFoundation)]
    private static extern IntPtr CFDictionaryCreate(
        IntPtr allocator, IntPtr[] keys, IntPtr[] values, nint count,
        IntPtr keyCallbacks, IntPtr valueCallbacks);
    [DllImport(CoreFoundation)]
    private static extern IntPtr CFArrayCreate(
        IntPtr allocator, IntPtr[] values, nint count, IntPtr callbacks);
    [DllImport(CoreFoundation)]
    private static extern void CFRelease(IntPtr value);
}
