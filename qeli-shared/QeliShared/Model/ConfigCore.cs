using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace Qeli.Shared.Model;

/// Thin ABI 1.16 adapter. Profiles are INI; JSON is only the native service envelope.
public static unsafe class ConfigCore
{
    [DllImport("qeli", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint qeli_client_abi_version();
    [DllImport("qeli", CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_config_request(byte* input, nuint length, byte* output, nuint capacity, out nuint size);
    public static JsonElement Call(object request)
    {
        uint abi = qeli_client_abi_version();
        if (abi >> 16 != 1 || (abi & 65535) < 16)
            throw new InvalidOperationException("Configuration editor requires Qeli native ABI 1.16 or newer.");
        byte[] input = JsonSerializer.SerializeToUtf8Bytes(request);
        byte[] output = new byte[4096];
        try
        {
            if (input.Length > 2 * 1024 * 1024) throw new ArgumentException("Configuration request too large.");
            fixed (byte* source = input)
            {
                int status; nuint size;
                fixed (byte* target = output) status = qeli_config_request(source, (nuint)input.Length, target, (nuint)output.Length, out size);
                if (status == -6)
                {
                    if (size > 4 * 1024 * 1024) throw new InvalidOperationException("Configuration response too large.");
                    CryptographicOperations.ZeroMemory(output);
                    output = new byte[(int)size];
                    fixed (byte* target = output) status = qeli_config_request(source, (nuint)input.Length, target, (nuint)output.Length, out size);
                }
                if (status != 0 || size > (nuint)output.Length) throw new InvalidOperationException($"Configuration ABI error ({status}).");
                using var doc = JsonDocument.Parse(output.AsMemory(0, (int)size));
                if (!doc.RootElement.GetProperty("ok").GetBoolean()) throw new ArgumentException(doc.RootElement.GetProperty("error").GetString());
                return doc.RootElement.GetProperty("result").Clone();
            }
        }
        finally { CryptographicOperations.ZeroMemory(input); CryptographicOperations.ZeroMemory(output); }
    }
    public static JsonElement Policy(string operation, object? data = null) => Call(new { version=1, op="policy", operation, data });
}
