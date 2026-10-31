using System.Runtime.InteropServices;

namespace ActiveInfinity;

/// <summary>Stable <c>infinity/...</c> failure from the reference codec.</summary>
public sealed class ActiveInfinityException : Exception
{
    public string Code { get; }
    public int Status { get; }

    public ActiveInfinityException(string code, int status)
        : base($"{code} (status {status})")
    {
        Code = code;
        Status = status;
    }
}

internal static class Native
{
    private const string Library = "active_infinity_ffi";

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint active_infinity_abi_version();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr active_infinity_last_error();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr active_infinity_alloc(nuint length);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void active_infinity_free(IntPtr pointer, nuint length);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int active_infinity_validate(IntPtr pointer, nuint length);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int active_infinity_content_hash(IntPtr pointer, nuint length, IntPtr output);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int active_infinity_reencode(IntPtr pointer, nuint length, IntPtr output, out nuint outputLength);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int active_infinity_from_active(IntPtr source, nuint sourceLength, IntPtr name, IntPtr output, out nuint outputLength);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int active_infinity_redacted_json(IntPtr pointer, nuint length, IntPtr output, out nuint outputLength);

    internal static string LastError()
    {
        IntPtr pointer = active_infinity_last_error();
        return pointer == IntPtr.Zero ? "infinity/unknown" : Marshal.PtrToStringUTF8(pointer) ?? "infinity/unknown";
    }

    internal static void Check(int status)
    {
        if (status != 0)
        {
            throw new ActiveInfinityException(LastError(), status);
        }
    }
}

/// <summary>An AINF image with the reference operations attached.</summary>
public sealed class Image
{
    /// <summary>ABI version this binding targets.</summary>
    public const uint Abi = 1;

    public byte[] Bytes { get; }

    public Image(byte[] bytes)
    {
        if (Native.active_infinity_abi_version() != Abi)
        {
            throw new ActiveInfinityException("infinity/abi-mismatch", -1);
        }
        Bytes = bytes;
    }

    public static Image FromFile(string path) => new(File.ReadAllBytes(path));

    public Image Validate()
    {
        WithInput(pointer => Native.active_infinity_validate(pointer, (nuint)Bytes.Length));
        return this;
    }

    public byte[] ContentHash()
    {
        byte[] hash = new byte[32];
        IntPtr output = Marshal.AllocHGlobal(hash.Length);
        try
        {
            WithInput(pointer =>
            {
                int status = Native.active_infinity_content_hash(pointer, (nuint)Bytes.Length, output);
                Native.Check(status);
                return status;
            });
            Marshal.Copy(output, hash, 0, hash.Length);
            return hash;
        }
        finally
        {
            Marshal.FreeHGlobal(output);
        }
    }

    public string ContentHashHex() => Convert.ToHexString(ContentHash()).ToLowerInvariant();

    public byte[] Reencode() => Output((IntPtr input, IntPtr output, out nuint length) =>
        Native.active_infinity_reencode(input, (nuint)Bytes.Length, output, out length));

    public string RedactedJson()
    {
        byte[] json = Output((IntPtr input, IntPtr output, out nuint length) =>
            Native.active_infinity_redacted_json(input, (nuint)Bytes.Length, output, out length));
        return System.Text.Encoding.UTF8.GetString(json);
    }

    public static byte[] FromActive(string source, string name = "module.active")
    {
        byte[] sourceBytes = System.Text.Encoding.UTF8.GetBytes(source);
        byte[] nameBytes = System.Text.Encoding.UTF8.GetBytes(name + "\0");
        IntPtr namePointer = Marshal.AllocHGlobal(nameBytes.Length);
        Marshal.Copy(nameBytes, 0, namePointer, nameBytes.Length);
        try
        {
            return WithBuffer(sourceBytes, (IntPtr input, IntPtr output, out nuint length) =>
                Native.active_infinity_from_active(input, (nuint)sourceBytes.Length, namePointer, output, out length));
        }
        finally
        {
            Marshal.FreeHGlobal(namePointer);
        }
    }

    private delegate int OutputCall(IntPtr input, IntPtr output, out nuint length);

    private byte[] Output(OutputCall call) => WithBuffer(Bytes, call);

    private static byte[] WithBuffer(byte[] payload, OutputCall call)
    {
        IntPtr input = Native.active_infinity_alloc((nuint)payload.Length);
        try
        {
            Marshal.Copy(payload, 0, input, payload.Length);
            nuint length = 0;
            int status = call(input, IntPtr.Zero, out length);
            if (status != -2 || length == 0)
            {
                Native.Check(status);
                return Array.Empty<byte>();
            }
            IntPtr output = Marshal.AllocHGlobal((int)length);
            try
            {
                nuint capacity = length;
                status = call(input, output, out capacity);
                Native.Check(status);
                byte[] result = new byte[(int)capacity];
                Marshal.Copy(output, result, 0, result.Length);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(output);
            }
        }
        finally
        {
            Native.active_infinity_free(input, (nuint)payload.Length);
        }
    }

    private void WithInput(Func<IntPtr, int> action)
    {
        IntPtr input = Native.active_infinity_alloc((nuint)Bytes.Length);
        try
        {
            Marshal.Copy(Bytes, 0, input, Bytes.Length);
            Native.Check(action(input));
        }
        finally
        {
            Native.active_infinity_free(input, (nuint)Bytes.Length);
        }
    }
}
