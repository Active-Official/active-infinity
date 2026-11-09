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
    internal static extern int active_infinity_validate_canonical(IntPtr pointer, nuint length);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int active_infinity_limits_default(ref Limits limits);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int active_infinity_validate_with_limits(IntPtr pointer, nuint length, IntPtr limits);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int active_infinity_decode_with_limits(IntPtr pointer, nuint length, IntPtr limits, IntPtr output, out nuint outputLength);

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

/// <summary>
/// Caller-supplied budget (INF-FFI-02): one ceiling per field, in the same
/// order as the C <c>active_infinity_limits</c> struct.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct Limits
{
    public uint MaxNodes;
    public uint MaxEdges;
    public uint MaxChildren;
    public uint MaxFields;
    public uint MaxParts;
    public uint MaxStrings;
    public uint MaxStringBytes;
    public uint MaxBlobs;
    public uint MaxBlobBytes;
    public uint MaxAnnotations;
    public uint MaxUnits;
    public uint MaxTypes;
    public uint MaxAux;
    public uint MaxNumbers;
    public uint MaxSecrets;
    public uint MaxSecretBytes;
    public uint MaxExtensions;
    public uint MaxProvBytes;
    public uint MaxProvEntries;
    public uint MaxHashes;
    public uint MaxBindings;
    public ulong MaxTotalBytes;
    public ulong MaxDecodedBytes;
    public uint MaxDepth;

    /// <summary>Fill a Limits with the library defaults (via the FFI).</summary>
    public static Limits Default()
    {
        Limits limits = new();
        Native.Check(Native.active_infinity_limits_default(ref limits));
        return limits;
    }

    /// <summary>
    /// Set one ceiling by its C field name (e.g. <c>max_nodes</c>). Fails
    /// closed on an unknown name.
    /// </summary>
    public void SetField(string name, ulong value)
    {
        switch (name)
        {
            case "max_nodes": MaxNodes = (uint)value; break;
            case "max_edges": MaxEdges = (uint)value; break;
            case "max_children": MaxChildren = (uint)value; break;
            case "max_fields": MaxFields = (uint)value; break;
            case "max_parts": MaxParts = (uint)value; break;
            case "max_strings": MaxStrings = (uint)value; break;
            case "max_string_bytes": MaxStringBytes = (uint)value; break;
            case "max_blobs": MaxBlobs = (uint)value; break;
            case "max_blob_bytes": MaxBlobBytes = (uint)value; break;
            case "max_annotations": MaxAnnotations = (uint)value; break;
            case "max_units": MaxUnits = (uint)value; break;
            case "max_types": MaxTypes = (uint)value; break;
            case "max_aux": MaxAux = (uint)value; break;
            case "max_numbers": MaxNumbers = (uint)value; break;
            case "max_secrets": MaxSecrets = (uint)value; break;
            case "max_secret_bytes": MaxSecretBytes = (uint)value; break;
            case "max_extensions": MaxExtensions = (uint)value; break;
            case "max_prov_bytes": MaxProvBytes = (uint)value; break;
            case "max_prov_entries": MaxProvEntries = (uint)value; break;
            case "max_hashes": MaxHashes = (uint)value; break;
            case "max_bindings": MaxBindings = (uint)value; break;
            case "max_total_bytes": MaxTotalBytes = value; break;
            case "max_decoded_bytes": MaxDecodedBytes = value; break;
            case "max_depth": MaxDepth = (uint)value; break;
            default: throw new ArgumentException($"unknown limits field {name}", nameof(name));
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

    /// <summary>
    /// Prove the image is the canonical encoding of its own content.
    /// <see cref="Validate"/> already proves this (INF-02); this states
    /// the requirement explicitly. (INF-POLY-03)
    /// </summary>
    public Image ValidateCanonical()
    {
        WithInput(pointer => Native.active_infinity_validate_canonical(pointer, (nuint)Bytes.Length));
        return this;
    }

    /// <summary>
    /// The limits-parameterized form of <see cref="ValidateCanonical"/>.
    /// A null limits means the library defaults. (INF-FFI-02)
    /// </summary>
    public Image ValidateWithLimits(Limits? limits = null)
    {
        WithInput(pointer =>
        {
            if (limits is null)
            {
                return Native.active_infinity_validate_with_limits(pointer, (nuint)Bytes.Length, IntPtr.Zero);
            }
            Limits value = limits.Value;
            IntPtr handle = Marshal.AllocHGlobal(Marshal.SizeOf<Limits>());
            try
            {
                Marshal.StructureToPtr(value, handle, false);
                return Native.active_infinity_validate_with_limits(pointer, (nuint)Bytes.Length, handle);
            }
            finally
            {
                Marshal.FreeHGlobal(handle);
            }
        });
        return this;
    }

    /// <summary>
    /// The limits-parameterized form of <see cref="Reencode"/>. A null limits
    /// is materialized through <see cref="Limits.Default"/> so the FFI always
    /// receives a struct pointer. (INF-FFI-02)
    /// </summary>
    public byte[] DecodeWithLimits(Limits? limits = null)
    {
        Limits value = limits ?? Limits.Default();
        IntPtr handle = Marshal.AllocHGlobal(Marshal.SizeOf<Limits>());
        try
        {
            Marshal.StructureToPtr(value, handle, false);
            return Output((IntPtr input, IntPtr output, out nuint length) =>
                Native.active_infinity_decode_with_limits(input, (nuint)Bytes.Length, handle, output, out length));
        }
        finally
        {
            Marshal.FreeHGlobal(handle);
        }
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
        // The FFI caps one allocation at 1 GiB: a null pointer is a refusal.
        if (input == IntPtr.Zero && payload.Length > 0)
        {
            throw new ActiveInfinityException("infinity/limit", -1);
        }
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
        if (input == IntPtr.Zero && Bytes.Length > 0)
        {
            throw new ActiveInfinityException("infinity/limit", -1);
        }
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
