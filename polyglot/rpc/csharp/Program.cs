// Thin Active RPC client over native ARP1 on TCP (C# / .NET).
//
//   dotnet run -c Release --project polyglot/rpc/csharp/RpcClient.csproj

using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace RpcClient;

internal static class Program
{
    private static readonly ulong[] Budget = { 10000, 64UL << 20, 5000, 100000, 256, 100000, 10000000 };

    private static string Require(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"{name} is required");

    private static void PutU32(List<byte> buffer, uint value)
    {
        // ARP1 is little-endian on every host; BitConverter follows the host.
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        buffer.AddRange(bytes.ToArray());
    }

    private static void PutU64(List<byte> buffer, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
        buffer.AddRange(bytes.ToArray());
    }

    private static void PutString(List<byte> buffer, string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        PutU32(buffer, (uint)bytes.Length);
        buffer.AddRange(bytes);
    }

    private static byte[] Request(ulong id, string method, byte[] payload, byte[]? cap)
    {
        var buffer = new List<byte>();
        buffer.AddRange(Encoding.ASCII.GetBytes("ARP1"));
        buffer.AddRange(new byte[] { 1, 1 });
        buffer.AddRange(new byte[] { 0, 0 });
        PutU64(buffer, id);
        PutString(buffer, method);
        PutU32(buffer, 0);
        PutU32(buffer, (uint)payload.Length);
        buffer.AddRange(payload);
        if (cap is null)
        {
            PutU32(buffer, 0);
            return buffer.ToArray();
        }
        PutU32(buffer, 1);
        buffer.AddRange(cap);
        PutU32(buffer, 1);
        PutString(buffer, "echo");
        foreach (ulong value in Budget) PutU64(buffer, value);
        buffer.AddRange(new byte[] { 0, 0, 0 });
        return buffer.ToArray();
    }

    private static (int Kind, string Method, byte[] Body) Call(string address, byte[] envelope)
    {
        int split = address.LastIndexOf(':');
        if (split <= 0 || split == address.Length - 1)
        {
            throw new InvalidDataException("ACTIVE_RPC_ADDR must be host:port");
        }
        string host = address[..split];
        int port = int.Parse(address[(split + 1)..]);
        using var client = new TcpClient();
        client.Connect(host, port);
        using NetworkStream stream = client.GetStream();
        byte[] header = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)envelope.Length);
        stream.Write(header);
        stream.Write(envelope);
        stream.Flush();
        ReadExact(stream, header);
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length > 1u << 20)
        {
            throw new InvalidDataException("frame exceeds the ceiling");
        }
        byte[] body = new byte[length];
        ReadExact(stream, body);
        if (body.Length < 20)
        {
            throw new InvalidDataException("short envelope");
        }
        if (Encoding.ASCII.GetString(body, 0, 4) != "ARP1" || body[4] != 1)
        {
            throw new InvalidDataException("bad envelope magic");
        }
        int kind = body[5];
        int methodLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(16));
        if (methodLength < 0 || methodLength > body.Length - 20)
        {
            throw new InvalidDataException("truncated method");
        }
        string method = Encoding.UTF8.GetString(body, 20, methodLength);
        return (kind, method, body);
    }

    private static bool Echoes(byte[] body, byte[] payload)
    {
        if (body.Length < payload.Length + 8) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(body.Length - 4)) != 0) return false;
        return body.AsSpan(body.Length - 4 - payload.Length, payload.Length).SequenceEqual(payload);
    }

    private static void ReadExact(Stream stream, byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0) throw new EndOfStreamException("truncated frame");
            offset += read;
        }
    }

    public static int Main()
    {
        string address = Require("ACTIVE_RPC_ADDR");
        string capHex = Require("ACTIVE_RPC_CAP");
        byte[] cap = Convert.FromHexString(capHex);
        if (cap.Length != 16) throw new InvalidOperationException("ACTIVE_RPC_CAP must be 32 hex characters");
        byte[] payload = File.ReadAllBytes(Require("ACTIVE_RPC_PAYLOAD"));

        var echo = Call(address, Request(42, "echo", payload, cap));
        if (echo.Kind != 2 || BinaryPrimitives.ReadUInt64LittleEndian(echo.Body.AsSpan(8)) != 42 || !Echoes(echo.Body, payload))
            throw new Exception($"echo: {echo.Kind} {echo.Method}");
        var refused = Call(address, Request(43, "refuse", payload, cap));
        if (refused.Kind != 3 || refused.Method != "rpc/method-not-granted") throw new Exception($"refusal: {refused}");
        var anonymous = Call(address, Request(44, "echo", payload, null));
        if (anonymous.Kind != 3 || anonymous.Method != "rpc/unknown-capability") throw new Exception($"missing capability: {anonymous}");

        Console.WriteLine("C# thin RPC PASS (echo, refusal, missing capability)");
        return 0;
    }
}
