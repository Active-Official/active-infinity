using System.Text.Json;
using ActiveInfinity;

static string FindRoot()
{
    DirectoryInfo? directory = new(AppContext.BaseDirectory);
    while (directory is not null)
    {
        if (File.Exists(Path.Combine(directory.FullName, "conformance", "manifest.json")))
        {
            return directory.FullName;
        }
        directory = directory.Parent;
    }
    throw new InvalidOperationException("run from the repository root or its build directory");
}

string root = FindRoot();
using JsonDocument manifest = JsonDocument.Parse(
    File.ReadAllBytes(Path.Combine(root, "conformance", "manifest.json")));

int checkedCases = 0;
foreach (JsonElement entry in manifest.RootElement.GetProperty("cases").EnumerateArray())
{
    if (entry.GetProperty("kind").GetString() != "valid")
    {
        continue;
    }
    string name = entry.GetProperty("name").GetString()!;
    string path = Path.Combine(root, entry.GetProperty("path").GetString()!);
    Image image = Image.FromFile(path);
    image.Validate();

    string expected = entry.GetProperty("content_hash").GetString()!;
    if (image.ContentHashHex() != expected)
    {
        throw new Exception($"{name}: content hash mismatch");
    }

    byte[] canonical = image.Reencode();
    if (name == "non_canonical")
    {
        if (canonical.AsSpan().SequenceEqual(image.Bytes))
        {
            throw new Exception($"{name}: expected re-encoding to change bytes");
        }
    }
    else if (!canonical.AsSpan().SequenceEqual(image.Bytes))
    {
        throw new Exception($"{name}: canonical bytes changed");
    }
    checkedCases += 1;
}

string source = "port = 8080\nname = \"csharp\"\n";
byte[] first = Image.FromActive(source, "csharp.active");
byte[] second = Image.FromActive(source, "csharp.active");
if (!first.AsSpan().SequenceEqual(second))
{
    throw new Exception("Active source encoding is not deterministic");
}
new Image(first).Validate();

Image full = Image.FromFile(Path.Combine(root, "tests", "vectors", "valid", "full.ainf"));
string json = full.RedactedJson();
if (json.Contains("CANARY_SECRET_"))
{
    throw new Exception("secret canary survived redaction");
}
using (JsonDocument.Parse(json)) { }

try
{
    new Image(new byte[] { 0xff, 0xff }).Validate();
    throw new Exception("malformed input was accepted");
}
catch (ActiveInfinityException error) when (error.Code.StartsWith("infinity/", StringComparison.Ordinal))
{
}

Console.WriteLine($"C# conformance PASS ({checkedCases} vectors, ABI {Image.Abi})");
return 0;
