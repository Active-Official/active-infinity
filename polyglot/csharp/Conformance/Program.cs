using System.Linq;
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
    if (name == "non_canonical")
    {
        // NF-INF02-01: validate and content_hash prove the canonical form
        // (INF-02), so a non-canonical image is refused; reencode is the
        // repair path.
        try
        {
            image.Validate();
            throw new Exception($"{name}: non-canonical image was validated");
        }
        catch (ActiveInfinityException error)
        {
            if (error.Code != "infinity/not-canonical")
            {
                throw new Exception($"{name}: wrong code {error.Code}");
            }
        }
        try
        {
            image.ContentHashHex();
            throw new Exception($"{name}: non-canonical image was hashed");
        }
        catch (ActiveInfinityException error)
        {
            if (error.Code != "infinity/not-canonical")
            {
                throw new Exception($"{name}: wrong code {error.Code}");
            }
        }
        // INF-POLY-03: the binding surfaces ValidateCanonical; it must
        // refuse the non-canonical image with the same code.
        try
        {
            image.ValidateCanonical();
            throw new Exception($"{name}: non-canonical image passed ValidateCanonical");
        }
        catch (ActiveInfinityException error)
        {
            if (error.Code != "infinity/not-canonical")
            {
                throw new Exception($"{name}: wrong code {error.Code}");
            }
        }
    }
    else
    {
        image.Validate();
        image.ValidateCanonical();

        string expected = entry.GetProperty("content_hash").GetString()!;
        if (image.ContentHashHex() != expected)
        {
            throw new Exception($"{name}: content hash mismatch");
        }
    }

    byte[] canonical = image.Reencode();
    if (name == "non_canonical")
    {
        if (canonical.AsSpan().SequenceEqual(image.Bytes))
        {
            throw new Exception($"{name}: expected re-encoding to change bytes");
        }
        new Image(canonical).Validate();
    }
    else if (!canonical.AsSpan().SequenceEqual(image.Bytes))
    {
        throw new Exception($"{name}: canonical bytes changed");
    }
    checkedCases += 1;
}

// INF-POLY-03: pin the exact count, derived from the manifest -- the test
// used to have no floor at all, so an empty run could PASS.
int validCases = manifest.RootElement.GetProperty("cases").EnumerateArray()
    .Count(entry => entry.GetProperty("kind").GetString() == "valid");
if (checkedCases != validCases)
{
    throw new Exception($"valid vectors were not exercised: {checkedCases} of {validCases}");
}

// INF-POLY-02: every invalid vector except the two limits-dependent ones
// (limit, too_deep) must be refused by ValidateCanonical with exactly the
// manifest's expected_code. The FFI exposes no limits parameter, so those
// two need narrowed limits (max_nodes:1, max_depth:8) and are covered by
// the CLI's `conformance run` and the Rust suite instead. invalid_stream
// vectors are CLI-only: no stream decode exists in the FFI.
int invalidChecked = 0;
int invalidSkipped = 0;
foreach (JsonElement entry in manifest.RootElement.GetProperty("cases").EnumerateArray())
{
    if (entry.GetProperty("kind").GetString() != "invalid")
    {
        continue;
    }
    string invalidName = entry.GetProperty("name").GetString()!;
    if (invalidName == "limit" || invalidName == "too_deep")
    {
        invalidSkipped += 1;
        continue;
    }
    string invalidPath = Path.Combine(root, entry.GetProperty("path").GetString()!);
    string expectedCode = entry.GetProperty("expected_code").GetString()!;
    Image invalidImage = Image.FromFile(invalidPath);
    try
    {
        invalidImage.ValidateCanonical();
        throw new Exception($"{invalidName}: invalid image was accepted");
    }
    catch (ActiveInfinityException error)
    {
        if (error.Code != expectedCode)
        {
            throw new Exception($"{invalidName}: wrong code {error.Code}");
        }
    }
    invalidChecked += 1;
}
int invalidTotal = manifest.RootElement.GetProperty("cases").EnumerateArray()
    .Count(entry => entry.GetProperty("kind").GetString() == "invalid");
if (invalidChecked + invalidSkipped != invalidTotal)
{
    throw new Exception($"invalid vectors were not exercised: {invalidChecked} + {invalidSkipped} of {invalidTotal}");
}
if (invalidSkipped != 2)
{
    throw new Exception($"limits-dependent skips changed: {invalidSkipped}");
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
