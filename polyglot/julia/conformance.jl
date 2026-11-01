# Conformance test for the Julia binding.
#
#   julia polyglot/julia/conformance.jl
#
# Validates every valid vector, reproduces its manifest content hash, re-encodes
# canonically, compiles Active text, and checks that the redaction canary never
# leaves the projection.

include(joinpath(@__DIR__, "ActiveInfinity.jl"))

using .ActiveInfinity

const ROOT = normpath(joinpath(@__DIR__, "..", ".."))

function manifest_cases()
    text = read(joinpath(ROOT, "conformance", "manifest.json"), String)
    # kind "valid" is followed by this case's name, path and content_hash.
    pattern = r"\"kind\": \"valid\"[\s\S]*?\"name\": \"([^\"]+)\"[\s\S]*?\"path\": \"([^\"]+)\"[\s\S]*?\"content_hash\": \"([0-9a-f]{64})\""
    return [(String(m.captures[1]), String(m.captures[2]), String(m.captures[3]))
            for m in eachmatch(pattern, text)]
end

function main()
    cases = manifest_cases()
    length(cases) >= 4 || error("the manifest must list at least four valid cases")
    checked = 0
    for (name, path, expected) in cases
        data = read(joinpath(ROOT, path))
        validate(data)
        actual = content_hash_hex(data)
        actual == expected || error("$name: content hash $actual, expected $expected")
        canonical = reencode(data)
        if name == "non_canonical"
            canonical == data && error("$name: a non-canonical image re-encoded unchanged")
        else
            canonical == data || error("$name: re-encode changed canonical bytes")
        end
        checked += 1
    end

    source = "port = 8080\nname = \"julia\"\n"
    first = from_active(source, "julia.active")
    second = from_active(source, "julia.active")
    first == second || error("from_active is not deterministic")
    validate(first)

    full = read(joinpath(ROOT, "tests", "vectors", "valid", "full.ainf"))
    redacted = redacted_json(full)
    occursin("CANARY_SECRET_", redacted) && error("the redacted projection leaked the canary")
    startswith(redacted, "{") || error("the redacted projection is not JSON")

    malformed = UInt8[0xff, 0xff, 0xff]
    refused = false
    try
        validate(malformed)
    catch failure
        failure isa ActiveInfinityError || rethrow()
        startswith(failure.code, "infinity/") || rethrow()
        refused = true
    end
    refused || error("malformed input was accepted")

    println("Julia conformance PASS ($checked vectors, ABI $(abi_version()))")
    return 0
end

exit(main())
