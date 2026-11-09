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
    # INF-POLY-03: pin the exact count -- the manifest lists 5 valid
    # vectors. A slack `>= 4` let a dropped vector pass silently.
    length(cases) == 5 || error("the manifest must list exactly five valid cases")
    checked = 0
    for (name, path, expected) in cases
        data = read(joinpath(ROOT, path))
        if name == "non_canonical"
            # NF-INF02-01: validate and content_hash prove the canonical
            # form (INF-02), so a non-canonical image is refused; reencode
            # is the repair path.
            refused = false
            try
                validate(data)
            catch failure
                failure isa ActiveInfinityError || rethrow()
                failure.code == "infinity/not-canonical" || error("$name: wrong code $(failure.code)")
                refused = true
            end
            refused || error("$name: non-canonical image was validated")
            refused = false
            try
                content_hash_hex(data)
            catch failure
                failure isa ActiveInfinityError || rethrow()
                failure.code == "infinity/not-canonical" || error("$name: wrong code $(failure.code)")
                refused = true
            end
            refused || error("$name: non-canonical image was hashed")
            # INF-POLY-03: the binding surfaces validate_canonical; it must
            # refuse the non-canonical image with the same code.
            refused = false
            try
                validate_canonical(data)
            catch failure
                failure isa ActiveInfinityError || rethrow()
                failure.code == "infinity/not-canonical" || error("$name: wrong code $(failure.code)")
                refused = true
            end
            refused || error("$name: non-canonical image passed validate_canonical")
        else
            validate(data)
            validate_canonical(data)
            actual = content_hash_hex(data)
            actual == expected || error("$name: content hash $actual, expected $expected")
        end
        canonical = reencode(data)
        if name == "non_canonical"
            canonical == data && error("$name: a non-canonical image re-encoded unchanged")
            validate(canonical)
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
