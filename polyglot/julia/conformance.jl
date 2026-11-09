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

function manifest_invalid_cases()
    text = read(joinpath(ROOT, "conformance", "manifest.json"), String)
    # kind "invalid" (with the closing quote, so "invalid_stream" never
    # matches) is followed by this case's name, path and expected_code.
    pattern = r"\"kind\": \"invalid\"[\s\S]*?\"name\": \"([^\"]+)\"[\s\S]*?\"path\": \"([^\"]+)\"[\s\S]*?\"options\": \\{([^}]*)\\}[\s\S]*?\"expected_code\": \"([^\"]+)\""
    return [(String(m.captures[1]), String(m.captures[2]), String(m.captures[3]), String(m.captures[4]))
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

    # INF-POLY-02: every invalid vector must be refused with exactly the
    # manifest's expected_code. INF-FFI-02: the two limits-dependent ones
    # (limit, too_deep) go through validate_with_limits with the narrowed
    # budget from the entry's options.limits (max_nodes:1, max_depth:8);
    # the rest go through validate_canonical. invalid_stream vectors are
    # CLI-only: no stream decode exists in the FFI.
    invalid_cases = manifest_invalid_cases()
    length(invalid_cases) == 35 || error("the manifest must list exactly 35 invalid cases")
    invalid_checked = 0
    for (name, path, options, expected) in invalid_cases
        data = read(joinpath(ROOT, path))
        refused = false
        try
            limits_match = match(r"\"limits\": \"([^\"]+)\"", options)
            if limits_match !== nothing
                field, value = split(limits_match.captures[1], ":")
                limits = Limits()
                set_limit!(limits, field, parse(Int, value))
                validate_with_limits(data, limits)
            else
                validate_canonical(data)
            end
        catch failure
            failure isa ActiveInfinityError || rethrow()
            failure.code == expected || error("$name: wrong code $(failure.code)")
            refused = true
        end
        refused || error("$name: invalid image was accepted")
        invalid_checked += 1
    end
    invalid_checked + invalid_skipped == 35 || error("the manifest invalid vectors were not exercised")
    invalid_skipped == 2 || error("the limits-dependent skips changed")

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
