"""
Active Infinity binding for Julia.

The library is the Rust reference through the frozen C ABI, so bytes cannot
drift between languages. Point `ACTIVE_INFINITY_LIB` at the shared library, or
leave it unset to let the loader search.

    julia polyglot/julia/conformance.jl
"""
module ActiveInfinity

export ABI_VERSION, ActiveInfinityError, Image, abi_version, content_hash,
       content_hash_hex, from_active, redacted_json, reencode, validate,
       validate_canonical

const ABI_VERSION = Int32(1)

# `ccall` takes a global variable holding the library name, so resolve it once.
const LIBRARY_NAME = let configured = get(ENV, "ACTIVE_INFINITY_LIB", "")
    isempty(configured) ? "active_infinity_ffi" : configured
end

struct ActiveInfinityError <: Exception
    code::String
end

Base.showerror(io::IO, error::ActiveInfinityError) =
    print(io, "Active Infinity: ", error.code)

"""Copy the calling thread's error code immediately: the next call frees it."""
function last_error()::String
    pointer = ccall((:active_infinity_last_error, LIBRARY_NAME), Cstring, ())
    return pointer == C_NULL ? "infinity/unavailable" : unsafe_string(pointer)
end

function check(status::Integer)
    status == 0 && return nothing
    throw(ActiveInfinityError(last_error()))
end

abi_version() = Int32(ccall((:active_infinity_abi_version, LIBRARY_NAME), UInt32, ()))

validate(image::AbstractVector{UInt8}) =
    check(ccall((:active_infinity_validate, LIBRARY_NAME), Int32,
                (Ptr{UInt8}, Csize_t), image, length(image)))

validate_canonical(image::AbstractVector{UInt8}) =
    check(ccall((:active_infinity_validate_canonical, LIBRARY_NAME), Int32,
                (Ptr{UInt8}, Csize_t), image, length(image)))

function content_hash(image::AbstractVector{UInt8})::Vector{UInt8}
    out = Vector{UInt8}(undef, 32)
    check(ccall((:active_infinity_content_hash, LIBRARY_NAME), Int32,
                (Ptr{UInt8}, Csize_t, Ptr{UInt8}), image, length(image), out))
    return out
end

content_hash_hex(image::AbstractVector{UInt8}) =
    join(string.(content_hash(image), base = 16, pad = 2), "")

"""Re-encode an image (canonical bytes), sizing the buffer by the query."""
function reencode(image::AbstractVector{UInt8})::Vector{UInt8}
    capacity = Ref{Csize_t}(0)
    status = ccall((:active_infinity_reencode, LIBRARY_NAME), Int32,
                   (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ref{Csize_t}),
                   image, length(image), C_NULL, capacity)
    status == -2 || check(status)
    out = Vector{UInt8}(undef, capacity[])
    status = ccall((:active_infinity_reencode, LIBRARY_NAME), Int32,
                   (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ref{Csize_t}),
                   image, length(image), out, capacity)
    check(status)
    resize!(out, capacity[])
    return out
end

"""The redacted JSON projection of an image."""
function redacted_json(image::AbstractVector{UInt8})::String
    capacity = Ref{Csize_t}(0)
    status = ccall((:active_infinity_redacted_json, LIBRARY_NAME), Int32,
                   (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ref{Csize_t}),
                   image, length(image), C_NULL, capacity)
    status == -2 || check(status)
    out = Vector{UInt8}(undef, capacity[])
    status = ccall((:active_infinity_redacted_json, LIBRARY_NAME), Int32,
                   (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ref{Csize_t}),
                   image, length(image), out, capacity)
    check(status)
    resize!(out, capacity[])
    return String(out)
end

"""Compile Active text through the reference implementation.

The name is NUL-terminated and at most 4096 bytes, per the C header.
"""
function from_active(source::AbstractString, name::AbstractString)::Vector{UInt8}
    source_bytes = Vector{UInt8}(codeunits(source))
    name_bytes = vcat(Vector{UInt8}(codeunits(name)), UInt8[0x00])
    capacity = Ref{Csize_t}(0)
    status = ccall((:active_infinity_from_active, LIBRARY_NAME), Int32,
                   (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ptr{UInt8}, Ref{Csize_t}),
                   source_bytes, length(source_bytes), name_bytes, C_NULL, capacity)
    status == -2 || check(status)
    out = Vector{UInt8}(undef, capacity[])
    status = ccall((:active_infinity_from_active, LIBRARY_NAME), Int32,
                   (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ptr{UInt8}, Ref{Csize_t}),
                   source_bytes, length(source_bytes), name_bytes, out, capacity)
    check(status)
    resize!(out, capacity[])
    return out
end

"""One validated image with its identity helpers."""
struct Image
    data::Vector{UInt8}
    function Image(data::AbstractVector{UInt8})
        bytes = Vector{UInt8}(data)
        validate(bytes)
        return new(bytes)
    end
end

validate(image::Image) = validate(image.data)
content_hash(image::Image) = content_hash(image.data)
content_hash_hex(image::Image) = content_hash_hex(image.data)
reencode(image::Image) = reencode(image.data)
redacted_json(image::Image) = redacted_json(image.data)

end # module
