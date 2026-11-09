# frozen_string_literal: true

# Active Infinity for Ruby (FFI binding over the C ABI).
#
#   require_relative "lib/active_infinity"
#   image = ActiveInfinity::Image.new(File.binread("module.ainf")).validate
#   image.content_hash_hex
#   image.reencode
#   image.redacted_json

require "ffi"

module ActiveInfinity
  ABI = 1

  class Error < StandardError
    attr_reader :code, :status

    def initialize(code, status)
      super("#{code} (status #{status})")
      @code = code
      @status = status
    end
  end

  extend FFI::Library

  library = ENV["ACTIVE_INFINITY_LIB"]
  if library && !library.empty?
    ffi_lib library
  else
    # One candidate per OS: the bare name resolves through the platform
    # loader where it can, and the explicit names cover the rest.
    # XPL-INF-06: the list used to name no `.dll`, so the binding could
    # not load on Windows at all.
    ffi_lib %w[active_infinity_ffi active_infinity_ffi.dll libactive_infinity_ffi.so libactive_infinity_ffi.dylib]
  end

  attach_function :active_infinity_abi_version, [], :uint32
  attach_function :active_infinity_last_error, [], :string
  attach_function :active_infinity_alloc, [:size_t], :pointer
  attach_function :active_infinity_free, %i[pointer size_t], :void
  attach_function :active_infinity_alloc_gen, %i[size_t pointer], :pointer
  attach_function :active_infinity_free_gen, %i[pointer size_t uint64], :int32
  attach_function :active_infinity_validate, %i[pointer size_t], :int32
  attach_function :active_infinity_validate_canonical, %i[pointer size_t], :int32
  attach_function :active_infinity_limits_default, [:pointer], :int32
  attach_function :active_infinity_validate_with_limits, %i[pointer size_t pointer], :int32
  attach_function :active_infinity_decode_with_limits,
                  %i[pointer size_t pointer pointer pointer], :int32

  # INF-FFI-02: caller-supplied budget, one ceiling per field, in the same
  # order as the C `active_infinity_limits` struct.
  class Limits < FFI::Struct
    layout :max_nodes, :uint32,
           :max_edges, :uint32,
           :max_children, :uint32,
           :max_fields, :uint32,
           :max_parts, :uint32,
           :max_strings, :uint32,
           :max_string_bytes, :uint32,
           :max_blobs, :uint32,
           :max_blob_bytes, :uint32,
           :max_annotations, :uint32,
           :max_units, :uint32,
           :max_types, :uint32,
           :max_aux, :uint32,
           :max_numbers, :uint32,
           :max_secrets, :uint32,
           :max_secret_bytes, :uint32,
           :max_extensions, :uint32,
           :max_prov_bytes, :uint32,
           :max_prov_entries, :uint32,
           :max_hashes, :uint32,
           :max_bindings, :uint32,
           :max_total_bytes, :uint64,
           :max_decoded_bytes, :uint64,
           :max_depth, :uint32

    def self.default
      limits = new
      ActiveInfinity.check(ActiveInfinity.active_infinity_limits_default(limits))
      limits
    end
  end
  attach_function :active_infinity_content_hash, %i[pointer size_t pointer], :int32
  attach_function :active_infinity_reencode, %i[pointer size_t pointer pointer], :int32
  attach_function :active_infinity_from_active,
                  %i[pointer size_t pointer pointer pointer], :int32
  attach_function :active_infinity_redacted_json, %i[pointer size_t pointer pointer], :int32

  raise Error.new("infinity/abi-mismatch", -1) unless active_infinity_abi_version == ABI

  module_function

  def check(status)
    unless status.zero?
      raise Error.new(active_infinity_last_error || "infinity/unknown", status)
    end
  end

  # INF-FFI-01: allocates generationally. The generation out-pointer is
  # an FFI::MemoryPointer (not an FFI allocation), so the legacy pair is
  # not involved. A refused free_gen (stale handle) is a binding bug; it
  # is ignored in `ensure` rather than raised, where it would mask the
  # operation's own error.
  def with_buffer(bytes)
    return yield(nil, 0) if bytes.empty?

    generation_out = FFI::MemoryPointer.new(:uint64)
    pointer = active_infinity_alloc_gen(bytes.bytesize, generation_out)
    # The FFI caps one allocation at 1 GiB; a null pointer is a refusal, not an
    # address to write to.
    raise Error.new("infinity/limit", -1) if pointer.null?
    generation = generation_out.read_uint64

    pointer.put_bytes(0, bytes)
    begin
      yield(pointer, bytes.bytesize)
    ensure
      active_infinity_free_gen(pointer, bytes.bytesize, generation)
    end
  end

  def output(bytes, prefix = nil)
    with_buffer(bytes) do |input, length|
      size = FFI::MemoryPointer.new(:size_t)
      size.write(:size_t, 0)
      status = if prefix
                 yield(input, length, prefix, nil, size)
               else
                 yield(input, length, nil, size)
               end
      check(status) unless status == -2
      required = size.read(:size_t)
      return "".b if required.zero?

      out = FFI::MemoryPointer.new(:uint8, required)
      size.write(:size_t, required)
      status = if prefix
                 yield(input, length, prefix, out, size)
               else
                 yield(input, length, out, size)
               end
      check(status)
      out.read_bytes(size.read(:size_t))
    end
  end

  class Image
    attr_reader :bytes

    def initialize(bytes)
      @bytes = bytes.b
    end

    def self.from_file(path)
      new(File.binread(path))
    end

    def validate
      ActiveInfinity.with_buffer(@bytes) do |input, length|
        ActiveInfinity.check(ActiveInfinity.active_infinity_validate(input, length))
      end
      self
    end

    # INF-POLY-03: `validate` already proves the canonical form (INF-02);
    # this states the requirement explicitly.
    def validate_canonical
      ActiveInfinity.with_buffer(@bytes) do |input, length|
        ActiveInfinity.check(ActiveInfinity.active_infinity_validate_canonical(input, length))
      end
      self
    end

    # INF-FFI-02: the limits-parameterized form of validate_canonical.
    # nil means the library defaults.
    def validate_with_limits(limits = nil)
      ActiveInfinity.with_buffer(@bytes) do |input, length|
        ActiveInfinity.check(
          ActiveInfinity.active_infinity_validate_with_limits(input, length, limits)
        )
      end
      self
    end

    # INF-FFI-02: the limits-parameterized form of reencode. A nil limits
    # is materialized through Limits.default() because the output helper
    # treats a nil prefix as "no prefix".
    def decode_with_limits(limits = nil)
      limits ||= Limits.default
      ActiveInfinity.output(@bytes, limits) do |input, length, limits_pointer, out, size|
        ActiveInfinity.active_infinity_decode_with_limits(
          input, length, limits_pointer, out, size
        )
      end
    end

    def content_hash
      ActiveInfinity.with_buffer(@bytes) do |input, length|
        out = FFI::MemoryPointer.new(:uint8, 32)
        ActiveInfinity.check(
          ActiveInfinity.active_infinity_content_hash(input, length, out)
        )
        out.read_bytes(32)
      end
    end

    def content_hash_hex
      content_hash.unpack1("H*")
    end

    def reencode
      ActiveInfinity.output(@bytes) do |input, length, out, size|
        ActiveInfinity.active_infinity_reencode(input, length, out, size)
      end
    end

    def redacted_json
      ActiveInfinity.output(@bytes) do |input, length, out, size|
        ActiveInfinity.active_infinity_redacted_json(input, length, out, size)
      end.force_encoding(Encoding::UTF_8)
    end

    def self.from_active(source, name = "module.active")
      payload = source.b
      name_bytes = "#{name}\0".b
      name_pointer = FFI::MemoryPointer.new(:uint8, name_bytes.bytesize)
      name_pointer.put_bytes(0, name_bytes)
      begin
        ActiveInfinity.output(payload, name_pointer) do |input, length, prefix, out, size|
          ActiveInfinity.active_infinity_from_active(input, length, prefix, out, size)
        end
      ensure
        # FFI memory is garbage collected; explicit release keeps the example
        # honest about lifetime without a native free hook.
        name_pointer.free
      end
    end
  end
end
