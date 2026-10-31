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
    ffi_lib %w[active_infinity_ffi libactive_infinity_ffi.so libactive_infinity_ffi.dylib]
  end

  attach_function :active_infinity_abi_version, [], :uint32
  attach_function :active_infinity_last_error, [], :string
  attach_function :active_infinity_alloc, [:size_t], :pointer
  attach_function :active_infinity_free, %i[pointer size_t], :void
  attach_function :active_infinity_validate, %i[pointer size_t], :int32
  attach_function :active_infinity_content_hash, %i[pointer size_t pointer], :int32
  attach_function :active_infinity_reencode, %i[pointer size_t pointer pointer], :int32
  attach_function :active_infinity_from_active,
                  %i[pointer size_t pointer pointer pointer], :int32
  attach_function :active_infinity_redacted_json, %i[pointer size_t pointer pointer], :int32

  raise Error.new("infinity/abi-mismatch", -1) unless active_infinity_abi_version == ABI

  module_function

  def check(status)
    raise Error.new(active_infinity_last_error, status) unless status.zero?
  end

  def with_buffer(bytes)
    return yield(nil, 0) if bytes.empty?

    pointer = active_infinity_alloc(bytes.bytesize)
    pointer.put_bytes(0, bytes)
    begin
      yield(pointer, bytes.bytesize)
    ensure
      active_infinity_free(pointer, bytes.bytesize)
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
