-- Active Infinity for LuaJIT (FFI binding over the C ABI).
--
--   local ai = require("active_infinity")
--   local image = ai.read_file("module.ainf")
--   ai.validate(image)
--   print(ai.content_hash_hex(image))
--
-- Works with LuaJIT (the `ffi` module); plain Lua 5.x needs a C bridge.

local ffi = require("ffi")

ffi.cdef [[
typedef enum active_infinity_status {
    ACTIVE_INFINITY_OK = 0,
    ACTIVE_INFINITY_INVALID = -1,
    ACTIVE_INFINITY_BUFFER_TOO_SMALL = -2,
    ACTIVE_INFINITY_PANIC = -3
} active_infinity_status;

uint32_t active_infinity_abi_version(void);
const char *active_infinity_version(void);
const char *active_infinity_last_error(void);
uint8_t *active_infinity_alloc(size_t len);
void active_infinity_free(uint8_t *ptr, size_t len);
int32_t active_infinity_validate(const uint8_t *ptr, size_t len);
int32_t active_infinity_content_hash(const uint8_t *ptr, size_t len, uint8_t out32[32]);
int32_t active_infinity_reencode(const uint8_t *ptr, size_t len, uint8_t *out, size_t *out_len);
int32_t active_infinity_from_active(const uint8_t *source, size_t source_len,
                                    const char *name, uint8_t *out, size_t *out_len);
int32_t active_infinity_redacted_json(const uint8_t *ptr, size_t len,
                                      uint8_t *out, size_t *out_len);
]]

local library = os.getenv("ACTIVE_INFINITY_LIB") or "active_infinity_ffi"
local lib = ffi.load(library)

local M = { ABI = 1 }

if lib.active_infinity_abi_version() ~= M.ABI then
  error("infinity/abi-mismatch: ABI " .. tostring(lib.active_infinity_abi_version()))
end

local function last_error()
  local text = lib.active_infinity_last_error()
  return text ~= nil and ffi.string(text) or "infinity/unknown"
end

local function check(status)
  if status ~= 0 then
    error(string.format("%s (status %d)", last_error(), status))
  end
end

local function with_input(bytes, callback)
  if #bytes == 0 then
    return callback(nil, 0)
  end
  local pointer = lib.active_infinity_alloc(#bytes)
  ffi.copy(pointer, bytes, #bytes)
  local ok, result = pcall(callback, pointer, #bytes)
  lib.active_infinity_free(pointer, #bytes)
  if not ok then
    error(result, 0)
  end
  return result
end

local function output(bytes, call)
  return with_input(bytes, function(pointer, length)
    local size = ffi.new("size_t[1]", 0)
    local status = call(pointer, length, nil, size)
    if status ~= -2 then
      check(status)
      return ""
    end
    local required = tonumber(size[0])
    if required == 0 then
      return ""
    end
    local out = ffi.new("uint8_t[?]", required)
    size[0] = required
    check(call(pointer, length, out, size))
    return ffi.string(out, tonumber(size[0]))
  end)
end

function M.read_file(path)
  local file = assert(io.open(path, "rb"))
  local bytes = file:read("*a")
  file:close()
  return bytes
end

function M.validate(bytes)
  with_input(bytes, function(pointer, length)
    check(lib.active_infinity_validate(pointer, length))
  end)
  return true
end

function M.content_hash(bytes)
  local out = ffi.new("uint8_t[32]")
  with_input(bytes, function(pointer, length)
    check(lib.active_infinity_content_hash(pointer, length, out))
  end)
  return ffi.string(out, 32)
end

function M.content_hash_hex(bytes)
  return (M.content_hash(bytes):gsub(".", function(char)
    return string.format("%02x", string.byte(char))
  end))
end

function M.reencode(bytes)
  return output(bytes, function(pointer, length, out, size)
    return lib.active_infinity_reencode(pointer, length, out, size)
  end)
end

function M.redacted_json(bytes)
  return output(bytes, function(pointer, length, out, size)
    return lib.active_infinity_redacted_json(pointer, length, out, size)
  end)
end

function M.from_active(source, name)
  return with_input(source, function(pointer, length)
    local name_bytes = (name or "module.active") .. "\0"
    local size = ffi.new("size_t[1]", 0)
    local status = lib.active_infinity_from_active(pointer, length, name_bytes, nil, size)
    if status ~= -2 then
      check(status)
      return ""
    end
    local required = tonumber(size[0])
    local out = ffi.new("uint8_t[?]", required)
    size[0] = required
    check(lib.active_infinity_from_active(pointer, length, name_bytes, out, size))
    return ffi.string(out, tonumber(size[0]))
  end)
end

return M
