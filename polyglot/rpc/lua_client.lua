-- Thin Active RPC client over native ARP1 on TCP (LuaJIT FFI).
--
--   luajit polyglot/rpc/lua_client.lua

local ffi = require("ffi")

ffi.cdef [[
struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char sin_zero[8];
};
int socket(int domain, int type, int protocol);
int connect(int fd, const struct sockaddr *addr, unsigned int length);
long send(int fd, const void *buffer, unsigned long length, int flags);
long recv(int fd, void *buffer, unsigned long length, int flags);
int close(int fd);
uint16_t htons(uint16_t value);
uint32_t inet_addr(const char *text);
char *getenv(const char *name);
]]

local libc = ffi.C
local budget = { 10000, 67108864, 5000, 100000, 256, 100000, 10000000 }

local function u32(value)
  return string.char(value % 256, math.floor(value / 256) % 256,
                     math.floor(value / 65536) % 256, math.floor(value / 16777216) % 256)
end

local function u64(value)
  local low = value % 4294967296
  local high = math.floor(value / 4294967296)
  return u32(low) .. u32(high)
end

local function put_string(buffer, text)
  return buffer .. u32(#text) .. text
end

local function request(id, method, payload, cap)
  local buffer = "ARP1" .. string.char(1, 1, 0, 0) .. u64(id)
  buffer = put_string(buffer, method) .. u32(0) .. u32(#payload) .. payload
  if cap == nil then
    return buffer .. u32(0)
  end
  buffer = buffer .. u32(1) .. cap .. u32(1) .. put_string("", "echo")
  for _, value in ipairs(budget) do
    buffer = buffer .. u64(value)
  end
  return buffer .. string.char(0, 0, 0)
end

local function read_all(fd, length)
  local buffer = ffi.new("char[?]", length)
  local offset = 0
  while offset < length do
    local received = tonumber(libc.recv(fd, buffer + offset, length - offset, 0))
    if received <= 0 then error("recv failed") end
    offset = offset + received
  end
  return ffi.string(buffer, length)
end

local function call(address, envelope)
  local host, port = address:match("^(.+):(%d+)$")
  local fd = libc.socket(2, 1, 0)
  if fd < 0 then error("socket failed") end
  local target = ffi.new("struct sockaddr_in")
  target.sin_family = 2
  target.sin_port = libc.htons(tonumber(port))
  target.sin_addr = libc.inet_addr(host)
  if libc.connect(fd, ffi.cast("const struct sockaddr *", target),
                  ffi.sizeof("struct sockaddr_in")) ~= 0 then
    libc.close(fd)
    error("connect failed")
  end
  local frame = u32(#envelope) .. envelope
  local offset = 0
  while offset < #frame do
    local sent = tonumber(libc.send(fd, frame:sub(offset + 1), #frame - offset, 0))
    if sent <= 0 then libc.close(fd); error("send failed") end
    offset = offset + sent
  end
  local header = read_all(fd, 4)
  local length = header:byte(1) + header:byte(2) * 256 + header:byte(3) * 65536 + header:byte(4) * 16777216
  local body = read_all(fd, length)
  libc.close(fd)
  if body:sub(1, 4) ~= "ARP1" or body:byte(5) ~= 1 then error("bad magic") end
  local method_length = body:byte(17) + body:byte(18) * 256 + body:byte(19) * 65536 + body:byte(20) * 16777216
  return body:byte(6), body:sub(21, 20 + method_length), body
end

local function require_env(name)
  local value = libc.getenv(name)
  if value == nil then error(name .. " is required") end
  return ffi.string(value)
end

local address = require_env("ACTIVE_RPC_ADDR")
local cap_hex = require_env("ACTIVE_RPC_CAP")
local payload_path = require_env("ACTIVE_RPC_PAYLOAD")
if #cap_hex ~= 32 then error("ACTIVE_RPC_CAP must be 32 hex characters") end
local cap = cap_hex:gsub("%x%x", function(pair)
  return string.char(tonumber(pair, 16))
end)

local file = assert(io.open(payload_path, "rb"))
local payload = file:read("*a")
file:close()

local function u32_at(data, index)
  local a, b, c, d = data:byte(index, index + 3)
  return a + b * 256 + c * 65536 + d * 16777216
end

local kind, method, body = call(address, request(42, "echo", payload, cap))
local echo_ok = false
if kind == 2 then
  local caps = u32_at(body, #body - 3)
  local echoed = body:sub(#body - 3 - #payload, #body - 4)
  echo_ok = caps == 0 and echoed == payload and u32_at(body, 9) == 42
end
assert(echo_ok, "echo failed: " .. tostring(kind) .. " " .. tostring(method))

kind, method = call(address, request(43, "refuse", payload, cap))
assert(kind == 3 and method == "rpc/method-not-granted",
       "refusal mismatch: " .. tostring(kind) .. " " .. tostring(method))

kind, method = call(address, request(44, "echo", payload, nil))
assert(kind == 3 and method == "rpc/unknown-capability",
       "missing capability mismatch: " .. tostring(kind) .. " " .. tostring(method))

print("Lua thin RPC PASS (echo, refusal, missing capability)")
