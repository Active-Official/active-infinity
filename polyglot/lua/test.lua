-- LuaJIT conformance test. Run from the repository root:
--   luajit polyglot/lua/test.lua

package.path = "polyglot/lua/?.lua;" .. package.path
local ai = require("active_infinity")

local function read(path)
  local file = assert(io.open(path, "rb"))
  local bytes = file:read("*a")
  file:close()
  return bytes
end

local manifest = read("conformance/manifest.json")
local checked = 0

for path, expected in manifest:gmatch('"path"%s*:%s*"([^"]+)".-"content_hash"%s*:%s*"([^"]+)"') do
  if path:find("/valid/", 1, true) then
    local image = read(path)
    ai.validate(image)
    local actual = ai.content_hash_hex(image)
    if actual ~= expected then
      error(string.format("%s: hash %s, want %s", path, actual, expected))
    end
    local canonical = ai.reencode(image)
    if path:find("non_canonical", 1, true) then
      if canonical == image then
        error(path .. ": expected re-encoding to change bytes")
      end
    elseif canonical ~= image then
      error(path .. ": canonical bytes changed")
    end
    checked = checked + 1
  end
end

assert(checked >= 4, "manifest vectors exercised")

local source = 'port = 8080\nname = "lua"\n'
local first = ai.from_active(source, "lua.active")
local second = ai.from_active(source, "lua.active")
assert(first == second, "Active source encoding is not deterministic")
ai.validate(first)

local json = ai.redacted_json(read("tests/vectors/valid/full.ainf"))
assert(not json:find("CANARY_SECRET_", 1, true), "secret canary survived")
assert(json:find("{", 1, true), "redacted JSON looks empty")

local ok, message = pcall(function()
  ai.validate("\255\255")
end)
assert(not ok, "malformed input was accepted")
assert(message:find("infinity/", 1, true), "unstable code: " .. tostring(message))

print(string.format("Lua conformance PASS (%d vectors, ABI %d)", checked, ai.ABI))
