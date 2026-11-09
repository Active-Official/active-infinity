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
    if path:find("non_canonical", 1, true) then
      -- NF-INF02-01: validate and content_hash prove the canonical form
      -- (INF-02), so a non-canonical image is refused; reencode is the
      -- repair path.
      local ok, message = pcall(function() ai.validate(image) end)
      assert(not ok, "non-canonical image was validated")
      assert(type(message) == "table" and message.code == "infinity/not-canonical",
             "wrong code: " .. tostring(message.code))
      local ok_hash, message_hash = pcall(function() ai.content_hash_hex(image) end)
      assert(not ok_hash, "non-canonical image was hashed")
      assert(type(message_hash) == "table" and message_hash.code == "infinity/not-canonical",
             "wrong code: " .. tostring(message_hash.code))
      -- INF-POLY-03: the binding surfaces validate_canonical; it must
      -- refuse the non-canonical image with the same code.
      local ok_canon, message_canon = pcall(function() ai.validate_canonical(image) end)
      assert(not ok_canon, "non-canonical image passed validate_canonical")
      assert(type(message_canon) == "table" and message_canon.code == "infinity/not-canonical",
             "wrong code: " .. tostring(message_canon.code))
    else
      ai.validate(image)
      ai.validate_canonical(image)
      local actual = ai.content_hash_hex(image)
      if actual ~= expected then
        error(string.format("%s: hash %s, want %s", path, actual, expected))
      end
    end
    local canonical = ai.reencode(image)
    if path:find("non_canonical", 1, true) then
      if canonical == image then
        error(path .. ": expected re-encoding to change bytes")
      end
      ai.validate(canonical)
    elseif canonical ~= image then
      error(path .. ": canonical bytes changed")
    end
    checked = checked + 1
  end
end

-- INF-POLY-03: pin the exact count, derived from the manifest -- a
-- slack `>=` let a dropped vector pass silently.
local _, valid = manifest:gsub('"kind": "valid"', "")
assert(checked == valid, "manifest vectors exercised: " .. checked .. " of " .. valid)

-- INF-POLY-02: every invalid vector except the two limits-dependent ones
-- (limit, too_deep) must be refused by validate_canonical with exactly the
-- manifest's expected_code. The FFI exposes no limits parameter, so those
-- two need narrowed limits (max_nodes:1, max_depth:8) and are covered by
-- the CLI's `conformance run` and the Rust suite instead. invalid_stream
-- vectors are CLI-only: no stream decode exists in the FFI. The scan below
-- matches `"kind": "invalid"` (with the closing quote, so it never matches
-- `"kind": "invalid_stream"`) followed by the case's name, path and
-- expected_code.
local invalid_checked = 0
local invalid_skipped = 0
for name, path, expected in manifest:gmatch('"kind": "invalid".-"name"%s*:%s*"([^"]+)".-"path"%s*:%s*"([^"]+)".-"expected_code"%s*:%s*"([^"]+)"') do
  local image = read(path)
  if name == "limit" or name == "too_deep" then
    invalid_skipped = invalid_skipped + 1
  else
    local ok, message = pcall(function() ai.validate_canonical(image) end)
    assert(not ok, name .. ": invalid image was accepted")
    assert(type(message) == "table" and message.code == expected,
           name .. ": wrong code: " .. tostring(message.code) .. ", want " .. expected)
    invalid_checked = invalid_checked + 1
  end
end
local _, invalid_total = manifest:gsub('"kind": "invalid"', "")
assert(invalid_checked + invalid_skipped == invalid_total,
       "invalid vectors exercised: " .. invalid_checked .. " + " .. invalid_skipped .. " of " .. invalid_total)
assert(invalid_skipped == 2, "limits-dependent skips changed: " .. invalid_skipped)

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
assert(type(message) == "table", "expected a structured error, got " .. type(message))
assert(type(message.code) == "string" and message.code:find("^infinity/"),
       "unstable code: " .. tostring(message.code))
assert(type(message.status) == "number" and message.status < 0,
       "missing failure status: " .. tostring(message.status))
assert(tostring(message):find("infinity/", 1, true), "message lost the code")

print(string.format("Lua conformance PASS (%d vectors, ABI %d)", checked, ai.ABI))
