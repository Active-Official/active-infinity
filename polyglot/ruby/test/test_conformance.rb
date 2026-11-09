# frozen_string_literal: true

# Ruby conformance test. Run from the repository root:
#   ruby polyglot/ruby/test/test_conformance.rb

require "json"
require_relative "../lib/active_infinity"

root = File.expand_path("../../..", __dir__)
manifest = JSON.parse(File.read(File.join(root, "conformance", "manifest.json")))

checked = 0
manifest["cases"].each do |entry|
  next unless entry["kind"] == "valid"

  image = ActiveInfinity::Image.from_file(File.join(root, entry["path"]))
  if entry["name"] == "non_canonical"
    # NF-INF02-01: validate and content_hash prove the canonical form
    # (INF-02), so a non-canonical image is refused; reencode repairs it.
    begin
      image.validate
      raise "#{entry['name']}: non-canonical image was validated"
    rescue ActiveInfinity::Error => e
      raise "#{entry['name']}: wrong code #{e.code}" unless e.code == "infinity/not-canonical"
    end
    begin
      image.content_hash_hex
      raise "#{entry['name']}: non-canonical image was hashed"
    rescue ActiveInfinity::Error => e
      raise "#{entry['name']}: wrong code #{e.code}" unless e.code == "infinity/not-canonical"
    end
    # INF-POLY-03: the binding surfaces validate_canonical; it must refuse
    # the non-canonical image with the same code.
    begin
      image.validate_canonical
      raise "#{entry['name']}: non-canonical image passed validate_canonical"
    rescue ActiveInfinity::Error => e
      raise "#{entry['name']}: wrong code #{e.code}" unless e.code == "infinity/not-canonical"
    end
  else
    image.validate
    image.validate_canonical
    raise "#{entry['name']}: hash mismatch" unless image.content_hash_hex == entry["content_hash"]
  end

  canonical = image.reencode
  if entry["name"] == "non_canonical"
    raise "#{entry['name']}: expected changed bytes" if canonical == image.bytes
    ActiveInfinity::Image.new(canonical).validate
  elsif canonical != image.bytes
    raise "#{entry['name']}: canonical bytes changed"
  end
  checked += 1
end

# INF-POLY-03: pin the exact count, derived from the manifest -- the test
# used to have no floor at all, so an empty run could PASS.
valid = manifest["cases"].count { |entry| entry["kind"] == "valid" }
raise "valid vectors were not exercised: #{checked} of #{valid}" unless checked == valid

# INF-POLY-02: every invalid vector except the two limits-dependent ones
# (limit, too_deep) must be refused by validate_canonical with exactly the
# manifest's expected_code. The FFI exposes no limits parameter, so those
# two need narrowed limits (max_nodes:1, max_depth:8) and are covered by
# the CLI's `conformance run` and the Rust suite instead. invalid_stream
# vectors are CLI-only: no stream decode exists in the FFI.
invalid_checked = 0
invalid_skipped = 0
manifest["cases"].each do |entry|
  next unless entry["kind"] == "invalid"

  if entry["name"] == "limit" || entry["name"] == "too_deep"
    invalid_skipped += 1
    next
  end
  image = ActiveInfinity::Image.from_file(File.join(root, entry["path"]))
  begin
    image.validate_canonical
    raise "#{entry['name']}: invalid image was accepted"
  rescue ActiveInfinity::Error => e
    raise "#{entry['name']}: wrong code #{e.code}" unless e.code == entry["expected_code"]
  end
  invalid_checked += 1
end
invalid_total = manifest["cases"].count { |entry| entry["kind"] == "invalid" }
raise "invalid vectors were not exercised: #{invalid_checked} + #{invalid_skipped} of #{invalid_total}" unless invalid_checked + invalid_skipped == invalid_total
raise "limits-dependent skips changed: #{invalid_skipped}" unless invalid_skipped == 2

source = "port = 8080\nname = \"ruby\"\n"
first = ActiveInfinity::Image.from_active(source, "ruby.active")
second = ActiveInfinity::Image.from_active(source, "ruby.active")
raise "Active source encoding is not deterministic" unless first == second
ActiveInfinity::Image.new(first).validate

full = ActiveInfinity::Image.from_file(File.join(root, "tests/vectors/valid/full.ainf"))
json = full.redacted_json
raise "secret canary survived" if json.include?("CANARY_SECRET_")
JSON.parse(json)

begin
  ActiveInfinity::Image.new("\xff\xff".b).validate
  raise "malformed input was accepted"
rescue ActiveInfinity::Error => e
  raise "unstable code #{e.code}" unless e.code.start_with?("infinity/")
end

puts "Ruby conformance PASS (#{checked} vectors, ABI #{ActiveInfinity::ABI})"
