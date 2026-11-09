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
  else
    image.validate
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
