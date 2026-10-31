# frozen_string_literal: true

# Thin Active RPC client over native ARP1 on TCP (Ruby).
#
#   ruby polyglot/rpc/ruby_client.rb

require "socket"

MAGIC = "ARP1"
BUDGET = [10_000, 64 << 20, 5_000, 100_000, 256, 100_000, 10_000_000].freeze

def put_string(buffer, text)
  buffer << [text.bytesize].pack("V") << text.b
end

def request(id, method, payload, cap_id)
  buffer = +"ARP1".b
  buffer << [1, 1].pack("CC") << [0].pack("v") << [id].pack("Q<")
  put_string(buffer, method)
  buffer << [0].pack("V") << [payload.bytesize].pack("V") << payload
  if cap_id.nil?
    buffer << [0].pack("V")
    return buffer
  end
  buffer << [1].pack("V") << cap_id
  buffer << [1].pack("V")
  put_string(buffer, "echo")
  buffer << BUDGET.pack("Q<*") << [0, 0, 0].pack("CCC")
  buffer
end

def call(address, envelope)
  host, port = address.split(":")
  socket = TCPSocket.new(host, Integer(port))
  begin
    socket.write([envelope.bytesize].pack("V") + envelope)
    header = socket.read(4)
    raise "connection closed" if header.nil? || header.bytesize < 4

    length = header.unpack1("V")
    body = socket.read(length)
    raise "truncated frame" if body.nil? || body.bytesize < length
  ensure
    socket.close
  end
  raise "bad magic" unless body.byteslice(0, 4) == MAGIC && body.getbyte(4) == 1

  kind = body.getbyte(5)
  method_length = body.byteslice(16, 4).unpack1("V")
  method = body.byteslice(20, method_length)
  [kind, method, body]
end

address = ENV.fetch("ACTIVE_RPC_ADDR")
cap = [ENV.fetch("ACTIVE_RPC_CAP")].pack("H*")
raise "ACTIVE_RPC_CAP must be 32 hex characters" unless cap.bytesize == 16

payload = File.binread(ENV.fetch("ACTIVE_RPC_PAYLOAD"))

kind, method, body = call(address, request(42, "echo", payload, cap))
echoed = body.byteslice(-4, 4).unpack1("V").zero? &&
         body.byteslice(body.bytesize - 4 - payload.bytesize, payload.bytesize) == payload
raise "echo failed: #{kind} #{method}" unless kind == 2 && body.byteslice(8, 8).unpack1("Q<") == 42 && echoed

kind, method, = call(address, request(43, "refuse", payload, cap))
unless kind == 3 && method == "rpc/method-not-granted"
  raise "refusal mismatch: #{kind} #{method}"
end

kind, method = call(address, request(44, "echo", payload, nil))
unless kind == 3 && method == "rpc/unknown-capability"
  raise "missing capability mismatch: #{kind} #{method}"
end

puts "Ruby thin RPC PASS (echo, refusal, missing capability)"
