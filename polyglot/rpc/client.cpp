// Thin Active RPC client over native ARP1 on TCP (C++17, POSIX sockets).
//
//   c++ -std=c++17 -O2 polyglot/rpc/client.cpp -o /tmp/rpc-client-cpp

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::uint64_t kBudget[] = {10000, 64ull << 20, 5000,    100000,
                                     256,   100000,      10000000};

void put_u32(std::vector<std::uint8_t> &out, std::uint32_t value) {
  for (int index = 0; index < 4; ++index)
    out.push_back(static_cast<std::uint8_t>(value >> (8 * index)));
}

void put_u64(std::vector<std::uint8_t> &out, std::uint64_t value) {
  for (int index = 0; index < 8; ++index)
    out.push_back(static_cast<std::uint8_t>(value >> (8 * index)));
}

void put_string(std::vector<std::uint8_t> &out, const std::string &text) {
  put_u32(out, static_cast<std::uint32_t>(text.size()));
  out.insert(out.end(), text.begin(), text.end());
}

std::vector<std::uint8_t> request(std::uint64_t id, const std::string &method,
                                  const std::vector<std::uint8_t> &payload,
                                  const std::vector<std::uint8_t> *cap) {
  std::vector<std::uint8_t> out = {'A', 'R', 'P', '1', 1, 1, 0, 0};
  put_u64(out, id);
  put_string(out, method);
  put_u32(out, 0);
  put_u32(out, static_cast<std::uint32_t>(payload.size()));
  out.insert(out.end(), payload.begin(), payload.end());
  if (cap == nullptr) {
    put_u32(out, 0);
    return out;
  }
  put_u32(out, 1);
  out.insert(out.end(), cap->begin(), cap->end());
  put_u32(out, 1);
  put_string(out, "echo");
  for (std::uint64_t value : kBudget)
    put_u64(out, value);
  out.push_back(0);
  out.push_back(0);
  out.push_back(0);
  return out;
}

void write_all(int socket, const std::uint8_t *data, std::size_t length) {
  while (length > 0) {
    const ssize_t sent = send(socket, data, length, 0);
    if (sent <= 0)
      throw std::runtime_error("send failed");
    data += sent;
    length -= static_cast<std::size_t>(sent);
  }
}

void read_all(int socket, std::uint8_t *data, std::size_t length) {
  while (length > 0) {
    const ssize_t received = recv(socket, data, length, 0);
    if (received <= 0)
      throw std::runtime_error("recv failed");
    data += received;
    length -= static_cast<std::size_t>(received);
  }
}

struct Response {
  int kind;
  std::string method;
  std::vector<std::uint8_t> body;
};

std::uint32_t read_u32(const std::uint8_t *data) {
  return static_cast<std::uint32_t>(data[0]) |
         (static_cast<std::uint32_t>(data[1]) << 8) |
         (static_cast<std::uint32_t>(data[2]) << 16) |
         (static_cast<std::uint32_t>(data[3]) << 24);
}

std::uint64_t read_u64(const std::uint8_t *data) {
  std::uint64_t value = 0;
  for (int index = 7; index >= 0; --index)
    value = (value << 8) | data[index];
  return value;
}

bool echoes(const std::vector<std::uint8_t> &body,
            const std::vector<std::uint8_t> &payload) {
  if (body.size() < payload.size() + 8)
    return false;
  if (read_u32(body.data() + body.size() - 4) != 0)
    return false;
  return std::memcmp(body.data() + body.size() - 4 - payload.size(),
                     payload.data(), payload.size()) == 0;
}

Response call(const std::string &address,
              const std::vector<std::uint8_t> &envelope) {
  const std::size_t split = address.rfind(':');
  const std::string host = address.substr(0, split);
  const int port = std::stoi(address.substr(split + 1));
  const int socket = ::socket(AF_INET, SOCK_STREAM, 0);
  if (socket < 0)
    throw std::runtime_error("socket failed");
  sockaddr_in target{};
  target.sin_family = AF_INET;
  target.sin_port = htons(static_cast<std::uint16_t>(port));
  if (inet_pton(AF_INET, host.c_str(), &target.sin_addr) != 1 ||
      connect(socket, reinterpret_cast<sockaddr *>(&target), sizeof target) !=
          0) {
    close(socket);
    throw std::runtime_error("connect failed");
  }
  const std::uint32_t size = static_cast<std::uint32_t>(envelope.size());
  std::uint8_t header[4] = {static_cast<std::uint8_t>(size),
                            static_cast<std::uint8_t>(size >> 8),
                            static_cast<std::uint8_t>(size >> 16),
                            static_cast<std::uint8_t>(size >> 24)};
  try {
    write_all(socket, header, 4);
    write_all(socket, envelope.data(), envelope.size());
    read_all(socket, header, 4);
  } catch (...) {
    close(socket);
    throw;
  }
  const std::uint32_t length = static_cast<std::uint32_t>(header[0]) |
                               (static_cast<std::uint32_t>(header[1]) << 8) |
                               (static_cast<std::uint32_t>(header[2]) << 16) |
                               (static_cast<std::uint32_t>(header[3]) << 24);
  std::vector<std::uint8_t> body(length);
  try {
    read_all(socket, body.data(), length);
  } catch (...) {
    close(socket);
    throw;
  }
  close(socket);
  if (body.size() < 20 || std::memcmp(body.data(), "ARP1", 4) != 0 ||
      body[4] != 1) {
    throw std::runtime_error("bad envelope");
  }
  const std::uint32_t method_length =
      static_cast<std::uint32_t>(body[16]) |
      (static_cast<std::uint32_t>(body[17]) << 8) |
      (static_cast<std::uint32_t>(body[18]) << 16) |
      (static_cast<std::uint32_t>(body[19]) << 24);
  return {body[5],
          std::string(reinterpret_cast<const char *>(body.data() + 20),
                      method_length),
          body};
}

std::vector<std::uint8_t> read_file(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file)
    throw std::runtime_error("cannot open payload");
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(file), {});
}

std::vector<std::uint8_t> parse_cap(const std::string &hex) {
  if (hex.size() != 32)
    throw std::runtime_error("ACTIVE_RPC_CAP must be 32 hex characters");
  std::vector<std::uint8_t> out;
  for (std::size_t index = 0; index < 32; index += 2) {
    out.push_back(static_cast<std::uint8_t>(
        std::stoul(hex.substr(index, 2), nullptr, 16)));
  }
  return out;
}

} // namespace

int main() {
  const char *address = std::getenv("ACTIVE_RPC_ADDR");
  const char *cap_hex = std::getenv("ACTIVE_RPC_CAP");
  const char *payload_path = std::getenv("ACTIVE_RPC_PAYLOAD");
  if (address == nullptr || cap_hex == nullptr || payload_path == nullptr) {
    std::fprintf(stderr, "ACTIVE_RPC_ADDR, ACTIVE_RPC_CAP and "
                         "ACTIVE_RPC_PAYLOAD are required\n");
    return 2;
  }
  const auto cap = parse_cap(cap_hex);
  const auto payload = read_file(payload_path);

  auto response = call(address, request(42, "echo", payload, &cap));
  if (response.kind != 2 || read_u64(response.body.data() + 8) != 42 ||
      !echoes(response.body, payload)) {
    std::fprintf(stderr, "echo failed: %d %s\n", response.kind,
                 response.method.c_str());
    return 1;
  }
  response = call(address, request(43, "refuse", payload, &cap));
  if (response.kind != 3 || response.method != "rpc/method-not-granted") {
    std::fprintf(stderr, "refusal mismatch: %d %s\n", response.kind,
                 response.method.c_str());
    return 1;
  }
  response = call(address, request(44, "echo", payload, nullptr));
  if (response.kind != 3 || response.method != "rpc/unknown-capability") {
    std::fprintf(stderr, "missing capability mismatch: %d %s\n", response.kind,
                 response.method.c_str());
    return 1;
  }
  std::printf("C++ thin RPC PASS (echo, refusal, missing capability)\n");
  return 0;
}
