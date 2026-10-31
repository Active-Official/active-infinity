/*
 * Thin Active RPC client over native ARP1 on TCP (C, POSIX sockets).
 *
 * Build (from the repository root):
 *   cc -O2 polyglot/rpc/client.c -o /tmp/rpc-client
 *
 * Environment:
 *   ACTIVE_RPC_ADDR=127.0.0.1:PORT  ACTIVE_RPC_CAP=<32 hex>
 * ACTIVE_RPC_PAYLOAD=<ainf>
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_FRAME (1u << 20)

static uint8_t *read_file(const char *path, size_t *length) {
  FILE *file = fopen(path, "rb");
  if (file == NULL)
    return NULL;
  fseek(file, 0, SEEK_END);
  long size = ftell(file);
  rewind(file);
  uint8_t *buffer = (uint8_t *)malloc((size_t)size);
  if (buffer == NULL || fread(buffer, 1, (size_t)size, file) != (size_t)size) {
    free(buffer);
    fclose(file);
    return NULL;
  }
  fclose(file);
  *length = (size_t)size;
  return buffer;
}

static void put_u32(uint8_t *out, size_t *cursor, uint32_t value) {
  memcpy(out + *cursor, &value, 4);
  *cursor += 4;
}

static void put_u64(uint8_t *out, size_t *cursor, uint64_t value) {
  memcpy(out + *cursor, &value, 8);
  *cursor += 8;
}

static void put_str(uint8_t *out, size_t *cursor, const char *text) {
  uint32_t length = (uint32_t)strlen(text);
  put_u32(out, cursor, length);
  memcpy(out + *cursor, text, length);
  *cursor += length;
}

static void put_cap(uint8_t *out, size_t *cursor, const uint8_t id[16]) {
  static const uint64_t budget[7] = {10000, 64ull << 20, 5000,    100000,
                                     256,   100000,      10000000};
  memcpy(out + *cursor, id, 16);
  *cursor += 16;
  put_u32(out, cursor, 1);
  put_str(out, cursor, "echo");
  for (int index = 0; index < 7; index++)
    put_u64(out, cursor, budget[index]);
  out[(*cursor)++] = 0; /* read_only */
  out[(*cursor)++] = 0; /* redact */
  out[(*cursor)++] = 0; /* no path scope */
}

static size_t build_request(uint8_t *out, uint64_t request_id,
                            const char *method, const uint8_t *payload,
                            size_t payload_length, const uint8_t *cap,
                            int with_cap) {
  size_t cursor = 0;
  memcpy(out + cursor, "ARP1", 4);
  cursor += 4;
  out[cursor++] = 1; /* version */
  out[cursor++] = 1; /* kind request */
  out[cursor++] = 0;
  out[cursor++] = 0; /* flags */
  put_u64(out, &cursor, request_id);
  put_str(out, &cursor, method);
  put_u32(out, &cursor, 0); /* args */
  put_u32(out, &cursor, (uint32_t)payload_length);
  memcpy(out + cursor, payload, payload_length);
  cursor += payload_length;
  if (with_cap) {
    put_u32(out, &cursor, 1);
    put_cap(out, &cursor, cap);
  } else {
    put_u32(out, &cursor, 0);
  }
  return cursor;
}

static int send_all(int socket, const uint8_t *data, size_t length) {
  while (length > 0) {
    ssize_t sent = send(socket, data, length, 0);
    if (sent <= 0)
      return -1;
    data += sent;
    length -= (size_t)sent;
  }
  return 0;
}

static int recv_all(int socket, uint8_t *data, size_t length) {
  while (length > 0) {
    ssize_t received = recv(socket, data, length, 0);
    if (received <= 0)
      return -1;
    data += received;
    length -= (size_t)received;
  }
  return 0;
}

static uint32_t get_u32(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static uint64_t get_u64(const uint8_t *data) {
  uint64_t value = 0;
  for (int index = 7; index >= 0; index--)
    value = (value << 8) | data[index];
  return value;
}

static uint8_t *rpc_call(const char *address, const uint8_t *request,
                         size_t request_length, size_t *body_length) {
  char host[128];
  const char *colon = strrchr(address, ':');
  if (colon == NULL)
    return NULL;
  size_t host_length = (size_t)(colon - address);
  if (host_length >= sizeof host)
    return NULL;
  memcpy(host, address, host_length);
  host[host_length] = '\0';
  int port = atoi(colon + 1);

  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0)
    return NULL;
  struct sockaddr_in target = {0};
  target.sin_family = AF_INET;
  target.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host, &target.sin_addr) != 1 ||
      connect(socket_fd, (struct sockaddr *)&target, sizeof target) != 0) {
    close(socket_fd);
    return NULL;
  }

  uint8_t header[4];
  memcpy(header, &(uint32_t){(uint32_t)request_length}, 4);
  if (send_all(socket_fd, header, 4) != 0 ||
      send_all(socket_fd, request, request_length) != 0 ||
      recv_all(socket_fd, header, 4) != 0) {
    close(socket_fd);
    return NULL;
  }
  uint32_t length = get_u32(header);
  if (length < 20 || length > MAX_FRAME) {
    close(socket_fd);
    return NULL;
  }
  uint8_t *response = (uint8_t *)malloc(length);
  if (response == NULL || recv_all(socket_fd, response, length) != 0) {
    free(response);
    close(socket_fd);
    return NULL;
  }
  close(socket_fd);
  if (memcmp(response, "ARP1", 4) != 0 || response[4] != 1) {
    free(response);
    return NULL;
  }
  *body_length = length;
  return response;
}

/* A response echoes the payload as the bytes before the empty caps table. */
static int echoes_payload(const uint8_t *body, size_t length,
                          const uint8_t *payload, size_t payload_length) {
  if (length < payload_length + 8)
    return 0;
  if (get_u32(body + length - 4) != 0)
    return 0;
  return memcmp(body + length - 4 - payload_length, payload, payload_length) ==
         0;
}

static int hex_id(const char *text, uint8_t out[16]) {
  if (strlen(text) != 32)
    return -1;
  for (int index = 0; index < 16; index++) {
    unsigned value = 0;
    if (sscanf(text + index * 2, "%2x", &value) != 1)
      return -1;
    out[index] = (uint8_t)value;
  }
  return 0;
}

static int error_method_is(const uint8_t *body, size_t length,
                           const char *expected) {
  if (length < 20)
    return 0;
  uint32_t method_length = get_u32(body + 16);
  if (20 + method_length > length)
    return 0;
  return method_length == strlen(expected) &&
         memcmp(body + 20, expected, method_length) == 0;
}

int main(void) {
  const char *address = getenv("ACTIVE_RPC_ADDR");
  const char *cap_text = getenv("ACTIVE_RPC_CAP");
  const char *payload_path = getenv("ACTIVE_RPC_PAYLOAD");
  if (address == NULL || cap_text == NULL || payload_path == NULL) {
    fprintf(stderr, "ACTIVE_RPC_ADDR, ACTIVE_RPC_CAP and ACTIVE_RPC_PAYLOAD "
                    "are required\n");
    return 2;
  }
  uint8_t cap[16];
  if (hex_id(cap_text, cap) != 0) {
    fprintf(stderr, "ACTIVE_RPC_CAP must be 32 hex characters\n");
    return 2;
  }
  size_t payload_length = 0;
  uint8_t *payload = read_file(payload_path, &payload_length);
  if (payload == NULL)
    return 2;

  uint8_t request[MAX_FRAME];
  size_t body_length = 0;

  size_t length =
      build_request(request, 42, "echo", payload, payload_length, cap, 1);
  uint8_t *body = rpc_call(address, request, length, &body_length);
  if (body == NULL || body[5] != 2 || get_u64(body + 8) != 42 ||
      !echoes_payload(body, body_length, payload, payload_length)) {
    fprintf(stderr, "echo failed\n");
    free(body);
    return 1;
  }
  free(body);

  length =
      build_request(request, 43, "refuse", payload, payload_length, cap, 1);
  body = rpc_call(address, request, length, &body_length);
  if (body == NULL || body[5] != 3 ||
      !error_method_is(body, body_length, "rpc/method-not-granted")) {
    fprintf(stderr, "refusal mismatch\n");
    free(body);
    return 1;
  }
  free(body);

  length = build_request(request, 44, "echo", payload, payload_length, cap, 0);
  body = rpc_call(address, request, length, &body_length);
  if (body == NULL || body[5] != 3 ||
      !error_method_is(body, body_length, "rpc/unknown-capability")) {
    fprintf(stderr, "missing-capability mismatch\n");
    free(body);
    return 1;
  }
  free(body);

  free(payload);
  printf("C thin RPC PASS (echo, refusal, missing capability)\n");
  return 0;
}
