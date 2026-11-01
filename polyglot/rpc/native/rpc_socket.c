/* Blocking TCP helpers for thin ARP1 clients in languages that ship no socket
 * library of their own (Fortran, COBOL).
 *
 * This file carries bytes and nothing else: the client encodes the ARP1 frame
 * itself, so the lane still proves the language can put a real envelope on the
 * wire. Every helper returns -1 on failure; the caller reports it.
 *
 * Build: cc -O2 -shared -o librpc_socket.so rpc_socket.c   (Linux)
 *        cl /LD rpc_socket.c /Fe:rpc_socket.dll /link ws2_32.lib  (Windows)
 * or link the object directly into the Fortran/COBOL program.
 */

#if defined(_WIN32)
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET rpc_fd;
typedef int rpc_length;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int rpc_fd;
typedef socklen_t rpc_length;
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
static int rpc_started = 0;
static int rpc_start(void) {
  if (rpc_started) {
    return 0;
  }
  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
    return -1;
  }
  rpc_started = 1;
  return 0;
}
#endif

/* Connect to `host` on `port`; returns a socket handle or -1. */
int64_t arp1_connect(const char *host, int64_t port) {
#if defined(_WIN32)
  if (rpc_start() != 0) {
    return -1;
  }
#endif
  struct addrinfo hints;
  struct addrinfo *results = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  char service[16];
  snprintf(service, sizeof service, "%ld", (long)port);
  if (getaddrinfo(host, service, &hints, &results) != 0) {
    return -1;
  }
  int64_t handle = -1;
  for (struct addrinfo *entry = results; entry != NULL;
       entry = entry->ai_next) {
    rpc_fd fd =
        socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
#if defined(_WIN32)
    if (fd == INVALID_SOCKET) {
      continue;
    }
    if (connect(fd, entry->ai_addr, (int)entry->ai_addrlen) == 0) {
#else
    if (fd < 0) {
      continue;
    }
    if (connect(fd, entry->ai_addr, entry->ai_addrlen) == 0) {
#endif
      handle = (int64_t)fd;
      break;
    }
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
  }
  freeaddrinfo(results);
  return handle;
}

/* Send exactly `length` bytes; returns 0 or -1. */
int64_t arp1_send(int64_t handle, const unsigned char *buffer, int64_t length) {
  rpc_fd fd = (rpc_fd)handle;
  int64_t sent = 0;
  while (sent < length) {
#if defined(_WIN32)
    int chunk =
        send(fd, (const char *)(buffer + sent), (int)(length - sent), 0);
#else
    ssize_t chunk = send(fd, buffer + sent, (size_t)(length - sent), 0);
#endif
    if (chunk <= 0) {
      return -1;
    }
    sent += chunk;
  }
  return 0;
}

/* Read a u32 length prefix and then the body into `buffer`.
 * Returns the body length, or -1 on failure (including a body larger than
 * `capacity`). */
int64_t arp1_recv(int64_t handle, unsigned char *buffer, int64_t capacity) {
  rpc_fd fd = (rpc_fd)handle;
  unsigned char header[4];
  int64_t have = 0;
  while (have < 4) {
#if defined(_WIN32)
    int chunk = recv(fd, (char *)(header + have), (int)(4 - have), 0);
#else
    ssize_t chunk = recv(fd, header + have, (size_t)(4 - have), 0);
#endif
    if (chunk <= 0) {
      return -1;
    }
    have += chunk;
  }
  uint32_t declared = (uint32_t)header[0] | ((uint32_t)header[1] << 8) |
                      ((uint32_t)header[2] << 16) | ((uint32_t)header[3] << 24);
  if ((int64_t)declared > capacity) {
    return -1;
  }
  int64_t body = 0;
  while (body < (int64_t)declared) {
#if defined(_WIN32)
    int chunk =
        recv(fd, (char *)(buffer + body), (int)(declared - (uint32_t)body), 0);
#else
    ssize_t chunk =
        recv(fd, buffer + body, (size_t)(declared - (uint32_t)body), 0);
#endif
    if (chunk <= 0) {
      return -1;
    }
    body += chunk;
  }
  return body;
}

/* Close a socket handle. */
void arp1_close(int64_t handle) {
  rpc_fd fd = (rpc_fd)handle;
#if defined(_WIN32)
  closesocket(fd);
#else
  close(fd);
#endif
}

/* Decode 32 hex characters into 16 bytes; returns 0 or -1. */
int64_t arp1_hex16(const char *text, unsigned char *out) {
  for (int index = 0; index < 16; index++) {
    int high = 0;
    int low = 0;
    char pair[2] = {text[index * 2], text[index * 2 + 1]};
    for (int half = 0; half < 2; half++) {
      char digit = pair[half];
      int value;
      if (digit >= '0' && digit <= '9') {
        value = digit - '0';
      } else if (digit >= 'a' && digit <= 'f') {
        value = digit - 'a' + 10;
      } else if (digit >= 'A' && digit <= 'F') {
        value = digit - 'A' + 10;
      } else {
        return -1;
      }
      if (half == 0) {
        high = value;
      } else {
        low = value;
      }
    }
    out[index] = (unsigned char)((high << 4) | low);
  }
  return 0;
}

