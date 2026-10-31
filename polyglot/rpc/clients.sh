#!/usr/bin/env bash
# Build and run commands for every thin ARP1 client.
#
# Sourced by `run_clients.sh` (against the real kernel peer) and by
# `encoder_check.sh` (against the recording socket). Nothing here reads the
# network; each `run_*` function builds if needed and starts the client.
# `client_available <name>` reports whether the runtime is installed.

build_assemblyscript() {
  mkdir -p polyglot/rpc/build
  if [ ! -f polyglot/rpc/build/as_request.wasm ] ||
    [ polyglot/rpc/as_request.ts -nt polyglot/rpc/build/as_request.wasm ]; then
    npx --yes -p assemblyscript@0.27.31 asc polyglot/rpc/as_request.ts \
      -o polyglot/rpc/build/as_request.wasm --optimize
  fi
}

run_python() { python3 polyglot/rpc/python_client.py; }
run_c() {
  cc -O2 polyglot/rpc/client.c -o /tmp/rpc-client
  /tmp/rpc-client
}
run_cpp() {
  c++ -std=c++17 -O2 polyglot/rpc/client.cpp -o /tmp/rpc-client-cpp
  /tmp/rpc-client-cpp
}
run_zig() {
  (cd polyglot/rpc && zig build-exe zig_client.zig -femit-bin=/tmp/rpc-client-zig -lc)
  /tmp/rpc-client-zig
}
run_js() { node polyglot/rpc/js_client.js; }
run_ts() { node polyglot/rpc/js_client.js; }
run_go() { go run polyglot/rpc/go_client.go; }
run_ruby() { ruby polyglot/rpc/ruby_client.rb; }
run_php() { php polyglot/rpc/php_client.php; }
run_lua() { luajit polyglot/rpc/lua_client.lua; }
run_dart() { dart run polyglot/rpc/dart_client.dart; }
run_java() {
  rm -rf /tmp/rpc-classes && mkdir -p /tmp/rpc-classes
  javac -d /tmp/rpc-classes polyglot/rpc/RpcClient.java
  java -cp /tmp/rpc-classes RpcClient
}
run_kotlin() {
  rm -rf /tmp/rpc-classes && mkdir -p /tmp/rpc-classes
  javac -d /tmp/rpc-classes polyglot/rpc/RpcClient.java
  kotlinc -cp /tmp/rpc-classes -include-runtime -d /tmp/rpc-kotlin.jar polyglot/rpc/KotlinRpc.kt
  java -cp "/tmp/rpc-kotlin.jar:/tmp/rpc-classes" KotlinRpcKt
}
run_scala() {
  rm -rf /tmp/rpc-classes && mkdir -p /tmp/rpc-classes
  javac -d /tmp/rpc-classes polyglot/rpc/RpcClient.java
  "$(readlink -f "${SCALA_CLI:-/cache/scala-cli}")" run polyglot/rpc/ScalaRpc.scala \
    --classpath /tmp/rpc-classes --jvm system --server=false \
    --main-class ScalaRpc --suppress-experimental-feature-warning
}
run_csharp() {
  dotnet run -c Release --project polyglot/rpc/csharp/RpcClient.csproj
}
run_swift() {
  swiftc -O polyglot/rpc/rpc_client.swift -o /tmp/rpc-client-swift
  /tmp/rpc-client-swift
}
run_kotlin_native() {
  bash polyglot/rpc/build_kotlin_native.sh
}
run_ktnative() { run_kotlin_native; }
run_assemblyscript() {
  build_assemblyscript
  node polyglot/rpc/as_client.js
}
run_shell() {
  bash polyglot/rpc/shell_client.sh
}

client_available() {
  case "$1" in
    python) command -v python3 >/dev/null ;;
    c) command -v cc >/dev/null ;;
    cpp) command -v c++ >/dev/null ;;
    zig) command -v zig >/dev/null ;;
    js|ts) command -v node >/dev/null ;;
    go) command -v go >/dev/null ;;
    ruby) command -v ruby >/dev/null ;;
    php) command -v php >/dev/null ;;
    lua) command -v luajit >/dev/null ;;
    dart) command -v dart >/dev/null ;;
    java) command -v javac >/dev/null ;;
    kotlin) command -v kotlinc >/dev/null ;;
    scala) [ -x "${SCALA_CLI:-/cache/scala-cli}" ] ;;
    csharp) command -v dotnet >/dev/null ;;
    swift) command -v swiftc >/dev/null ;;
    assemblyscript) command -v node >/dev/null ;;
    shell) return 0 ;;
    ktnative) command -v konanc >/dev/null ||
      [ -x "${POLYGLOT_CACHE:-/cache}/kotlin-native/bin/konanc" ] ;;
    *) return 1 ;;
  esac
}

# Every thin client in the matrix, in a stable order.
CLIENTS=(python c cpp zig js go ruby php lua dart java kotlin scala csharp swift ktnative assemblyscript shell)
