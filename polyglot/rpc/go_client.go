// Thin Active RPC client over native ARP1 on TCP (Go).
//
//	go run polyglot/rpc/go_client.go
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

func main() {
	address := os.Getenv("ACTIVE_RPC_ADDR")
	capHex := os.Getenv("ACTIVE_RPC_CAP")
	payloadPath := os.Getenv("ACTIVE_RPC_PAYLOAD")
	if address == "" || capHex == "" || payloadPath == "" {
		fmt.Fprintln(os.Stderr, "ACTIVE_RPC_ADDR, ACTIVE_RPC_CAP and ACTIVE_RPC_PAYLOAD are required")
		os.Exit(2)
	}
	capID, err := hex.DecodeString(capHex)
	if err != nil || len(capID) != 16 {
		fmt.Fprintln(os.Stderr, "ACTIVE_RPC_CAP must be 32 hex characters")
		os.Exit(2)
	}
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		panic(err)
	}

	if kind, method, body := call(address, request(42, "echo", payload, capID)); kind != 2 ||
		binary.LittleEndian.Uint64(body[8:16]) != 42 || !echoes(body, payload) {
		fmt.Fprintf(os.Stderr, "echo failed: kind=%d method=%s\n", kind, method)
		os.Exit(1)
	}
	if kind, method, _ := call(address, request(43, "refuse", payload, capID)); kind != 3 || method != "rpc/method-not-granted" {
		fmt.Fprintf(os.Stderr, "refusal mismatch: kind=%d method=%s\n", kind, method)
		os.Exit(1)
	}
	if kind, method, _ := call(address, request(44, "echo", payload, nil)); kind != 3 || method != "rpc/unknown-capability" {
		fmt.Fprintf(os.Stderr, "missing-capability mismatch: kind=%d method=%s\n", kind, method)
		os.Exit(1)
	}
	fmt.Println("Go thin RPC PASS (echo, refusal, missing capability)")
}

func putString(buffer *bytes.Buffer, text string) {
	binary.Write(buffer, binary.LittleEndian, uint32(len(text)))
	buffer.WriteString(text)
}

func request(id uint64, method string, payload []byte, capID []byte) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("ARP1")
	buffer.WriteByte(1) // version
	buffer.WriteByte(1) // request
	binary.Write(&buffer, binary.LittleEndian, uint16(0))
	binary.Write(&buffer, binary.LittleEndian, id)
	putString(&buffer, method)
	binary.Write(&buffer, binary.LittleEndian, uint32(0)) // args
	binary.Write(&buffer, binary.LittleEndian, uint32(len(payload)))
	buffer.Write(payload)
	if capID == nil {
		binary.Write(&buffer, binary.LittleEndian, uint32(0))
		return buffer.Bytes()
	}
	binary.Write(&buffer, binary.LittleEndian, uint32(1))
	buffer.Write(capID)
	binary.Write(&buffer, binary.LittleEndian, uint32(1))
	putString(&buffer, "echo")
	for _, value := range []uint64{10000, 64 << 20, 5000, 100000, 256, 100000, 10000000} {
		binary.Write(&buffer, binary.LittleEndian, value)
	}
	buffer.WriteByte(0) // read_only
	buffer.WriteByte(0) // redact
	buffer.WriteByte(0) // no path scope
	return buffer.Bytes()
}

func call(address string, envelope []byte) (int, string, []byte) {
	connection, err := net.Dial("tcp", address)
	if err != nil {
		panic(err)
	}
	defer connection.Close()
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(envelope)))
	if _, err := connection.Write(append(header[:], envelope...)); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		panic(err)
	}
	length := binary.LittleEndian.Uint32(header[:])
	response := make([]byte, length)
	if _, err := io.ReadFull(connection, response); err != nil {
		panic(err)
	}
	if !bytes.Equal(response[:4], []byte("ARP1")) || response[4] != 1 {
		panic("bad envelope magic")
	}
	kind := int(response[5])
	methodLength := int(binary.LittleEndian.Uint32(response[16:20]))
	method := string(response[20 : 20+methodLength])
	return kind, strings.TrimRight(method, "\x00"), response
}

func echoes(body, payload []byte) bool {
	if len(body) < len(payload)+8 {
		return false
	}
	if binary.LittleEndian.Uint32(body[len(body)-4:]) != 0 {
		return false
	}
	return bytes.Equal(body[len(body)-4-len(payload):len(body)-4], payload)
}
