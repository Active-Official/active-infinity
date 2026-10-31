<?php

declare(strict_types=1);

// Thin Active RPC client over native ARP1 on TCP (PHP).
//
//   php polyglot/rpc/php_client.php

const BUDGET = [10000, 64 * 1024 * 1024, 5000, 100000, 256, 100000, 10000000];

function putString(string &$buffer, string $text): void
{
    $buffer .= pack('V', strlen($text)) . $text;
}

function request(int $id, string $method, string $payload, ?string $capId): string
{
    $buffer = 'ARP1';
    $buffer .= pack('CC', 1, 1);
    $buffer .= pack('v', 0);
    $buffer .= pack('P', $id);
    putString($buffer, $method);
    $buffer .= pack('V', 0);
    $buffer .= pack('V', strlen($payload)) . $payload;
    if ($capId === null) {
        return $buffer . pack('V', 0);
    }
    $buffer .= pack('V', 1) . $capId;
    $buffer .= pack('V', 1);
    putString($buffer, 'echo');
    foreach (BUDGET as $value) {
        $buffer .= pack('P', $value);
    }
    $buffer .= pack('CCC', 0, 0, 0);
    return $buffer;
}

/** @return array{0:int,1:string} */
function call(string $address, string $envelope): array
{
    [$host, $port] = explode(':', $address);
    $socket = stream_socket_client("tcp://$host:$port", $errno, $error, 10);
    if ($socket === false) {
        throw new RuntimeException("connect: $error");
    }
    try {
        fwrite($socket, pack('V', strlen($envelope)) . $envelope);
        $header = fread($socket, 4);
        if ($header === false || strlen($header) < 4) {
            throw new RuntimeException('connection closed');
        }
        $length = unpack('V', $header)[1];
        $body = '';
        while (strlen($body) < $length) {
            $chunk = fread($socket, $length - strlen($body));
            if ($chunk === false || $chunk === '') {
                throw new RuntimeException('truncated frame');
            }
            $body .= $chunk;
        }
    } finally {
        fclose($socket);
    }
    if (substr($body, 0, 4) !== 'ARP1' || ord($body[4]) !== 1) {
        throw new RuntimeException('bad magic');
    }
    $kind = ord($body[5]);
    $methodLength = unpack('V', substr($body, 16, 4))[1];
    $method = substr($body, 20, $methodLength);
    return [$kind, $method, $body];
}

$address = getenv('ACTIVE_RPC_ADDR');
$capHex = getenv('ACTIVE_RPC_CAP');
$payloadPath = getenv('ACTIVE_RPC_PAYLOAD');
if ($address === false || $capHex === false || $payloadPath === false) {
    fwrite(STDERR, "ACTIVE_RPC_ADDR, ACTIVE_RPC_CAP and ACTIVE_RPC_PAYLOAD are required\n");
    exit(2);
}
$cap = hex2bin($capHex);
if ($cap === false || strlen($cap) !== 16) {
    fwrite(STDERR, "ACTIVE_RPC_CAP must be 32 hex characters\n");
    exit(2);
}
$payload = file_get_contents($payloadPath);
if ($payload === false) {
    exit(2);
}

[$kind, $method, $body] = call($address, request(42, 'echo', $payload, $cap));
$echoed = unpack('V', substr($body, -4))[1] === 0
    && substr($body, strlen($body) - 4 - strlen($payload), strlen($payload)) === $payload;
if ($kind !== 2 || unpack('P', substr($body, 8, 8))[1] !== 42 || !$echoed) {
    fwrite(STDERR, "echo failed: $kind $method\n");
    exit(1);
}

[$kind, $method, ] = call($address, request(43, 'refuse', $payload, $cap));
if ($kind !== 3 || $method !== 'rpc/method-not-granted') {
    fwrite(STDERR, "refusal mismatch: $kind $method\n");
    exit(1);
}

[$kind, $method, ] = call($address, request(44, 'echo', $payload, null));
if ($kind !== 3 || $method !== 'rpc/unknown-capability') {
    fwrite(STDERR, "missing capability mismatch: $kind $method\n");
    exit(1);
}

echo "PHP thin RPC PASS (echo, refusal, missing capability)\n";
