import java.io.DataInputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

/**
 * Thin Active RPC client over native ARP1 on TCP (JVM).
 *
 * <p>Java, Kotlin and Scala share this class, so the three languages exercise
 * identical wire code.
 *
 * <pre>
 * javac -d /tmp/rpc polyglot/rpc/RpcClient.java
 * java -cp /tmp/rpc RpcClient
 * </pre>
 */
public final class RpcClient {
    private static final long[] BUDGET = {10000, 64L << 20, 5000, 100000, 256, 100000, 10000000};

    private RpcClient() {}

    public static void main(String[] args) throws Exception {
        run();
    }

    public static void run() throws Exception {
        String address = require("ACTIVE_RPC_ADDR");
        byte[] cap = HexFormat.of().parseHex(require("ACTIVE_RPC_CAP"));
        if (cap.length != 16) {
            throw new IllegalArgumentException("ACTIVE_RPC_CAP must be 32 hex characters");
        }
        byte[] payload = Files.readAllBytes(Path.of(require("ACTIVE_RPC_PAYLOAD")));

        Response echo = call(address, request(42, "echo", payload, cap));
        if (echo.kind != 2 || ByteBuffer.wrap(echo.body, 8, 8).order(ByteOrder.LITTLE_ENDIAN).getLong() != 42L
                || !echoes(echo.body, payload)) {
            throw new AssertionError("echo: " + echo.kind + " " + echo.method);
        }
        Response refused = call(address, request(43, "refuse", payload, cap));
        if (refused.kind != 3 || !refused.method.equals("rpc/method-not-granted")) {
            throw new AssertionError("refusal: " + refused.kind + " " + refused.method);
        }
        Response anonymous = call(address, request(44, "echo", payload, null));
        if (anonymous.kind != 3 || !anonymous.method.equals("rpc/unknown-capability")) {
            throw new AssertionError("missing capability: " + anonymous.kind + " " + anonymous.method);
        }
        System.out.println("JVM thin RPC PASS (echo, refusal, missing capability)");
    }

    private static String require(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException(name + " is required");
        }
        return value;
    }

    private static void putString(ByteBuffer buffer, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        buffer.putInt(bytes.length).put(bytes);
    }

    private static byte[] request(long id, String method, byte[] payload, byte[] cap) {
        int size = 4 + 2 + 2 + 8 + 4 + method.length() + 4 + 4 + payload.length + 4;
        if (cap != null) {
            size += 16 + 4 + 4 + 4 + 7 * 8 + 3;
        }
        ByteBuffer buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put("ARP1".getBytes(StandardCharsets.US_ASCII));
        buffer.put((byte) 1).put((byte) 1);
        buffer.putShort((short) 0);
        buffer.putLong(id);
        putString(buffer, method);
        buffer.putInt(0);
        buffer.putInt(payload.length).put(payload);
        if (cap == null) {
            buffer.putInt(0);
            return buffer.array();
        }
        buffer.putInt(1).put(cap);
        buffer.putInt(1);
        putString(buffer, "echo");
        for (long value : BUDGET) {
            buffer.putLong(value);
        }
        buffer.put((byte) 0).put((byte) 0).put((byte) 0);
        return buffer.array();
    }

    private static boolean echoes(byte[] body, byte[] payload) {
        int capacity = ByteBuffer.wrap(body, body.length - 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (capacity != 0 || body.length < payload.length + 8) {
            return false;
        }
        return java.util.Arrays.equals(
                java.util.Arrays.copyOfRange(body, body.length - 4 - payload.length, body.length - 4),
                payload);
    }

    private static Response call(String address, byte[] envelope) throws Exception {
        int split = address.lastIndexOf(':');
        String host = address.substring(0, split);
        int port = Integer.parseInt(address.substring(split + 1));
        try (Socket socket = new Socket(host, port)) {
            OutputStream output = socket.getOutputStream();
            ByteBuffer header = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            header.putInt(envelope.length);
            output.write(header.array());
            output.write(envelope);
            output.flush();

            DataInputStream input = new DataInputStream(socket.getInputStream());
            byte[] frameHeader = new byte[4];
            input.readFully(frameHeader);
            int length = ByteBuffer.wrap(frameHeader).order(ByteOrder.LITTLE_ENDIAN).getInt();
            byte[] body = new byte[length];
            input.readFully(body);
            if (!new String(body, 0, 4, StandardCharsets.US_ASCII).equals("ARP1") || body[4] != 1) {
                throw new AssertionError("bad envelope magic");
            }
            int kind = body[5];
            int methodLength = ByteBuffer.wrap(body, 16, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            String method = new String(body, 20, methodLength, StandardCharsets.UTF_8);
            return new Response(kind, method, body);
        }
    }

    private record Response(int kind, String method, byte[] body) {}
}
