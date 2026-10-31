// Kotlin/JVM thin RPC entry point: reuses the Java wire code so both languages
// exercise identical bytes.
//
//   kotlinc -cp <java-classes> -include-runtime -d /tmp/rpc-kotlin.jar polyglot/rpc/KotlinRpc.kt
//   java -cp /tmp/rpc-kotlin.jar:<java-classes> KotlinRpcKt

fun main() {
    RpcClient.run()
}
