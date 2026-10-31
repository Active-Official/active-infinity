// Scala thin RPC entry point: reuses the Java wire code.
//
//   bash polyglot/scala/build.sh (after javac of polyglot/rpc/RpcClient.java)

object ScalaRpc {
  def main(args: Array[String]): Unit = RpcClient.run()
}
