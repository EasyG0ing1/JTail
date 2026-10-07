# JTail

A pure-Java (21+), **zero-dependency** Tailscale client library. It lets a Java program join an existing tailnet
from inside the JVM: no `tailscaled`, no Go, no Rust, no JNI, no TUN device. Traffic runs over an in-process
userspace WireGuard + TCP/IP stack, in the spirit of Go's `tsnet`.

> **Status: under construction.** The public API below is fixed; the join implementation is being built bottom-up.
> `JTail.join(...)` currently throws `JTailException` until the control client, WireGuard and netstack land.

## Target usage

```java
try (Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))   // reusable auth key from the Tailscale admin console
        .hostname("worker-" + deploymentId)     // unique per deployment
        .stateDir(Path.of("jtail-state"))       // optional: keep the same node identity across restarts
        .ephemeral(true)                        // optional: auto-remove the node when it goes offline
        .tag("tag:worker")                      // optional: ACL tag the auth key may apply
        .join()) {

    System.out.println("Joined as " + net.name() + " at " + net.address());
    try (Socket s = net.dial("db-server", 5432)) { /* ... */ }
    try (ServerSocket ss = net.listen(8080)) { /* ... */ }
}
```

Shortest form: `JTail.join(authKey)`. Self-hosted Headscale: `.controlUrl("https://headscale.example.com")`.

Many deployments of the same program can share one reusable auth key; each registers as its own node.

## Roadmap

| # | Component | State |
|---|-----------|-------|
| 1 | Crypto primitives (BLAKE2s, HKDF, X25519, ChaCha20-Poly1305) | done, RFC vectors |
| 2 | ts2021 Noise control handshake + transport | done, verified against Go `controlbase` |
| 3 | Public API, config, persistent node identity | done |
| 4 | Control client: HTTP upgrade, register with auth key, map poll (needs a small JSON codec) | next |
| 5 | WireGuard data plane (Noise_IKpsk2) | planned |
| 6 | DERP relay client | planned |
| 7 | Userspace TCP/UDP/ICMP stack and `Socket`/`ServerSocket` adapters | planned |
| 8 | Disco/direct paths, MagicDNS, ACL filter | planned |

## Interop testing

`interop/` holds small Go programs built against a local checkout of tailscale/tailscale and used **only** as test
oracles. The library never needs them.

```
interop/build-oracle.sh /path/to/tailscale /tmp/oracles
mvn test -DargLine="-Djtail.oracle.dir=/tmp/oracles"
```

## License

BSD-3-Clause, matching the Tailscale client code this project is derived from.
