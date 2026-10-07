# JTail

**A Tailscale client in pure Java.** JTail lets a Java 21+ program join an existing tailnet (or a self-hosted
[Headscale](https://github.com/juanfont/headscale) network) from *inside the JVM*: no `tailscaled`, no Go, no Rust,
no JNI, no TUN device, no root, **no runtime dependencies at all**. The WireGuard data plane, the Tailscale control
protocol, DERP relays, NAT traversal and a TCP/IP stack are all implemented in Java, in the spirit of Go's
[`tsnet`](https://pkg.go.dev/tailscale.com/tsnet).

```java
try (Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))   // reusable auth key from the Tailscale admin console
        .hostname("worker-" + deploymentId)     // unique per deployment
        .stateDir(Path.of("jtail-state"))       // optional: keep the same node identity (and IP) across restarts
        .ephemeral(true)                        // optional: node disappears from the tailnet when it goes offline
        .tag("tag:worker")                      // optional: ACL tag the auth key may apply
        .join()) {

    System.out.println("Joined as " + net.name() + " at " + net.address());

    try (Socket s = net.dial("db-server", 5432)) { /* an ordinary java.net.Socket */ }

    try (ServerSocket server = net.listen(8080)) {
        Socket client = server.accept();           // connections from other tailnet nodes
    }
}
```

Run any number of deployments of the same program with one reusable auth key and distinct hostnames: each registers as
its own node in the tailnet and can reach (and be reached by) every other node, subject to your ACLs.

> **Status:** feature-complete for the scenarios below and verified against the real Go implementations (see
> [Verification](#verification)). It has not been exercised against Tailscale's production control plane with a real
> account from the development environment, only against Tailscale's own control-plane test server and, for the
> handshake, the live service. Treat it as a young implementation of a security-sensitive protocol; see
> [Security notes](#security-notes).

## Quick start

Maven (build from source for now):

```
mvn install            # unit tests + (skipped) interop tests; produces target/JTail-<version>.jar
```

```xml
<dependency>
  <groupId>com.simtechdata</groupId>
  <artifactId>JTail</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

1. In the [Tailscale admin console](https://login.tailscale.com/admin/settings/keys) create an **auth key**
   (reusable, optionally pre-authorized/ephemeral/tagged). For Headscale use `headscale preauthkeys create`.
2. Pass it to `JTail.network().authKey(...)`. Self-hosted? Add `.controlUrl("https://headscale.example.com")`.
3. `join()` blocks until the node is registered and usable (default timeout 60 s, `JTailException` on failure).

Using existing libraries with the tailnet:

```java
// JDK HttpClient via the built-in local proxy
try (HttpProxy proxy = net.startHttpProxy(0)) {
    HttpClient client = HttpClient.newBuilder()
            .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxy.port()))).build();
    String body = client.send(HttpRequest.newBuilder(URI.create("http://internal-api:8080/status")).build(),
            HttpResponse.BodyHandlers.ofString()).body();
}

// anything that takes a SocketFactory (e.g. PostgreSQL JDBC: socketFactory=... or a custom wrapper)
Socket s = net.socketFactory().createSocket("db-server", 5432);
```

See [`examples/`](examples) for runnable programs.

## The API

| Call | What it does |
|---|---|
| `JTail.network()…join()` | Build a config and join. `JTail.join(authKey)` is the one-liner. |
| `Tailnet.dial(host, port[, timeout])` | Opens a TCP connection; returns a real `java.net.Socket` (wrap it in TLS with `SSLSocketFactory.createSocket(socket, host, port, true)`). `host` is a peer name, short hostname, tailnet IP, MagicDNS extra record, or a name resolvable via the tailnet's split-DNS. |
| `Tailnet.listen(port)` | A `java.net.ServerSocket` accepting connections that arrive over the tailnet. |
| `Tailnet.openUdp(port)` | UDP socket on the tailnet address. |
| `Tailnet.ping(host, timeoutMs)` | ICMP echo; returns RTT in ms. |
| `Tailnet.socketFactory()` | A `javax.net.SocketFactory` for libraries that open their own connections (JDBC drivers, Apache HttpClient, OkHttp, JavaMail, ...). |
| `Tailnet.startHttpProxy(port)` | Local HTTP proxy on 127.0.0.1 (CONNECT + absolute-URI) that forwards through the tailnet, so `java.net.http.HttpClient` and any proxy-aware tool can reach tailnet hosts. |
| `Tailnet.peers()` / `address()` / `addresses()` / `name()` | Netmap view of the tailnet and this node. |
| `Tailnet.resolve(host)` / `isDirect(host)` | Name resolution and path diagnostics (direct UDP vs. DERP relay). |
| `Tailnet.close()` | Drains pending output, leaves the tailnet (ephemeral nodes are logged out immediately). |

Builder options: `authKey`, `hostname`, `controlUrl`, `stateDir`, `ephemeral`, `tag`, `acceptRoutes`, `directPaths`,
`udpPort`, `joinTimeout`, `onLoginRequired` (interactive browser login when no auth key is available),
`allowInsecureControl`, `includeLoopbackEndpoints` (tests).

## How it works

```
 your code ── java.net.Socket / ServerSocket / UdpSocket
                │
        ┌───────▼────────┐    userspace IPv4+IPv6, TCP (retransmit, NewReno, window scaling, OOO), UDP, ICMP
        │   netstack     │    + ACL packet filter from the netmap
        └───────┬────────┘
        ┌───────▼────────┐    Noise_IKpsk2 handshake, ChaCha20-Poly1305 transport, replay window, cookies, timers,
        │   WireGuard    │    cryptokey routing
        └───────┬────────┘
        ┌───────▼────────┐    per peer: direct UDP once disco ping/pong verifies a path, else DERP; call-me-maybe;
        │   magicsock    │    STUN; heartbeat path trust                      ──► UDP socket
        └───────┬────────┘
        ┌───────▼────────┐    TCP+TLS relays, NaCl-box login, auto-reconnect  ──► DERP servers
        │   DERP         │
        └────────────────┘
        control plane: ts2021 = HTTP upgrade → Noise_IK → HTTP/2 → JSON /machine/register + streaming /machine/map
                       (pure-Java HPACK/HTTP/2, JSON, tailcfg model, netmap delta merging)
```

Everything JTail needs that the JDK lacks is implemented here: BLAKE2s + HKDF/HMAC, NaCl box (Salsa20/XSalsa20/
Poly1305), XChaCha20, HPACK/HTTP/2, JSON, STUN, DNS, and the TCP/IP stack. The JDK supplies only X25519 and
ChaCha20-Poly1305 (`javax.crypto`) and sockets.

## Verification

JTail is checked against the *real* implementations, not just itself. `interop/` contains small Go programs that are
built against a Tailscale checkout and used **only as test oracles**; the library never needs them.

| Component | Verified against |
|---|---|
| BLAKE2s, X25519, ChaCha20-Poly1305, HChaCha20 | RFC 7693 / 7748 / 8439 and draft-irtf-cfrg-xchacha vectors |
| NaCl box (XSalsa20-Poly1305) | vectors generated with `golang.org/x/crypto/nacl/box`, lengths 0–1000 |
| ts2021 Noise control handshake + framing | Tailscale's `controlbase` server; also the **live production control plane** (handshake + HTTP/2 session) |
| HPACK / HTTP/2 client | RFC 7541 vectors; Go `net/http` h2c server (large bodies, flow control, streaming) |
| `/machine/register`, `/machine/map`, netmap deltas, MagicDNS records, split DNS, interactive login | Tailscale's own `testcontrol` server |
| **Headscale** control server (independent implementation, v0.29.4) | pre-auth-key registration, netmap with a real Go client, MagicDNS names, TCP both directions, ping |
| WireGuard (initiator **and** responder) | Tailscale's `wireguard-go` fork over real UDP |
| DERP client | Tailscale's `derpserver` over TLS; relay reconnect mid-TCP-connection |
| Disco messages | byte-for-byte against Go's `disco` package; STUN against RFC 5769 |
| TCP/IP stack | loss + reordering + zero-window + keepalive simulation, a fully synchronous (re-entrant) link; IPv4 and IPv6 |
| **Whole system** | a JTail node and a genuine Tailscale (`tsnet`) client on one tailnet: TCP both directions (IPv4+IPv6), 4 MB bulk transfers with SHA-256 integrity, UDP, ICMP, MagicDNS name dial |

Also covered by tests: restart persistence, interactive login, DERP-only mode and relay/control reconnects, WireGuard
rekeying, a 400-connection soak (no leaked connections), a 600-peer tailnet (joins in ~1.5 s), parser fuzzing.

Run everything (needs Go and a checkout of tailscale/tailscale):

```
interop/build-oracle.sh /path/to/tailscale /tmp/oracles
GOBIN=/tmp/headscale go install github.com/juanfont/headscale/cmd/headscale@v0.29.4     # optional
mvn test -DargLine="-Djtail.oracle.dir=/tmp/oracles -Djtail.headscale.bin=/tmp/headscale/headscale"
```

Without `jtail.oracle.dir` the interop tests are skipped and the pure-Java unit tests run.

Indicative throughput on a loopback tailnet in a small VM: ~170–220 Mbit/s per TCP stream, entirely in Java.

## Not implemented (yet)

Exit nodes and `--advertise-routes` (subnet routes *are* usable with `acceptRoutes(true)`), Tailnet Lock (TKA),
Taildrop, Tailscale SSH, Serve/Funnel, peer relays (UDP relay servers), DNS-over-HTTPS resolvers, and OAuth client
credentials. Window-scaled TCP has no SACK/timestamps. The stack drops IP fragments (tailnet MTU is 1280).

## Security notes

* JTail implements published protocols (WireGuard, Noise, Tailscale control/DERP/disco) from specification and from the
  open-source Tailscale client. It has had careful testing and fuzzing but **no independent security audit**.
* Auth keys are bearer secrets. Never log them; prefer short-lived or ephemeral, tag-scoped keys. A plaintext
  `http://` control URL is refused for non-loopback hosts unless you call `allowInsecureControl(true)`.
* `stateDir` holds the node's private keys (`identity.properties`, mode 0600). Anyone who can read it can impersonate
  the node.
* Inbound connections are filtered by the tailnet ACL packet filter delivered by the control server; with no filter
  all inbound connection attempts are refused.
* Report vulnerabilities privately to the repository owner.

## Project layout

```
com.simtechdata.jtail            public API: JTail, Tailnet, JTailConfig, Peer, JTailException
  .control / .control.noise      ts2021 client, Noise handshake
  .http2                         HPACK + HTTP/2 client
  .tailcfg / .json               wire types, netmap merging, JSON
  .wg                            WireGuard
  .magicsock / .derp             path selection, disco, STUN, DERP
  .netstack / .net               TCP/IP stack and java.net.Socket adapters
  .filter / .dns / .state        ACL filter, DNS, node identity
```

Only `com.simtechdata.jtail` is a stable API; the other packages are implementation and may change.

## License

BSD-3-Clause. JTail is a clean-room Java implementation guided by the BSD-licensed Tailscale client source; a few
constant tables were generated from `golang.org/x/net`. See [NOTICE](NOTICE). "Tailscale" is a trademark of
Tailscale Inc.; this project is not affiliated with or endorsed by Tailscale.
