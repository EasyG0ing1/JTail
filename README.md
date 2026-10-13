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

## What JTail is, and what it is not

JTail was written to provide Java programs direct access to a tailnet without the need for a Tailscale client installed at the OS level. I wanted a way to create Java programs that could access back end resources without needing to expose those resources to the Internet. JTail does exactly that.

JTail is a **library that puts your Java program on a tailnet**. It is not a VPN client. It creates no network
interface, installs no routes and changes no DNS settings, so the operating system never learns that the tailnet
exists. Only the objects JTail hands to your code can reach tailnet devices; everything else, including code in your own
application and in the same JVM, cannot.

### What can and cannot reach the tailnet

| Code | What it is | Reaches the tailnet? |
|---|---|---|
| `net.dial(host, port)` | a `java.net.Socket` | **yes** |
| `net.listen(port)` | a `java.net.ServerSocket` | **yes**, accepts connections from tailnet nodes |
| `net.openUdp(port)` | a `UdpSocket` | **yes** |
| `net.socketFactory()` | a `javax.net.SocketFactory` | **yes**, for any library that lets you supply one (JDBC drivers, Apache HttpClient, OkHttp, JavaMail, SMB or SSH client libraries, ...) |
| `net.ping(host, ms)`, `net.resolve(host)` | tailnet-level ping and name lookup | **yes** (this is not the operating system's `ping`) |
| `net.startHttpProxy(port)` | a local HTTP/HTTPS proxy | **yes**, but only for HTTP(S) clients you point at it, and only after you start it (see below) |
| `new Socket("db-server", 5432)` | a plain `java.net.Socket` | **no**: it uses the operating system's network and cannot resolve or reach tailnet devices |
| `HttpClient.newHttpClient()`, `new URL(...).openConnection()` | the JDK's HTTP clients, with no proxy configured | **no**: same reason (give them the JTail proxy, or use `dial`) |
| `InetAddress.getByName("db-server")` | the JDK's resolver | **no**: it cannot resolve MagicDNS names; use `net.resolve(...)` |
| `Files.walk(...)`, `Files.newInputStream(...)`, `new File(...)` | Java file APIs | **no**: they cannot open a share on a tailnet machine, and JTail mounts nothing |
| `ProcessBuilder`, `Runtime.exec` running `curl`, `ssh`, `ping`, `smbclient`, another `java` program | child processes | **no**: they inherit nothing from your JTail session (they can reach HTTP(S) services only through a proxy you started) |
| A share mounted by the operating system (SMB, NFS, AFP); Finder, Explorer, browsers, `mount` | other programs on the machine | **no**: they are unaffected by JTail |
| A library that opens its own sockets and offers no `Socket` or `SocketFactory` hook | third-party code | **no**: it cannot use the tailnet |

In short: **if a piece of code did not obtain its connection from a JTail object, it is not on the tailnet.**

A remote service does not need JTail. `dial("fileserver", 445)` is an ordinary TCP connection to whatever listens on
that tailnet node, such as the SMB service of the operating system. An SMB client library that accepts a custom
`SocketFactory` can therefore talk to it through `net.socketFactory()`. (This is expected to work but is not covered
by JTail's tests.)

### The HTTP proxy is deliberate

`startHttpProxy` is the single way to let code outside your JTail objects reach the tailnet, and it is opt-in:

* **It is never started automatically.** 
* A proxy exists only after your code
  calls `net.startHttpProxy(...)`.
* It listens on `127.0.0.1` only and handles HTTP and HTTPS (`CONNECT`).
* By default **any process on the machine** that can reach the port may use it, and through it your node's tailnet
  access.
* Secure the proxy by calling `net.startHttpProxy(port, username, password)` which requires HTTP Basic authentication.
* OS level programs such as curl could access tailnet resources through the proxy.
* Java resources such as `java.net.http.HttpClient`, which have no `SocketFactory` hook, can reach the tailnet through the proxy.

## Quick start

Add the dependency from Maven Central (Java 21+, no other dependencies are pulled in):

```xml
<dependency>
  <groupId>com.simtechdata</groupId>
  <artifactId>JTail</artifactId>
  <version>1.0.0</version>
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
| `Tailnet.startHttpProxy(port[, user, password])` | Opt-in local HTTP proxy on 127.0.0.1 (CONNECT + absolute-URI) that forwards through the tailnet, so `java.net.http.HttpClient` and any proxy-aware tool can reach tailnet hosts. Never started automatically; no authentication unless you pass a user name and password. |
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

These are features that may be added later. What JTail deliberately is not (a system-wide VPN) is described in
[What JTail is, and what it is not](#what-jtail-is-and-what-it-is-not).

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
