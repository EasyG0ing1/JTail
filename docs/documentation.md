# JTail Documentation

This guide explains how to use **JTail** in your own Java programs. It assumes basic Java knowledge (classes, streams,
exceptions, try-with-resources) but no networking background. Networking terms are defined in
[Section 2](#2-terminology).

---

## Table of Contents

1. [What is JTail?](#1-what-is-jtail)
2. [Terminology](#2-terminology)
3. [Requirements](#3-requirements)
4. [Adding JTail to your project](#4-adding-jtail-to-your-project)
5. [Getting an auth key](#5-getting-an-auth-key)
6. [Your first program](#6-your-first-program)
7. [Configuration (the builder)](#7-configuration-the-builder)
8. [The `Tailnet` API](#8-the-tailnet-api)
9. [TCP connections: `dial` and `listen`](#9-tcp-connections-dial-and-listen)
10. [Names and addresses](#10-names-and-addresses)
11. [Peers](#11-peers)
12. [Ping](#12-ping)
13. [UDP](#13-udp)
14. [Integrating with other libraries](#14-integrating-with-other-libraries)
15. [Running multiple instances](#15-running-multiple-instances)
16. [Persisting node identity](#16-persisting-node-identity)
17. [Interactive login](#17-interactive-login)
18. [Direct connections and relays](#18-direct-connections-and-relays)
19. [Using Headscale](#19-using-headscale)
20. [Error handling](#20-error-handling)
21. [Shutting down](#21-shutting-down)
22. [Security considerations](#22-security-considerations)
23. [Troubleshooting](#23-troubleshooting)
24. [Limitations](#24-limitations)
25. [Quick reference](#25-quick-reference)

---

## 1. What is JTail?

JTail is a **native** java library that gives you the ability to write a Tailscale network into your java program.

- No Tailscale app to install.
- No Go, Rust or C code.
- No administrator (root) rights needed.
- No other libraries to download. JTail needs nothing except Java 21+

You write a few lines of code, and your program becomes a member of the private network.

```
   Your Java program                            Another computer
 ┌──────────────────────┐                     ┌────────────────────┐
 │  JTail               │ ◄══ private,       ═► │ Tailscale / JTail  │
 │  (joins the network) │     encrypted link  │                    │
 └──────────────────────┘                     └────────────────────┘
```

All traffic between nodes is end-to-end encrypted using WireGuard. JTail implements the Tailscale client protocols
(control plane, WireGuard, DERP relays, NAT traversal) and a userspace TCP/IP stack entirely in Java. It does not create
a network interface on the host: only your Java program is part of the tailnet, and other processes on the same machine
are not affected.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Tailnet** | Your private network. Every node that joins it can communicate with every other node, subject to the network's access rules (ACLs). |
| **Node** | One member of the tailnet. Your running Java program is a node. |
| **Peer** | Another node, from the point of view of the current node. |
| **Auth key** | A secret token that allows a program to join a tailnet without an interactive login. It looks like `tskey-auth-abc123...`. |
| **Hostname** | The name of a node, such as `worker-1` or `database`. |
| **IP address** | The numeric address of a node. Tailnet IPv4 addresses are in the `100.64.0.0/10` range. |
| **Port** | A number assigned to a specific service on the network. |
| **TCP** | Transmission Control Protocol. The main protocol used on the internet. |
| **UDP** | User Datagram Protocol: A faster, simpler protocol. UDP is a better protocol for broadcasting packets especially to multiple clients at the same time. |
| **Socket** | Java's abstraction for a network connection, with an input stream and an output stream. |
| **DERP relay** | A relay server operated on the internet that forwards encrypted traffic between two nodes that cannot reach each other directly. |
| **Direct connection** | A connection between two nodes that does not pass through a relay. It has lower latency. |
| **Control server** | The coordination server that maintains the list of nodes in the tailnet and distributes keys and access rules. For Tailscale it is operated by Tailscale; [Headscale](https://github.com/juanfont/headscale) is a self-hosted alternative. |
| **MagicDNS** | Name resolution for tailnet nodes, so you can use `database` instead of `100.64.0.5`. |
| **ACL** | Access control list: the rules in your tailnet that decide which nodes may connect to which. |

---

## 3. Requirements

1. **Java 21 or newer.** Verify with `java -version`.
2. **A tailnet.** This is either a Tailscale account (the free plan works) or a self-hosted Headscale server.
3. **An auth key** (see the next sections).
4. **Another node to communicate with**, such as a machine running Tailscale or another instance of your program using
   JTail.

---

## 4. Adding JTail to your project

JTail is built with Maven. Build and install it into your local repository from the project folder:

```bash
mvn install
```

Then add the dependency to your own project's `pom.xml`:

```xml
<dependency>
    <groupId>com.simtechdata</groupId>
    <artifactId>JTail</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Set your project to compile for Java 21:

```xml
<properties>
    <maven.compiler.release>21</maven.compiler.release>
</properties>
```

The public API is in a single package. These are the imports you normally need:

```java
import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
```

JTail has no runtime dependencies, so nothing else is added to your classpath.

---

## 5. Getting an auth key

An auth key lets your program join the tailnet without any interactive login, which is what you want for services that
run unattended.

**Tailscale:**

1. Open the Tailscale admin console and go to **Settings → Keys**.
2. Click **Generate auth key**.
3. Choose the options:
   - **Reusable**: required if several instances of your program share the key.
   - **Ephemeral**: nodes are removed from the tailnet automatically when they go offline.
   - **Pre-approved**: skip manual device approval if your tailnet requires it.
   - **Tags**: labels such as `tag:worker` that your ACLs can reference.
4. Copy the key. It is only displayed once.

**Headscale:** run `headscale preauthkeys create --user 1 --reusable --expiration 24h`.

> **Treat the key like a password.** Anyone who has it can add devices to your tailnet. Do not hard-code it in source
> files or commit it to version control. Read it from an environment variable or a secrets manager instead.

Setting an environment variable:

```bash
# Linux / macOS
export TS_AUTHKEY="tskey-auth-xxxxxxxxxxxx"

# Windows (PowerShell)
$env:TS_AUTHKEY = "tskey-auth-xxxxxxxxxxxx"
```

In Java, read it with `System.getenv("TS_AUTHKEY")`.

---

## 6. Your first program

The smallest useful program joins the tailnet, prints its identity, and leaves.

```java
import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;

public class Hello {
    public static void main(String[] args) throws Exception {
        try (Tailnet net = JTail.network()
                .authKey(System.getenv("TS_AUTHKEY"))
                .hostname("my-first-jtail")
                .join()) {

            System.out.println("Joined the tailnet");
            System.out.println("Name:    " + net.name());
            System.out.println("Address: " + net.address().getHostAddress());
        }
    }
}
```

- `JTail.network()` returns a builder for the configuration.
- `.authKey(...)` supplies the auth key.
- `.hostname(...)` sets the name other nodes will see.
- `.join()` registers the node and blocks until it is usable (60 seconds by default). On failure it throws a
  `JTailException` (see [Error handling](#20-error-handling)).
- `Tailnet` implements `AutoCloseable`, so try-with-resources calls `close()` and leaves the tailnet cleanly.

### Shortest form

If you only have a key and the defaults are acceptable:

```java
Tailnet net = JTail.join(System.getenv("TS_AUTHKEY"));
```

You are then responsible for calling `net.close()`.

---

## 7. Configuration (the builder)

`JTail.network()` returns a `JTailConfig.Builder`. You chain setter calls and finish with `.join()`. Only `authKey` is
required (unless you use [interactive login](#17-interactive-login)); every other setting has a default.

```java
Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))
        .hostname("worker-7")
        .stateDir(Path.of("jtail-state"))
        .ephemeral(true)
        .tag("tag:worker")
        .join();
```

### Settings

| Method | Description | Default |
|---|---|---|
| `authKey(String)` | The auth key used to register the node. | *(required)* |
| `hostname(String)` | The node's name. It should be unique for each instance of your program. | The machine's hostname |
| `controlUrl(String)` | The control server URL. Only needed for a self-hosted server such as Headscale. | Tailscale's control server |
| `stateDir(Path)` | A directory where the node identity is persisted so the node keeps its address across restarts. | *none* (new identity on every run) |
| `ephemeral(boolean)` | If `true`, the node is removed from the tailnet automatically when it goes offline. | `false` |
| `tag(String)` | Requests an ACL tag such as `tag:worker`. May be called several times. The auth key must be permitted to apply it. | *none* |
| `joinTimeout(Duration)` | Maximum time `join()` waits before failing. | 60 seconds |
| `directPaths(boolean)` | If `false`, all traffic is relayed through DERP (see [Section 18](#18-direct-connections-and-relays)). | `true` |
| `udpPort(int)` | Fixed local UDP port used for direct connections. | `0` (any free port) |
| `acceptRoutes(boolean)` | Accept subnet routes advertised by other nodes (subnet routers). | `false` |
| `onLoginRequired(Consumer<String>)` | Enables interactive browser login when no auth key is available. | *none* |
| `allowInsecureControl(boolean)` | Allows a plain `http://` control URL for a non-loopback host. **Insecure**; see [Section 22](#22-security-considerations). | `false` |
| `includeLoopbackEndpoints(boolean)` | Advertises loopback addresses. Only useful for tests where several nodes run on the same machine. | `false` |

### Building the configuration separately

`build()` creates an immutable `JTailConfig` without contacting the network, which you can pass to `JTail.join(...)`
later:

```java
JTailConfig config = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))
        .hostname("later")
        .build();          // no network activity yet

Tailnet net = JTail.join(config);
```

---

## 8. The `Tailnet` API

A successful `join()` returns a `Tailnet`. It is the entry point for everything you do on the tailnet.

| Method | Description |
|---|---|
| `address()` | This node's primary (IPv4) tailnet address. |
| `addresses()` | All of this node's tailnet addresses (IPv4 and IPv6). |
| `name()` | This node's fully qualified name, such as `worker-7.my-tailnet.ts.net`. |
| `peers()` | A snapshot of the other nodes in the tailnet. |
| `dial(host, port)` | Opens a TCP connection to another node and returns a `java.net.Socket`. |
| `dial(host, port, timeoutMillis)` | Same, with an explicit connect timeout. |
| `listen(port)` | Accepts TCP connections from other nodes and returns a `java.net.ServerSocket`. |
| `ping(host, timeoutMillis)` | Sends an ICMP echo request and returns the round-trip time in milliseconds. |
| `openUdp(port)` | Opens a UDP socket on the tailnet address. |
| `resolve(host)` | Resolves a name to an `InetAddress`. |
| `isDirect(host)` | Reports whether traffic to the node uses a direct connection rather than a relay. |
| `connectionCount()` | The number of TCP connections currently tracked (useful for diagnostics). |
| `socketFactory()` | A `javax.net.SocketFactory` for libraries that open their own connections. |
| `startHttpProxy(port)` | Starts a local HTTP proxy that forwards through the tailnet. |
| `close()` | Leaves the tailnet and releases all resources. |

`Tailnet` is thread-safe. It can be shared between threads, including virtual threads.

---

## 9. TCP connections: `dial` and `listen`

`dial` and `listen` are the core of the API. They return standard `Socket` and `ServerSocket` objects, so existing
code that works with those types works unchanged.

### 9.1 Accepting connections (`listen`)

This server listens on port 7000 and echoes back whatever each client sends.

```java
import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import java.net.ServerSocket;
import java.net.Socket;

public class EchoServer {
    public static void main(String[] args) throws Exception {
        try (Tailnet net = JTail.network()
                .authKey(System.getenv("TS_AUTHKEY"))
                .hostname("echo-server")
                .join();
             ServerSocket server = net.listen(7000)) {

            System.out.println("Listening on " + net.name() + ":7000");

            while (true) {
                Socket client = server.accept();   // blocks until a client connects
                System.out.println("Connection from " + client.getInetAddress().getHostAddress());

                // Handle each client on its own virtual thread so accept() can continue.
                Thread.ofVirtual().start(() -> {
                    try (client) {
                        client.getInputStream().transferTo(client.getOutputStream());
                    } catch (Exception e) {
                        System.out.println("Client disconnected: " + e.getMessage());
                    }
                });
            }
        }
    }
}
```

Notes:

- `net.listen(0)` selects a free port. Read it back with `server.getLocalPort()`.
- `server.setSoTimeout(5000)` makes `accept()` throw a `SocketTimeoutException` after 5 seconds.
- Only nodes inside your tailnet can connect, and only if your ACLs allow it.

### 9.2 Connecting (`dial`)

```java
import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
import java.net.Socket;

public class EchoClient {
    public static void main(String[] args) throws Exception {
        try (Tailnet net = JTail.network()
                .authKey(System.getenv("TS_AUTHKEY"))
                .hostname("echo-client")
                .ephemeral(true)
                .join();
             Socket socket = net.dial("echo-server", 7000)) {

            socket.getOutputStream().write("hello\n".getBytes());
            socket.getOutputStream().flush();

            byte[] buffer = new byte[1024];
            int count = socket.getInputStream().read(buffer);
            System.out.println("Server replied: " + new String(buffer, 0, count));
        }
    }
}
```

`dial("echo-server", 7000)` connects to port 7000 on the node named `echo-server`.

### 9.3 Accepted values for `host`

| Value | Example | Behavior |
|---|---|---|
| Short name | `"echo-server"` | Resolved against the tailnet's nodes. |
| Fully qualified name | `"echo-server.my-tailnet.ts.net"` | Resolved against the tailnet's nodes. |
| IPv4 address | `"100.64.0.7"` | Used as is. |
| IPv6 address | `"fd7a:115c:a1e0::7"` | Used as is. |
| DNS name | `"db.corp.internal"` | Resolved through the tailnet's DNS configuration (see [Section 10](#10-names-and-addresses)). |

Failures surface as standard exceptions: `UnknownHostException` if the name cannot be resolved,
`NoRouteToHostException` if there is no route to the address, and `SocketTimeoutException` if the connection attempt
times out.

### 9.4 Timeouts

The default connect timeout is 30 seconds. To change it, pass a value in milliseconds:

```java
Socket s = net.dial("echo-server", 7000, 5000);   // fail after 5 seconds
```

To bound how long a read may block, use the standard Java option:

```java
socket.setSoTimeout(10_000);   // reads throw SocketTimeoutException after 10 seconds
```

### 9.5 Closing connections

- `socket.close()` closes the connection in both directions.
- `socket.shutdownOutput()` sends a FIN (signals end of the data you are sending) while still allowing you to read the
  remaining data from the peer. Protocols often use this to mark the end of a request.

### 9.6 Keep-alive

`socket.setKeepAlive(true)` enables TCP keep-alive. After 60 seconds of inactivity JTail sends probes every 15 seconds,
and if 8 consecutive probes go unanswered the connection is reset. This lets you detect peers that disappeared without
closing the connection.

### 9.7 Layering TLS

Tailnet traffic is already encrypted by WireGuard. If a service nevertheless requires TLS, wrap the socket as usual:

```java
Socket raw = net.dial("web-server", 443);
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket tls = (SSLSocket) factory.createSocket(raw, "web-server", 443, true);
tls.startHandshake();
```

---

## 10. Names and addresses

### This node's name and addresses

```java
System.out.println(net.name());                     // worker-7.my-tailnet.ts.net
System.out.println(net.address().getHostAddress());  // 100.64.0.3 (IPv4)

for (InetAddress a : net.addresses()) {               // IPv4 and IPv6
    System.out.println(a.getHostAddress());
}
```

### Resolving a name

```java
InetAddress ip = net.resolve("echo-server");
System.out.println(ip.getHostAddress());
```

`resolve` (and therefore `dial`) checks these sources in order:

1. An IP address literal is used as is.
2. The names of peers in the tailnet (short name or fully qualified name).
3. Extra DNS records configured for the tailnet.
4. **Split DNS**: if the tailnet delegates a domain suffix (for example `corp.internal`) to a specific DNS server, JTail
   queries that server through the tailnet.

If none of these resolve the name, an `UnknownHostException` is thrown.

> `resolve` and `dial` only handle names that belong to your tailnet. Ordinary internet host names such as
> `example.com` are not reachable this way, because traffic stays inside the tailnet.

---

## 11. Peers

```java
for (Peer p : net.peers()) {
    System.out.println(p.name() + "  " + p.addresses() + (p.online() ? "  [online]" : "  [offline]"));
}
```

`Peer` is a record with these components:

| Component | Description |
|---|---|
| `name()` | Fully qualified name, such as `database.my-tailnet.ts.net`. |
| `hostname()` | The hostname the node reported. |
| `addresses()` | The node's tailnet addresses. |
| `online()` | Whether the control server currently considers the node connected. |
| `tags()` | The node's ACL tags, such as `tag:server`. |

`peers()` returns the latest known state and is updated in the background as nodes join and leave.

### Waiting for a peer

Immediately after `join()` the peer list may still be filling in. If your program depends on a particular peer, wait
for it:

```java
long deadline = System.currentTimeMillis() + 30_000;
while (net.peers().stream().noneMatch(p -> p.name().startsWith("database"))
        && System.currentTimeMillis() < deadline) {
    Thread.sleep(250);
}
```

---

## 12. Ping

`ping` sends an ICMP echo request and returns the round-trip time.

```java
try {
    long ms = net.ping("echo-server", 5000);   // timeout in milliseconds
    System.out.println("Reply in " + ms + " ms");
} catch (java.net.SocketTimeoutException e) {
    System.out.println("No reply");
}
```

A `SocketTimeoutException` is thrown if no reply arrives in time. Your ACLs determine whether a node accepts pings.

---

## 13. UDP

`openUdp` returns a `UdpSocket` bound to the tailnet address. Use UDP for small messages where low overhead matters more
than guaranteed delivery.

```java
import com.simtechdata.jtail.netstack.UdpSocket;

try (UdpSocket udp = net.openUdp(0)) {                          // 0 selects a free port
    byte[] target = net.resolve("echo-server").getAddress();

    udp.send(target, 7004, "ping".getBytes());

    UdpSocket.Datagram reply = udp.receive(5000);               // timeout in milliseconds
    System.out.println("Received: " + new String(reply.data()));
    System.out.println("From port: " + reply.srcPort());
}
```

- `udp.port()` returns the local port.
- `receive(timeout)` waits indefinitely if the timeout is `0` or negative, and throws `SocketTimeoutException` if no
  datagram arrives in time.
- A datagram must fit within the tailnet MTU (1280 bytes), which is roughly 1,250 bytes of payload for IPv4 and a little
  less for IPv6. Larger payloads throw an `IOException`.

To implement a UDP server, open the socket on a fixed port and call `receive` in a loop. `Datagram` carries the sender's
address, so you can reply:

```java
UdpSocket.Datagram d = udp.receive(0);
udp.send(d.srcIp(), d.srcPort(), "ack".getBytes());
```

---

## 14. Integrating with other libraries

Many libraries (JDBC drivers, HTTP clients, mail clients) open their own connections and know nothing about JTail.
There are two ways to route their traffic through the tailnet.

### 14.1 `SocketFactory`

If the library accepts a `javax.net.SocketFactory`, pass it the one JTail provides:

```java
SocketFactory factory = net.socketFactory();

Socket s = factory.createSocket("db-server", 5432);   // connects immediately
```

The factory also supports unconnected sockets that are connected later, which is how many libraries use it:

```java
Socket s = factory.createSocket();
s.connect(InetSocketAddress.createUnresolved("db-server", 5432), 10_000);
```

Use `InetSocketAddress.createUnresolved(...)` with a host name so that JTail, not the system resolver, performs the
lookup. Consult the library's documentation for where a `SocketFactory` can be configured.

### 14.2 Local HTTP proxy

`java.net.http.HttpClient` and other proxy-aware clients can use the proxy that JTail starts on the loopback interface:

```java
import com.simtechdata.jtail.net.HttpProxy;

try (HttpProxy proxy = net.startHttpProxy(0)) {      // 0 selects a free port

    HttpClient client = HttpClient.newBuilder()
            .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxy.port())))
            .build();

    HttpResponse<String> response = client.send(
            HttpRequest.newBuilder(URI.create("http://internal-api:8080/status")).build(),
            HttpResponse.BodyHandlers.ofString());

    System.out.println(response.statusCode());
    System.out.println(response.body());
}
```

Details:

- The proxy listens only on `127.0.0.1`.
- It supports `CONNECT` (used for HTTPS) and absolute-URI HTTP requests.
- If the target host is not in your tailnet, the client receives a `502 Bad Gateway` response.
- Other tools can use it as well, for example `curl -x http://127.0.0.1:PORT http://internal-api:8080/`.
- Close the proxy when you no longer need it (try-with-resources does this).

---

## 15. Running multiple instances

You can run the same program on many machines, and each instance joins the tailnet as its own node. The requirements are:

1. Create one **reusable** auth key.
2. Give each instance a **unique hostname**.
3. Supply the same key to every instance, for example through the `TS_AUTHKEY` environment variable.

```java
String id = System.getenv("WORKER_ID");        // "1", "2", "3", ...

try (Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))
        .hostname("worker-" + id)               // worker-1, worker-2, ...
        .ephemeral(true)                        // removed automatically when the instance stops
        .join()) {

    // Every worker can now reach every other worker by name, for example:
    // net.dial("worker-1", 9000)
}
```

Notes:

- If two instances use the same hostname, the control server typically assigns the second one a modified name (such as
  `worker-1-1`). Communication still works, but unique hostnames avoid confusion.
- Use `ephemeral(true)` for short-lived instances so the tailnet is not filled with stale nodes.
- Use `stateDir` ([next section](#16-persisting-node-identity)) for long-lived instances that must keep their address.

---

## 16. Persisting node identity

A node's identity consists of private keys. If you do not configure a `stateDir`, JTail generates new keys on every
run, and the control server registers a **new node** (with a new address) each time.

To keep a stable identity, provide a directory:

```java
Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))
        .hostname("database-helper")
        .stateDir(Path.of("jtail-state"))     // created if it does not exist
        .join();
```

JTail stores the identity in `identity.properties` inside that directory.

| With `stateDir` | Without `stateDir` |
|---|---|
| The same node and address after every restart. | A new node on every run. |
| Suitable for services that others depend on. | Suitable for short-lived jobs; combine with `ephemeral(true)`. |

> **Protect the state directory.** It contains private keys; anyone who can read it can impersonate the node. On
> POSIX file systems JTail restricts the file to the owning user.
>
> **Do not share one `stateDir` between instances that run at the same time.** Give each instance its own directory,
> such as `jtail-state/worker-1`.

If the control server reports that a stored node key has expired, JTail generates a new node key, saves it, and
registers again automatically.

---

## 17. Interactive login

If no auth key is available and a user is present (for example in a desktop tool), JTail can use the browser-based login
flow:

```java
Tailnet net = JTail.network()
        .hostname("my-desktop-tool")
        .onLoginRequired(url -> {
            System.out.println("Open this URL to authorize the node:");
            System.out.println(url);
        })
        .join();            // blocks until the login is completed
```

- JTail invokes your handler with a URL.
- Present it to the user in whatever way suits your application (print it, open a browser, show it in a dialog).
- `join()` blocks until the login finishes and then continues.

If the server requires a login and no `onLoginRequired` handler is configured, `join()` throws a `JTailException`.
Because a user may take a while to log in, consider a longer `joinTimeout`, for example
`.joinTimeout(Duration.ofMinutes(5))`.

---

## 18. Direct connections and relays

Two nodes communicate over one of two paths:

```
  Direct:   A ═══════════════════ B          (lower latency)

  Relayed:  A ═════► DERP relay ◄═════ B     (works through almost any network)
```

JTail selects the path automatically:

1. Traffic starts on the relay, so the first packets are delivered immediately.
2. In the background, JTail probes for a direct path (NAT traversal).
3. When a direct path is verified, traffic switches to it. No action is required from your code.

To see which path is in use:

```java
if (net.isDirect("echo-server")) {
    System.out.println("Direct connection");
} else {
    System.out.println("Relayed through DERP");
}
```

### Forcing relays

If UDP is blocked on your network, or you do not want to expose this host's addresses to other nodes, disable direct
connections:

```java
.directPaths(false)
```

All traffic is then relayed through DERP. Functionality is unchanged; latency may be higher.

### Fixing the UDP port

Direct connections use a local UDP port. By default JTail uses any free port. If your firewall requires a specific port,
configure it:

```java
.udpPort(41641)
```

---

## 19. Using Headscale

[Headscale](https://github.com/juanfont/headscale) is a self-hosted implementation of the Tailscale control server. To
use it, set the `controlUrl`:

```java
Tailnet net = JTail.network()
        .controlUrl("https://headscale.example.com")
        .authKey(System.getenv("HEADSCALE_KEY"))
        .hostname("my-node")
        .join();
```

JTail has been tested against Headscale. Use an `https://` URL whenever possible (see
[Section 22](#22-security-considerations)).

---

## 20. Error handling

### 20.1 Errors while joining

`join()` throws `JTailException`, an unchecked exception. Its message describes the cause.

```java
try {
    Tailnet net = JTail.network()
            .authKey(System.getenv("TS_AUTHKEY"))
            .hostname("my-node")
            .join();
    // use the tailnet
} catch (JTailException e) {
    System.err.println("Could not join the tailnet: " + e.getMessage());
}
```

Common causes:

| Message contains | Meaning |
|---|---|
| `invalid authkey` / `rejected registration` | The key is wrong, expired or has been used up. |
| `timed out waiting to join the tailnet` | The control server could not be reached, or it took longer than `joinTimeout`. |
| `could not reach the control server` | No internet connectivity, a wrong `controlUrl`, or a firewall. |
| `interactive login is required` | The server requires a login and no `onLoginRequired` handler was configured. |
| `key ... expired` | The saved node key expired and could not be renewed; the node may need to be re-approved or removed in the admin console. |

### 20.2 Errors while using the tailnet

Methods that perform I/O throw the standard `java.net` / `java.io` exceptions:

| Exception | Typical cause |
|---|---|
| `UnknownHostException` | The name is not in your tailnet or its DNS configuration. |
| `NoRouteToHostException` | There is no route to the destination address. |
| `SocketTimeoutException` | The peer did not respond within the timeout. |
| `SocketException` | The connection was reset, refused or closed. "Connection refused" means nothing is listening on that port. |
| `IOException` | Any other I/O failure while reading or writing. |

A simple retry pattern with increasing delay:

```java
for (int attempt = 1; attempt <= 3; attempt++) {
    try (Socket s = net.dial("database", 5432, 5000)) {
        // use the connection
        break;
    } catch (IOException e) {
        System.out.println("Attempt " + attempt + " failed: " + e.getMessage());
        Thread.sleep(1000L * attempt);
    }
}
```

### 20.3 Startup latency

Shortly after joining, other nodes may not yet know about you, and the first connection to a peer can take a few seconds
to establish. If the first `dial` fails, retry after a short pause.

---

## 21. Shutting down

Always close the `Tailnet` when you are finished. Try-with-resources is the simplest approach; otherwise register a
shutdown hook:

```java
Tailnet net = JTail.join(System.getenv("TS_AUTHKEY"));
Runtime.getRuntime().addShutdownHook(new Thread(net::close));
```

`close()` does the following:

1. Waits up to about 2 seconds for data you have just written to be delivered.
2. For ephemeral nodes, asks the control server to remove the node immediately.
3. Stops all background threads and closes all connections.

Calling `close()` more than once is safe.

---

## 22. Security considerations

- **Protect your auth key.** Use an environment variable or a secrets manager, never source code or version control.
- **Prefer short-lived, narrowly scoped keys.** Use ephemeral keys and tags where possible.
- **Protect `stateDir`.** It contains the node's private keys.
- **Use `https://` for `controlUrl`.** JTail refuses a plain `http://` URL for any host other than the local machine,
  because the control server's key is fetched over that URL and an on-path attacker could intercept your auth key. You
  can override this with `allowInsecureControl(true)`, but only on a network you fully trust.
- **ACLs apply.** JTail enforces the access rules your control server distributes. Inbound connection attempts that the
  rules do not allow are refused. If your server never receives connections, check your ACLs.
- **No independent audit.** JTail is extensively tested, but it has not had an independent security audit. Keep this in
  mind if you protect highly sensitive data.

---

## 23. Troubleshooting

**`join()` blocks or times out.**
Verify internet connectivity and the `controlUrl`, and make sure outbound HTTPS (port 443) is allowed. By default the
join fails after 60 seconds with an exception that describes the cause.

**`dial` throws `UnknownHostException`.**
The peer may not be online yet or the name may be misspelled. Print `net.peers()` to see which names exist. The peer
list can take a moment to populate after joining.

**`dial` throws "connection refused".**
The peer is reachable but nothing is listening on that port. Check that the server is running and that the port number
is correct.

**`dial` times out.**
Usually an ACL blocks the connection or the peer is offline. Try `net.ping(...)` first. Remember that your own node must
also be allowed to reach the target.

**Connections are slow.**
You may be using a relay. Check `net.isDirect(host)`. Direct paths require UDP to work on both sides, and JTail upgrades
to a direct path in the background a few seconds after the first traffic. With `directPaths(false)` traffic always uses
a relay.

**Every run creates a new node.**
Use `ephemeral(true)` so stale nodes are removed automatically, or use `stateDir` so the same identity is reused.

**Two instances interfere with each other.**
They share a `stateDir` or a hostname. Give each instance its own.

**`join()` rejects the control URL.**
You passed a plain `http://` URL for a non-local host. Use `https://`.

---

## 24. Limitations

- **Exit nodes** (routing all internet traffic through another node) are not supported.
- **Advertising subnet routes** is not supported. Using routes advertised by other nodes works with
  `acceptRoutes(true)`.
- **Tailnet Lock**, **Taildrop**, **Tailscale SSH** and **Serve/Funnel** are not supported.
- **DNS-over-HTTPS resolvers** and **OAuth client credentials** are not supported; use standard auth keys.
- JTail does not create a network interface. Only your Java program joins the tailnet.

---

## 25. Quick reference

```java
// 1. Join
Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))   // required (or onLoginRequired)
        .hostname("my-node")                     // unique per instance
        .stateDir(Path.of("jtail-state"))        // optional: persist identity
        .ephemeral(true)                         // optional: auto-remove when offline
        .join();

// 2. This node
net.name();   net.address();   net.addresses();

// 3. Other nodes
net.peers();

// 4. Connect (TCP)
Socket s = net.dial("other-node", 8080);

// 5. Accept connections (TCP)
ServerSocket server = net.listen(8080);
Socket client = server.accept();

// 6. UDP
UdpSocket udp = net.openUdp(0);

// 7. Diagnostics
long ms = net.ping("other-node", 5000);
boolean direct = net.isDirect("other-node");

// 8. Integration with other libraries
net.socketFactory();
net.startHttpProxy(0);

// 9. Leave
net.close();
```

| Goal | API |
|---|---|
| Join the tailnet | `JTail.network()...join()` |
| Connect to another node | `net.dial(name, port)` |
| Accept connections | `net.listen(port)` |
| Send datagrams | `net.openUdp(port)` |
| List nodes | `net.peers()` |
| Check reachability | `net.ping(name, ms)` |
| Keep the same address across restarts | `.stateDir(path)` |
| Remove the node automatically when it stops | `.ephemeral(true)` |
| Use a self-hosted Headscale server | `.controlUrl("https://...")` |
| Give a library a connection factory | `net.socketFactory()` |
| Use `HttpClient` through the tailnet | `net.startHttpProxy(0)` |
| Force all traffic through relays | `.directPaths(false)` |

---

### Further reading

- The **README** in the repository root describes how JTail works internally and how it was verified.
- The **`examples/`** folder contains runnable programs: an echo server, an echo client and an interactive login
  example.
- The tests in `src/test/java/.../e2e/` show real, working uses of the API.
