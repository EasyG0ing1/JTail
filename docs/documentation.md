# JTail — The Friendly Guide

Welcome! This guide explains how to use **JTail** in your own Java programs. You do not need to know anything about
networking to follow along. Every new word is explained the first time it shows up.

---

## Table of Contents

1. [What is JTail?](#1-what-is-jtail)
2. [A few words you need to know](#2-a-few-words-you-need-to-know)
3. [What you need before you start](#3-what-you-need-before-you-start)
4. [Adding JTail to your project](#4-adding-jtail-to-your-project)
5. [Get an auth key](#5-get-an-auth-key)
6. [Your first program](#6-your-first-program)
7. [All the settings (the builder)](#7-all-the-settings-the-builder)
8. [Everything you can do with a `Tailnet`](#8-everything-you-can-do-with-a-tailnet)
9. [Talking to other computers: `dial` and `listen`](#9-talking-to-other-computers-dial-and-listen)
10. [Names and addresses](#10-names-and-addresses)
11. [Looking at the other computers (peers)](#11-looking-at-the-other-computers-peers)
12. [Ping](#12-ping)
13. [UDP: fast and simple messages](#13-udp-fast-and-simple-messages)
14. [Using JTail with other libraries](#14-using-jtail-with-other-libraries)
15. [Running many copies of your program](#15-running-many-copies-of-your-program)
16. [Saving your identity between restarts](#16-saving-your-identity-between-restarts)
17. [Logging in without an auth key](#17-logging-in-without-an-auth-key)
18. [Direct connections vs. relays](#18-direct-connections-vs-relays)
19. [Using Headscale instead of Tailscale](#19-using-headscale-instead-of-tailscale)
20. [Handling errors](#20-handling-errors)
21. [Shutting down properly](#21-shutting-down-properly)
22. [Staying safe](#22-staying-safe)
23. [Things that go wrong (and how to fix them)](#23-things-that-go-wrong-and-how-to-fix-them)
24. [Things JTail cannot do (yet)](#24-things-jtail-cannot-do-yet)
25. [Quick cheat sheet](#25-quick-cheat-sheet)

---

## 1. What is JTail?

Imagine you have a few computers in different places: one at home, one in the cloud, one at school. Normally they
cannot talk to each other easily, because each one sits behind its own router and firewall.

**Tailscale** is a service that fixes this. It builds a **private network** that connects all your computers, like they
were all plugged into the same switch, no matter where they really are. Everything sent over it is **encrypted**
(scrambled so nobody else can read it).

Usually, to be part of a Tailscale network, you install a separate program on the computer. **JTail is different.**
JTail is a Java library, so your Java program can join the private network **all by itself**:

- No Tailscale app to install.
- No Go, Rust or C code.
- No administrator (root) rights needed.
- No other libraries to download. JTail needs nothing except Java 21.

You write a few lines of code, and your program becomes a member of the private network.

```
   Your Java program                            Another computer
 ┌──────────────────────┐                     ┌────────────────────┐
 │  JTail               │ ◄══ private,       ═► │ Tailscale / JTail  │
 │  (joins the network) │     encrypted link  │                    │
 └──────────────────────┘                     └────────────────────┘
```

---

## 2. A few words you need to know

| Word | What it means |
|---|---|
| **Tailnet** | Your private network. "Tail" comes from Tailscale, "net" from network. Everything that joins it can talk to everything else (unless rules say otherwise). |
| **Node** | One member of the tailnet. Your running Java program is a node. |
| **Peer** | *Another* node, from your point of view. |
| **Auth key** | A secret password-like text that lets a program join your tailnet without anybody clicking anything. It looks like `tskey-auth-abc123...`. |
| **Hostname** | The name of a node, like `worker-1` or `database`. |
| **IP address** | A number that identifies a computer on a network, like `100.64.0.5`. Tailnet addresses start with `100.`. |
| **Port** | A numbered "door" on a computer. A web server uses door 80 or 443, a database might use 5432. |
| **TCP** | A way of sending data that makes sure everything arrives, in order. Most programs use it (websites, databases, chat). |
| **UDP** | A faster, simpler way of sending small messages. Some can get lost. Used for games, video calls and similar. |
| **Socket** | Java's name for "a connection you can read from and write to." |
| **DERP relay** | A helper server on the internet that passes your messages along when two computers can't reach each other directly. Think of it like a post office. |
| **Direct connection** | When two nodes talk straight to each other without a relay. Faster! |
| **Control server** | The "brain" of the tailnet. It keeps the list of who is in the network. For Tailscale this is run by Tailscale. [Headscale](https://github.com/juanfont/headscale) is a free version you can run yourself. |
| **MagicDNS** | Lets you use names like `database` instead of numbers like `100.64.0.5`. |

---

## 3. What you need before you start

1. **Java 21 or newer.** Check with `java -version`.
2. **A tailnet.** This is a Tailscale account with at least one network (free accounts work), *or* your own Headscale
   server.
3. **An auth key** (the next sections show how to get one).
4. **Another node to talk to** (optional but fun). It could be another computer running Tailscale, or another copy of
   your own program using JTail.

---

## 4. Adding JTail to your project

JTail is built with Maven. Download the code, then run this in the project folder:

```bash
mvn install
```

This puts JTail into your computer's local Maven storage. Then add it to **your own** project's `pom.xml`:

```xml
<dependency>
    <groupId>com.simtechdata</groupId>
    <artifactId>JTail</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Make sure your project is set to Java 21:

```xml
<properties>
    <maven.compiler.release>21</maven.compiler.release>
</properties>
```

Everything you will use lives in one package. These are the only imports you normally need:

```java
import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;
```

---

## 5. Get an auth key

An auth key lets your program join **without a human clicking a login button**. That is perfect for programs that run
on their own.

**With Tailscale:**

1. Go to the Tailscale admin website and open **Settings → Keys**.
2. Click **Generate auth key**.
3. Choose the options:
   - **Reusable** — turn this **on** if several copies of your program should use the same key.
   - **Ephemeral** — turn this on if nodes should vanish from your network when they stop running.
   - **Pre-approved** — turn on if your network makes you approve new devices.
   - **Tags** — optional labels (like `tag:worker`) that your network rules can use.
4. Copy the key. **You can only see it once!**

**With Headscale:** run `headscale preauthkeys create --user 1 --reusable --expiration 24h`.

> ### 🔐 Treat the key like a password
> Anyone with your key can add devices to your network.
> - Never write it directly into your source code.
> - Never post it online or commit it to Git.
> - Put it in an **environment variable** instead (shown below).

To set an environment variable:

```bash
# Linux / macOS
export TS_AUTHKEY="tskey-auth-xxxxxxxxxxxx"

# Windows (PowerShell)
$env:TS_AUTHKEY = "tskey-auth-xxxxxxxxxxxx"
```

In Java you read it with `System.getenv("TS_AUTHKEY")`.

---

## 6. Your first program

Here is the smallest useful program. It joins the network, prints who it is, and leaves.

```java
import com.simtechdata.jtail.JTail;
import com.simtechdata.jtail.Tailnet;

public class Hello {
    public static void main(String[] args) throws Exception {
        try (Tailnet net = JTail.network()
                .authKey(System.getenv("TS_AUTHKEY"))
                .hostname("my-first-jtail")
                .join()) {

            System.out.println("I joined the network!");
            System.out.println("My name:    " + net.name());
            System.out.println("My address: " + net.address().getHostAddress());
        }
    }
}
```

What each part does:

- `JTail.network()` starts building your settings.
- `.authKey(...)` gives the secret key.
- `.hostname(...)` picks the name other computers will see.
- `.join()` **connects**. It waits (up to 60 seconds) until your program is really part of the network. If something
  goes wrong it throws a `JTailException` (see [Handling errors](#20-handling-errors)).
- `try (...) { }` is Java's "try-with-resources." When the block ends, Java automatically calls `close()`, which
  leaves the network cleanly. You don't have to remember to do it.

### Even shorter

If you only have a key and are happy with the defaults:

```java
Tailnet net = JTail.join(System.getenv("TS_AUTHKEY"));
```

Remember to call `net.close()` when you are done!

---

## 7. All the settings (the builder)

`JTail.network()` gives you a **builder**. You call methods on it to choose settings, one after another (this is
called "chaining"), and finish with `.join()`. Only `authKey` is required (unless you use
[interactive login](#17-logging-in-without-an-auth-key)). Everything else has a sensible default.

```java
Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))
        .hostname("worker-7")
        .stateDir(Path.of("jtail-state"))
        .ephemeral(true)
        .tag("tag:worker")
        .join();
```

### The settings, one by one

| Method | What it does | Default |
|---|---|---|
| `authKey(String)` | The secret key that lets you join. | *(required)* |
| `hostname(String)` | The name of your node. Make it **different for every copy** of your program. | The computer's own name |
| `controlUrl(String)` | The address of the control server. Only change this if you use Headscale. | Tailscale's server |
| `stateDir(Path)` | A folder where JTail saves your node's identity, so you keep the same address after a restart. | *none* (a new identity each run) |
| `ephemeral(boolean)` | If `true`, the node is deleted from the network automatically when it goes away. | `false` |
| `tag(String)` | Asks for a label like `tag:worker`. Can be called several times. Your key must be allowed to use it. | *none* |
| `joinTimeout(Duration)` | How long `join()` waits before giving up. | 60 seconds |
| `directPaths(boolean)` | `false` forces *everything* through relays (see [section 18](#18-direct-connections-vs-relays)). | `true` |
| `udpPort(int)` | A fixed UDP port to use for direct connections. | `0` (any free port) |
| `acceptRoutes(boolean)` | Lets you reach whole networks that another node shares (a "subnet router"). | `false` |
| `onLoginRequired(Consumer<String>)` | Lets you log in through a web page when you have no auth key. | *none* |
| `allowInsecureControl(boolean)` | Allows a non-HTTPS control address on a non-local machine. **Unsafe**, see [section 22](#22-staying-safe). | `false` |
| `includeLoopbackEndpoints(boolean)` | Only for tests where several nodes run on one computer. | `false` |

### Build first, join later

If you want to create the settings now and join later, use `build()`:

```java
JTailConfig config = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))
        .hostname("later")
        .build();          // nothing happens on the network yet

// ...later...
Tailnet net = JTail.join(config);
```

---

## 8. Everything you can do with a `Tailnet`

When `join()` succeeds you get a `Tailnet` object. Think of it as your **remote control for the private network**.
Here is every button on it:

| Method | What it gives you |
|---|---|
| `address()` | Your own main (IPv4) address, like `100.64.0.3`. |
| `addresses()` | All your addresses (IPv4 and IPv6). |
| `name()` | Your full name on the network, like `worker-7.tailnet-name.ts.net`. |
| `peers()` | A list of the other nodes. |
| `dial(host, port)` | Opens a connection **to** another node. Returns a normal Java `Socket`. |
| `dial(host, port, timeoutMillis)` | Same, but with your own waiting time. |
| `listen(port)` | Waits for other nodes to connect **to you**. Returns a normal Java `ServerSocket`. |
| `ping(host, timeoutMillis)` | Checks if a node answers and how fast. |
| `openUdp(port)` | Opens a UDP socket for small, fast messages. |
| `resolve(host)` | Turns a name into an address. |
| `isDirect(host)` | Tells you if you talk to that node directly (fast) or through a relay. |
| `connectionCount()` | How many TCP connections are open (handy for debugging). |
| `socketFactory()` | A "socket maker" for other libraries (see [section 14](#14-using-jtail-with-other-libraries)). |
| `startHttpProxy(port)` | Starts a tiny local web proxy (see [section 14](#14-using-jtail-with-other-libraries)). |
| `close()` | Leaves the network and cleans everything up. |

A `Tailnet` is **thread-safe**: many threads can use it at the same time, and you can use it from virtual threads.

---

## 9. Talking to other computers: `dial` and `listen`

This is the heart of the library. There are two roles:

- The **client** reaches out: `dial`.
- The **server** waits to be reached: `listen`.

Both give you the **normal Java classes** `Socket` and `ServerSocket`. If you have used those before, you already know
how to use them. If not, here is the idea: a `Socket` has an **input stream** (data coming in) and an **output
stream** (data going out).

### 9.1 Being a server (`listen`)

This program waits for connections on port 7000. Whatever a client sends, it sends back (an "echo server").

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

            System.out.println("Waiting on " + net.name() + " port 7000");

            while (true) {
                Socket client = server.accept();   // waits here until someone connects
                System.out.println("Someone connected from "
                        + client.getInetAddress().getHostAddress());

                // Handle each client in its own thread so we can accept more clients.
                Thread.ofVirtual().start(() -> {
                    try (client) {
                        client.getInputStream().transferTo(client.getOutputStream());
                    } catch (Exception e) {
                        System.out.println("Client left: " + e.getMessage());
                    }
                });
            }
        }
    }
}
```

Good to know:

- `net.listen(0)` picks any free port. Read it with `server.getLocalPort()`.
- `server.setSoTimeout(5000)` makes `accept()` give up after 5 seconds with a `SocketTimeoutException`.
- Only computers **inside your tailnet** can connect (and only if your network's rules allow it).

### 9.2 Being a client (`dial`)

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

            socket.getOutputStream().write("hello there\n".getBytes());
            socket.getOutputStream().flush();

            byte[] buffer = new byte[1024];
            int count = socket.getInputStream().read(buffer);
            System.out.println("Server said: " + new String(buffer, 0, count));
        }
    }
}
```

`dial("echo-server", 7000)` means: "connect to the node named `echo-server`, door number 7000."

### 9.3 What can I put as the `host`?

`dial` is flexible. The first argument can be:

| You write | Example | What happens |
|---|---|---|
| A short name | `"echo-server"` | Looks it up in your tailnet. |
| A full name | `"echo-server.my-tailnet.ts.net"` | Looks it up in your tailnet. |
| An IPv4 address | `"100.64.0.7"` | Used as-is. |
| An IPv6 address | `"fd7a:115c:a1e0::7"` | Used as-is. |
| A special DNS name | `"db.corp.internal"` | Looked up using your network's DNS settings (see [section 10](#10-names-and-addresses)). |

If the name can't be found you get an `UnknownHostException`. If there's no path to the computer you get a
`NoRouteToHostException`. If the other side doesn't answer in time you get a `SocketTimeoutException`.

### 9.4 Waiting less (or more)

The default wait for connecting is 30 seconds. Choose your own (in **milliseconds**):

```java
Socket s = net.dial("echo-server", 7000, 5000);   // give up after 5 seconds
```

To limit how long a *read* may wait, use the normal Java way:

```java
socket.setSoTimeout(10_000);   // reading gives up after 10 seconds
```

### 9.5 Closing a connection politely

- `socket.close()` closes everything.
- `socket.shutdownOutput()` says "I'm finished sending" but you can still **read** what the other side has left to say.
  Programs often use this to signal "that's the whole message."

### 9.6 Keep-alive

`socket.setKeepAlive(true)` turns on **keep-alive**: if the connection sits quietly for a minute, JTail sends tiny
checks. If the other computer has vanished (power cut, crash), the connection is closed with an error instead of
hanging forever.

### 9.7 Secure connections (TLS / HTTPS) on top

Tailnet traffic is already encrypted. But if you need TLS for another reason (for example a server expects HTTPS), wrap
the socket the usual Java way:

```java
Socket raw = net.dial("web-server", 443);
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket tls = (SSLSocket) factory.createSocket(raw, "web-server", 443, true);
tls.startHandshake();
```

---

## 10. Names and addresses

### My own name and addresses

```java
System.out.println(net.name());                    // worker-7.my-tailnet.ts.net
System.out.println(net.address().getHostAddress()); // 100.64.0.3   (IPv4)

for (InetAddress a : net.addresses()) {              // IPv4 and IPv6
    System.out.println(a.getHostAddress());
}
```

### Turning a name into an address

```java
InetAddress ip = net.resolve("echo-server");
System.out.println(ip.getHostAddress());
```

`resolve` looks in these places, in this order:

1. Is it already an IP address? Then use it.
2. Is it the name of a **peer** in your network? (short name or full name)
3. Is it a special "extra record" your network's admin set up?
4. Does your network use **split DNS** for that name's ending (like `corp.internal`)? Then JTail asks the right
   DNS server **through the tailnet**.

If none of these find it, you get an `UnknownHostException`.

> **Note:** `resolve` and `dial` only know about names that live in your tailnet. A normal website name like
> `example.com` is not reachable this way, because your traffic stays inside the private network.

---

## 11. Looking at the other computers (peers)

```java
for (Peer p : net.peers()) {
    System.out.println(p.name() + "  " + p.addresses()
            + (p.online() ? "  [online]" : "  [offline]"));
}
```

A `Peer` has these pieces of information:

| Piece | Meaning |
|---|---|
| `name()` | Full name, like `database.my-tailnet.ts.net`. |
| `hostname()` | The short name the node gave itself. |
| `addresses()` | A list of its tailnet addresses. |
| `online()` | `true` if the control server thinks it is currently connected. |
| `tags()` | Its labels, like `tag:server`. |

### Waiting for a peer to show up

Right after joining, the list of peers may still be filling in. If you need a certain peer, wait for it:

```java
long giveUp = System.currentTimeMillis() + 30_000;
while (net.peers().stream().noneMatch(p -> p.name().startsWith("database"))
        && System.currentTimeMillis() < giveUp) {
    Thread.sleep(250);
}
```

The list always shows the **latest** information; it updates by itself as nodes come and go.

---

## 12. Ping

`ping` sends a tiny "are you there?" message and measures how long the answer takes.

```java
try {
    long ms = net.ping("echo-server", 5000);   // wait up to 5 seconds
    System.out.println("It answered in " + ms + " ms");
} catch (java.net.SocketTimeoutException e) {
    System.out.println("No answer.");
}
```

If the other node doesn't answer in time, a `SocketTimeoutException` is thrown. Your network's rules decide whether a
node accepts pings at all.

---

## 13. UDP: fast and simple messages

TCP (sockets above) is like a phone call: a steady, reliable line. **UDP** is like sending postcards: quick, but a
postcard can occasionally get lost, and they may arrive out of order. It's great for things like games or sending
sensor readings.

```java
import com.simtechdata.jtail.netstack.UdpSocket;

try (UdpSocket udp = net.openUdp(0)) {                         // 0 = pick any free port
    byte[] target = net.resolve("echo-server").getAddress();   // the address as bytes

    udp.send(target, 7004, "ping!".getBytes());                // send a postcard

    UdpSocket.Datagram reply = udp.receive(5000);              // wait up to 5 seconds
    System.out.println("Got: " + new String(reply.data()));
    System.out.println("From port: " + reply.srcPort());
}
```

- `udp.port()` tells you which port you got.
- `receive(0)` (or any number ≤ 0) waits **forever**.
- If nothing arrives in time, you get a `SocketTimeoutException`.
- A single UDP message must fit in about **1,250 bytes** (IPv4; a little less for IPv6). Bigger ones throw an `IOException`.

To **be** a UDP server, open the socket on a fixed port (`net.openUdp(7004)`) and keep calling `receive`.
The `Datagram` you receive tells you who sent it (`srcIp()` and `srcPort()`), so you can reply:

```java
UdpSocket.Datagram d = udp.receive(0);
udp.send(d.srcIp(), d.srcPort(), "got it".getBytes());
```

---

## 14. Using JTail with other libraries

Lots of Java libraries open their own network connections: database drivers, web clients, email libraries. They don't
know about JTail. Here are two easy ways to make them use your tailnet.

### 14.1 The Socket Factory

Many libraries let you hand them a `javax.net.SocketFactory` (a "socket maker"). JTail gives you one:

```java
SocketFactory factory = net.socketFactory();

Socket s = factory.createSocket("db-server", 5432);          // connects right away
```

You can also create an **unconnected** socket first and connect it later, which is what many libraries do:

```java
Socket s = factory.createSocket();
s.connect(InetSocketAddress.createUnresolved("db-server", 5432), 10_000);
```

> Use `InetSocketAddress.createUnresolved(...)` with a **name**, so JTail (not your computer's normal DNS) looks it up.

Check the documentation of the library you are using for where to plug in a `SocketFactory`.

### 14.2 The local HTTP proxy

Java's built-in `HttpClient` can use an **HTTP proxy**. JTail can start a tiny proxy on your own computer that sends
everything through the tailnet.

```java
import com.simtechdata.jtail.net.HttpProxy;

try (HttpProxy proxy = net.startHttpProxy(0)) {      // 0 = any free port

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

Things to know about the proxy:

- It listens **only on your own computer** (`127.0.0.1`), so nobody else on your network can use it.
- It understands `CONNECT` (used for HTTPS) and normal `http://` requests.
- If the website name isn't in your tailnet, the client gets a `502 Bad Gateway` answer instead of hanging.
- Other programs (like `curl`) can use it too: `curl -x http://127.0.0.1:PORT http://internal-api:8080/`.
- Close it (the `try` block does that for you) when you no longer need it.

---

## 15. Running many copies of your program

This is one of JTail's best tricks: run the **same program on many computers**, and every copy joins your network as its
own node.

The rules are simple:

1. Create **one reusable auth key**.
2. Give each copy a **different hostname**.
3. Give each copy the same key (for example through the `TS_AUTHKEY` environment variable).

```java
String id = System.getenv("WORKER_ID");        // "1", "2", "3", ...

try (Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))
        .hostname("worker-" + id)               // worker-1, worker-2, ...
        .ephemeral(true)                        // clean up automatically when they stop
        .join()) {

    // every worker can now reach every other worker by name, for example:
    // net.dial("worker-1", 9000)
}
```

Tips:

- If two copies use the **same hostname**, the network usually gives the second one a slightly different name (like
  `worker-1-1`). It still works, but names become confusing, so keep them unique.
- Use `ephemeral(true)` for short-lived programs so your network doesn't fill up with dead nodes.
- Use `stateDir` (next section) for long-lived programs that should keep the same address.

---

## 16. Saving your identity between restarts

Each node has secret keys that prove who it is. If you don't tell JTail where to save them, it makes **brand-new keys
every time**, and the network sees a **new node** (with a new address) every run.

To keep the same identity, give it a folder:

```java
Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))
        .hostname("database-helper")
        .stateDir(Path.of("jtail-state"))     // created automatically if needed
        .join();
```

JTail saves one file in there: `identity.properties`.

| With `stateDir` | Without `stateDir` |
|---|---|
| Same node and same address every restart. | A new node every run. |
| Good for servers other things depend on. | Good for short jobs. Pair with `ephemeral(true)`. |

> **Keep that folder private!** It contains secret keys. Anyone who can read the file can pretend to be your node.
> JTail makes the file readable by you only (on Linux and macOS).
>
> **Don't share one `stateDir` between two copies running at the same time**; they would fight over the same identity.
> Give each copy its own folder, like `jtail-state/worker-1`.

---

## 17. Logging in without an auth key

Sometimes you don't have a key and a human is at the keyboard (for example, a desktop tool). JTail can use the normal
"open this web page and log in" flow:

```java
Tailnet net = JTail.network()
        .hostname("my-desktop-tool")
        .onLoginRequired(url -> {
            System.out.println("Please open this web address to log in:");
            System.out.println(url);
        })
        .join();            // waits here until the person finishes logging in
```

- JTail calls your function with a web address.
- Show it to the user (print it, open a browser, show it in a window).
- `join()` waits until they finish. It continues by itself afterwards.

If you forget `onLoginRequired` **and** the server wants a login, `join()` throws a `JTailException` telling you so.

Remember: `joinTimeout` applies to the normal join steps. A person can take a while to log in, so for this flow you may
want a longer value (`.joinTimeout(Duration.ofMinutes(5))`).

---

## 18. Direct connections vs. relays

When two nodes talk, there are two possible roads:

```
  Direct:   A ═══════════════════ B          (fast, short)

  Relayed:  A ═════► DERP relay ◄═════ B     (works almost anywhere, a bit slower)
```

JTail is clever about this:

1. It **starts with the relay**, so your first message goes through right away.
2. In the background it tries to find a **direct** road (this trick is called NAT traversal).
3. If it finds one, it **switches to it automatically**. You don't have to do anything.

You can look at what is happening:

```java
if (net.isDirect("echo-server")) {
    System.out.println("Talking directly. Nice and fast!");
} else {
    System.out.println("Using a relay for now.");
}
```

### Forcing relays only

Sometimes you want **no direct connections**: for example, UDP is blocked on your network, or you don't want to show
your computer's addresses to other nodes.

```java
.directPaths(false)
```

Everything still works, just always through the relays.

### Choosing the UDP port

Direct connections use a UDP port on your computer. By default JTail picks any free one. If your firewall needs a
specific port open, set it:

```java
.udpPort(41641)
```

---

## 19. Using Headscale instead of Tailscale

**Headscale** is a free program you can run on your own server that does the job of Tailscale's control server. To make
JTail talk to it, change the `controlUrl`:

```java
Tailnet net = JTail.network()
        .controlUrl("https://headscale.example.com")
        .authKey(System.getenv("HEADSCALE_KEY"))
        .hostname("my-node")
        .join();
```

JTail has been tested against Headscale and works with it. Use `https://` addresses whenever you can
(see [Staying safe](#22-staying-safe)).

---

## 20. Handling errors

Things can go wrong on a network, so be ready for them.

### 20.1 Problems while joining

`join()` throws `JTailException` (an unchecked exception, so you are not forced to catch it). The message tells you
what happened.

```java
try {
    Tailnet net = JTail.network()
            .authKey(System.getenv("TS_AUTHKEY"))
            .hostname("my-node")
            .join();
    // ... use it ...
} catch (JTailException e) {
    System.err.println("Could not join the network: " + e.getMessage());
}
```

Common reasons:

| The message says something like... | What it means |
|---|---|
| `invalid authkey` / `rejected registration` | The key is wrong, expired or used up. |
| `timed out waiting to join the tailnet` | The control server can't be reached, or it took too long. |
| `could not reach the control server` | No internet, wrong `controlUrl`, or a firewall. |
| `interactive login is required` | The server wants a human login and you didn't set `onLoginRequired`. |
| `node key ... expired` | Your saved identity is too old; remove or refresh the `stateDir`. |

### 20.2 Problems while using the network

The methods that touch the network throw the usual Java exceptions:

| Exception | When |
|---|---|
| `java.net.UnknownHostException` | The name isn't in your tailnet or DNS. |
| `java.net.NoRouteToHostException` | There's no way to get to that address. |
| `java.net.SocketTimeoutException` | The other side didn't answer in time. |
| `java.net.SocketException` | The connection was reset, refused or closed. (A "connection refused" message means nothing is listening on that port.) |
| `java.io.IOException` | Anything else that went wrong while reading or writing. |

A friendly pattern for making connections that might fail:

```java
for (int attempt = 1; attempt <= 3; attempt++) {
    try (Socket s = net.dial("database", 5432, 5000)) {
        // use the connection
        break;
    } catch (IOException e) {
        System.out.println("Attempt " + attempt + " failed: " + e.getMessage());
        Thread.sleep(1000L * attempt);       // wait a bit longer each time
    }
}
```

### 20.3 Peers need a moment

Right after you join, other nodes may need a few seconds to learn about you and for the first messages to make their
way through (and sometimes the very first connection needs a few extra seconds to set up). If a first `dial` fails, try
again after a short pause.

---

## 21. Shutting down properly

Always close your `Tailnet` when you are finished. The easiest way is `try-with-resources`, like the examples above. If
you can't, call it yourself:

```java
Tailnet net = JTail.join(System.getenv("TS_AUTHKEY"));
Runtime.getRuntime().addShutdownHook(new Thread(net::close));   // closes on Ctrl+C too
```

What `close()` does:

1. Waits up to about 2 seconds so data you just wrote has time to reach the other side.
2. If the node is `ephemeral`, tells the control server to remove it immediately.
3. Stops all background threads and closes the connections.

You can call `close()` more than once; it is safe.

---

## 22. Staying safe

- **Protect your auth key.** Use an environment variable or a secrets manager, never source code or Git.
- **Prefer short-lived, limited keys.** Use ephemeral keys and tags where you can.
- **Protect `stateDir`.** It holds secret keys.
- **Use `https://` for `controlUrl`.** JTail refuses a plain `http://` address for any computer other than your own
  machine, because someone on the network could steal your key. You can override with `allowInsecureControl(true)`,
  but only do this on a network you completely trust.
- **The network's rules still apply.** Tailscale/Headscale can have an **ACL** (access rules). JTail obeys them: if the
  rules say nobody may connect to your port, connections are refused.
- **Incoming connections are blocked unless allowed.** If your server doesn't receive any connections, check the access
  rules of your network.
- **JTail has not had an independent security audit.** It is carefully tested, but if you protect something very
  valuable, keep that in mind.

---

## 23. Things that go wrong (and how to fix them)

**"My program hangs on `join()`."**
Check your internet connection and the `controlUrl`. Make sure outgoing HTTPS (port 443) is allowed. Remember the join
gives up after 60 seconds by default and then throws an exception with details.

**"`dial` says the name is unknown."**
The peer may not be online yet, or you typed the name wrong. Print `net.peers()` to see what names exist. The peer list
can take a moment to fill after joining.

**"`dial` says connection refused."**
The other computer is reachable, but nothing is listening on that port. Is the server program running? Is the port
number right?

**"`dial` just times out."**
Most often the network's access rules (ACLs) block that connection, or the other node is offline. Try `net.ping(...)`
first. Note: your own program must also be allowed to reach the target.

**"It works, but it feels slow."**
You might be using a relay. Check `net.isDirect(host)`. Direct paths need UDP to work on both sides. Give it a few
seconds after the first message, because JTail upgrades to a direct road in the background. (Using `directPaths(false)`
always means relay.)

**"Every run creates a new node and my network fills up."**
Either use `ephemeral(true)` so they clean themselves up, or use `stateDir` so the same identity is reused.

**"Two copies are fighting."**
They use the same `stateDir` or the same hostname. Give each copy its own.

**"`join()` complains about http."**
You gave a plain `http://` control address for a non-local machine. Use `https://`.

---

## 24. Things JTail cannot do (yet)

Being honest helps you plan:

- **Exit nodes** (sending *all* your internet traffic through another node).
- **Sharing your own subnet** with the network (advertising routes). *Using* subnets other nodes share works with
  `acceptRoutes(true)`.
- **Tailnet Lock**, **Taildrop** (file sharing), **Tailscale SSH**, **Serve/Funnel**.
- **DNS over HTTPS** servers and **OAuth client keys**. Use normal auth keys.
- JTail does not make your *whole computer* part of the network. Only **your Java program** is. Other programs on the
  same computer are not affected.

---

## 25. Quick cheat sheet

```java
// 1. Join
Tailnet net = JTail.network()
        .authKey(System.getenv("TS_AUTHKEY"))   // required (or onLoginRequired)
        .hostname("my-node")                     // unique per copy
        .stateDir(Path.of("jtail-state"))        // optional: keep identity
        .ephemeral(true)                         // optional: auto-remove when gone
        .join();

// 2. Who am I?
net.name();   net.address();   net.addresses();

// 3. Who else is here?
net.peers();

// 4. Connect to someone (TCP)
Socket s = net.dial("other-node", 8080);

// 5. Wait for connections (TCP)
ServerSocket server = net.listen(8080);
Socket client = server.accept();

// 6. Small fast messages (UDP)
UdpSocket udp = net.openUdp(0);

// 7. Check a node
long ms = net.ping("other-node", 5000);
boolean fast = net.isDirect("other-node");

// 8. Plug into other libraries
net.socketFactory();
net.startHttpProxy(0);

// 9. Leave
net.close();
```

| I want to... | Use |
|---|---|
| Join the network | `JTail.network()...join()` |
| Connect to another node | `net.dial(name, port)` |
| Accept connections | `net.listen(port)` |
| Send fast small messages | `net.openUdp(port)` |
| See who is online | `net.peers()` |
| Test if a node is reachable | `net.ping(name, ms)` |
| Keep the same address after restarting | `.stateDir(path)` |
| Auto-remove my node when I stop | `.ephemeral(true)` |
| Use my own Headscale server | `.controlUrl("https://...")` |
| Give a library a connection maker | `net.socketFactory()` |
| Use `HttpClient` through the tailnet | `net.startHttpProxy(0)` |
| Force everything through relays | `.directPaths(false)` |

---

### Where to go next

- The **README** in the main folder has a technical overview of how JTail works inside.
- The **`examples/`** folder has complete programs you can run: an echo server, an echo client and an interactive login
  example.
- The **tests** in `src/test/java/.../e2e/` show many real working uses of the API.

Happy networking! 🎉
