// Dev-time oracle: a real Tailscale client (tsnet) joined to a control server, so JTail's pure-Java node can be
// verified against the genuine Go implementation of the data plane (WireGuard, magicsock, netstack, ACL filter).
//
//	go-tsnet -control URL -authkey KEY -host NAME
//
// Prints "UP <ip4> <ip6>" once online. Stdin commands (one per line):
//
//	echo <port>                     start a TCP echo server ("go:" + data) on the tailnet
//	sink <port>                     accept one TCP conn, read to EOF, reply with hex sha256 of what was read
//	dial <host:port> <message>      dial, send message, print "DIAL_REPLY <reply>"
//	send <host:port> <nbytes> <seed> dial, send deterministic bytes, print "SEND_DIGEST <hex sha256 echoed back>"
//	udpecho <port>                  start a UDP echo server on the tailnet
//	ping <host>                     tailnet ping; prints "PING_OK <ms>" or "PING_ERR"
//	status                          print "PEER <name> <ips> direct=<bool>" lines
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

func out(f string, a ...any) { fmt.Printf(f+"\n", a...); os.Stdout.Sync() }

func main() {
	control := flag.String("control", "", "control URL")
	authKey := flag.String("authkey", "", "auth key")
	host := flag.String("host", "go-node", "hostname")
	verbose := flag.Bool("v", false, "verbose logs to stderr")
	flag.Parse()

	dir, _ := os.MkdirTemp("", "jtail-tsnet-")
	defer os.RemoveAll(dir)
	logf := func(string, ...any) {}
	if *verbose {
		logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "TS "+f+"\n", a...) }
	}
	s := &tsnet.Server{Dir: dir, Hostname: *host, AuthKey: *authKey, ControlURL: *control, Ephemeral: true, Logf: logf, UserLogf: logf}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	st, err := s.Up(ctx)
	cancel()
	if err != nil {
		out("UP_ERR %v", err)
		os.Exit(1)
	}
	var v4, v6 string
	for _, ip := range st.TailscaleIPs {
		if ip.Is4() {
			v4 = ip.String()
		} else {
			v6 = ip.String()
		}
	}
	out("UP %s %s", v4, v6)

	lc, _ := s.LocalClient()
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "echo":
			ln, err := s.Listen("tcp", ":"+f[1])
			if err != nil {
				out("ECHO_ERR %v", err)
				continue
			}
			out("ECHO_LISTENING %s", f[1])
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						buf := make([]byte, 4096)
						for {
							n, err := c.Read(buf)
							if n > 0 {
								c.Write(append([]byte("go:"), buf[:n]...))
							}
							if err != nil {
								return
							}
						}
					}()
				}
			}()
		case "sink":
			ln, err := s.Listen("tcp", ":"+f[1])
			if err != nil {
				out("SINK_ERR %v", err)
				continue
			}
			out("SINK_LISTENING %s", f[1])
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				h := sha256.New()
				n, _ := io.Copy(h, c)
				c.Write([]byte(hex.EncodeToString(h.Sum(nil))))
				out("SINK_DONE %d", n)
			}()
		case "dial":
			go func(addr, msg string) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				c, err := s.Dial(ctx, "tcp", addr)
				if err != nil {
					out("DIAL_ERR %v", err)
					return
				}
				defer c.Close()
				c.Write([]byte(msg))
				buf := make([]byte, 4096)
				c.SetReadDeadline(time.Now().Add(20 * time.Second))
				n, err := c.Read(buf)
				if err != nil {
					out("DIAL_ERR read: %v", err)
					return
				}
				out("DIAL_REPLY %s", string(buf[:n]))
			}(f[1], strings.Join(f[2:], " "))
		case "send":
			go func(addr string, n int, seed int64) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				c, err := s.Dial(ctx, "tcp", addr)
				if err != nil {
					out("SEND_ERR %v", err)
					return
				}
				defer c.Close()
				data := make([]byte, n)
				rand.New(rand.NewSource(seed)).Read(data)
				if _, err := c.Write(data); err != nil {
					out("SEND_ERR write: %v", err)
					return
				}
				c.(interface{ CloseWrite() error }).CloseWrite()
				d, _ := io.ReadAll(c)
				out("SEND_DIGEST %s", string(d))
			}(f[1], atoi(f[2]), int64(atoi(f[3])))
		case "udpecho":
			pc, err := s.ListenPacket("udp", net.JoinHostPort(v4, f[1])) // tsnet needs an explicit tailnet IP here
			if err != nil {
				out("UDPECHO_ERR %v", err)
				continue
			}
			out("UDPECHO_LISTENING %s", f[1])
			go func() {
				buf := make([]byte, 2048)
				for {
					n, addr, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					pc.WriteTo(append([]byte("go-udp:"), buf[:n]...), addr)
				}
			}()
		case "dnsserve":
			pc, err := s.ListenPacket("udp", net.JoinHostPort(v4, f[1]))
			if err != nil {
				out("DNSSERVE_ERR %v", err)
				continue
			}
			out("DNSSERVE_LISTENING %s", f[1])
			answer := netip.MustParseAddr(v4)
			go func() {
				buf := make([]byte, 1500)
				for {
					n, addr, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					var p dnsmessage.Parser
					h, err := p.Start(buf[:n])
					if err != nil {
						continue
					}
					q, err := p.Question()
					if err != nil {
						continue
					}
					h.Response = true
					h.RecursionAvailable = true
					b := dnsmessage.NewBuilder(nil, h)
					b.EnableCompression()
					b.StartQuestions()
					b.Question(q)
					b.StartAnswers()
					if q.Type == dnsmessage.TypeA {
						a4 := answer.As4()
						b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: a4})
					}
					resp, _ := b.Finish()
					pc.WriteTo(resp, addr)
					out("DNS_QUERY %s %v", q.Name.String(), q.Type)
				}
			}()
		case "ping":
			go func(h string) {
				ip, err := netip.ParseAddr(h)
				if err != nil {
					out("PING_ERR bad addr")
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				r, err := lc.Ping(ctx, ip, tailcfg.PingDisco)
				if err != nil || r.Err != "" {
					out("PING_ERR %v %v", err, r)
					return
				}
				out("PING_OK %.1f", r.LatencySeconds*1000)
			}(f[1])
		case "status":
			stt, _ := lc.Status(context.Background())
			for _, p := range stt.Peer {
				out("PEER %s %v direct=%v online=%v", p.HostName, p.TailscaleIPs, p.CurAddr != "", p.Online)
			}
			out("STATUS_DONE")
		case "quit":
			return
		}
	}
	_ = ipn.State(0)
	_ = net.IP{}
	select {}
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
