// Dev-time oracle: Tailscale's fork of wireguard-go on a loopback UDP socket with an in-memory TUN.
// Replies to IPv4 ICMP echo requests, so JTail's pure-Java WireGuard can be verified byte-for-byte.
//
//	go-wg -peer <hex pubkey of Java side> [-endpoint 127.0.0.1:PORT]
//
// Prints "PUB <hex>" and "PORT <udp port>". Stdin command "ping <srcIP> <dstIP>" injects an echo request into the
// TUN (so Go initiates the handshake toward the Java endpoint) and prints "PONG" when the reply arrives.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func icmpEcho(src, dst netip.Addr, typ byte, payload []byte) []byte {
	p := make([]byte, 20+8+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 1
	s4, d4 := src.As4(), dst.As4()
	copy(p[12:], s4[:])
	copy(p[16:], d4[:])
	binary.BigEndian.PutUint16(p[10:], csum(p[:20]))
	p[20] = typ
	binary.BigEndian.PutUint16(p[24:], 1) // id
	binary.BigEndian.PutUint16(p[26:], 1) // seq
	copy(p[28:], payload)
	binary.BigEndian.PutUint16(p[22:], csum(p[20:]))
	return p
}

func main() {
	peerHex := flag.String("peer", "", "peer public key (hex)")
	endpoint := flag.String("endpoint", "", "peer endpoint ip:port (optional)")
	verbose := flag.Bool("v", false, "log wireguard-go internals to stderr")
	listen := flag.Int("port", 0, "UDP listen port (wireguard-go does not report ephemeral ports, so pick one)")
	flag.Parse()

	priv := key.NewNode()
	pub := priv.Public()
	ch := tuntest.NewChannelTUN()
	logf := logger.Discard
	if *verbose {
		logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "WG "+f+"\n", a...) }
	}
	dev := device.NewDevice(ch.TUN(), conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(f string, a ...any) { logf(f, a...) },
		Errorf:   func(f string, a ...any) { fmt.Fprintf(os.Stderr, "WGERR "+f+"\n", a...) },
	})
	privHex := priv.UntypedHexString()
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privHex, *listen)
	cfg += "public_key=" + *peerHex + "\nallowed_ip=0.0.0.0/0\n"
	if *endpoint != "" {
		cfg += "endpoint=" + *endpoint + "\n"
	}
	if err := dev.IpcSet(cfg); err != nil {
		panic(err)
	}
	if err := dev.Up(); err != nil {
		panic(err)
	}
	// find the bound port
	var port string
	out, _ := dev.IpcGet()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "listen_port=") {
			port = strings.TrimPrefix(l, "listen_port=")
		}
	}
	fmt.Printf("PUB %s\nPORT %s\n", pub.UntypedHexString(), port)
	os.Stdout.Sync()

	go func() { // packets decrypted by WireGuard arrive here; answer echo requests, report echo replies
		for pkt := range ch.Inbound { // device writes decrypted packets to Inbound (from the OS's viewpoint)
			if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 1 {
				continue
			}
			src, _ := netip.AddrFromSlice(pkt[12:16])
			dst, _ := netip.AddrFromSlice(pkt[16:20])
			switch pkt[20] {
			case 8:
				fmt.Printf("ECHO_REQ %s %s %d\n", src, dst, len(pkt)-28)
				os.Stdout.Sync()
				ch.Outbound <- icmpEcho(dst, src, 0, pkt[28:]) // device reads packets to encrypt from Outbound
			case 0:
				fmt.Printf("PONG %s %s %d\n", src, dst, len(pkt)-28)
				os.Stdout.Sync()
			}
		}
	}()

	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 3 && f[0] == "ping" {
			ch.Outbound <- icmpEcho(netip.MustParseAddr(f[1]), netip.MustParseAddr(f[2]), 8, []byte("go-initiated-ping"))
		}
		if len(f) == 1 && f[0] == "quit" {
			return
		}
	}
	select {}
}
