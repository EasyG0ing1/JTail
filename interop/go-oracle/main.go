// Dev-time interop oracle: runs Tailscale's real Go controlbase server so JTail's Java
// implementation can be verified byte-for-byte. NOT part of the JTail runtime.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"

	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	priv := key.NewMachine()
	pub := priv.Public()
	fmt.Printf("ADDR %s\nPUB %s\n", ln.Addr(), hex.EncodeToString(pub.UntypedBytes()))
	os.Stdout.Sync()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			conn, err := controlbase.Server(context.Background(), c, priv, nil)
			if err != nil {
				fmt.Printf("SERVER_ERR %v\n", err)
				return
			}
			fmt.Printf("HANDSHAKE_OK version=%d peer=%s\n", conn.ProtocolVersion(), hex.EncodeToString(conn.Peer().UntypedBytes()))
			os.Stdout.Sync()
			io.Copy(conn, conn) // echo
		}()
	}
}
