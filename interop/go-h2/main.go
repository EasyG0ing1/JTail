// Dev-time oracle: a cleartext HTTP/2 (h2c) server used to verify JTail's pure-Java HTTP/2 client.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen-Method", r.Method)
		w.Header().Set("X-Seen-Header", r.Header.Get("X-Custom"))
		w.Write(b)
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "chunk%d\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 300000)
		for i := range buf {
			buf[i] = byte(i * 7)
		}
		w.Write(buf)
	})
	mux.HandleFunc("/teapot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Long", string(make([]byte, 0)) + "value-that-is-long-enough-to-matter-0123456789")
		http.Error(w, "short and stout", 418)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Printf("ADDR %s\n", ln.Addr())
	os.Stdout.Sync()
	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	srv.Serve(ln)
}
