// Dev-time oracle: Tailscale's own testcontrol server plus a local DERP relay, so JTail's control client,
// DERP client and end-to-end behaviour can be verified without touching Tailscale's SaaS.
//
//	go-control [-authkey KEY] [-magicdns DOMAIN]
//
// Prints "BASEURL <url>" and "DERP <port>" lines, then answers stdin commands: "nodes" dumps registered nodes.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	authKey := flag.String("authkey", "", "required auth key (empty = any)")
	domain := flag.String("magicdns", "jtail.test", "MagicDNS domain")
	verbose := flag.Bool("v", false, "verbose control logs")
	requireAuth := flag.Bool("requireauth", false, "force the interactive AuthURL login flow")
	extra := flag.String("extrarecord", "", "comma list of name=ip MagicDNS extra records")
	dnsRoute := flag.String("dnsroute", "", "comma list of suffix=resolverIP split-DNS routes")
	flag.Parse()

	logf := logger.Discard
	if *verbose {
		logf = log.Printf
	}

	// Local DERP relay over TLS (self-signed; InsecureForTests tells clients not to verify).
	d := derpserver.New(key.NewNode(), logf)
	dln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	dsrv := httptest.NewUnstartedServer(derpserver.AddWebSocketSupport(d, derpserver.Handler(d)))
	dsrv.Listener.Close()
	dsrv.Listener = dln
	dsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	dsrv.StartTLS()
	derpPort := dln.Addr().(*net.TCPAddr).Port

	derpMap := &tailcfg.DERPMap{
		OmitDefaultRegions: true,
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1, RegionCode: "test", RegionName: "Test", Nodes: []*tailcfg.DERPNode{{
				Name: "t1", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
				DERPPort: derpPort, STUNPort: -1, InsecureForTests: true,
			}}},
		},
	}

	cln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	base := "http://" + cln.Addr().String()
	dnsCfg := &tailcfg.DNSConfig{Proxied: true, Domains: []string{*domain}}
	for _, kv := range strings.Split(*extra, ",") {
		if p := strings.SplitN(kv, "=", 2); len(p) == 2 {
			dnsCfg.ExtraRecords = append(dnsCfg.ExtraRecords, tailcfg.DNSRecord{Name: p[0], Value: p[1]})
		}
	}
	for _, kv := range strings.Split(*dnsRoute, ",") {
		if p := strings.SplitN(kv, "=", 2); len(p) == 2 {
			if dnsCfg.Routes == nil {
				dnsCfg.Routes = map[string][]*dnstype.Resolver{}
			}
			dnsCfg.Routes[p[0]] = []*dnstype.Resolver{{Addr: p[1]}}
		}
	}
	ctrl := &testcontrol.Server{
		DNSConfig:       dnsCfg,
		RequireAuth:     *requireAuth,
		Logf:            logf,
		DERPMap:         derpMap,
		RequireAuthKey:  *authKey,
		MagicDNSDomain:  *domain,
		ExplicitBaseURL: base,
		AllNodesSameUser: true,
	}
	go http.Serve(cln, ctrl)

	fmt.Printf("BASEURL %s\nDERP %d\n", base, derpPort)
	os.Stdout.Sync()
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "quit":
			return
		case "completeauth":
			if len(f) == 2 {
				fmt.Printf("COMPLETEAUTH %v\n", ctrl.CompleteAuth(f[1]))
				os.Stdout.Sync()
			}
		}
	}
	select {} // stdin closed: keep serving until killed
}
