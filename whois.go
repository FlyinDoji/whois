package whois

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// TCPTimeout is the time waited for contacting the Whois server
// ResponseTimeout is the time waited for the query to be served by the Whois server
const (
	Port            = ":43"
	ResponseTimeout = time.Duration(30) * time.Second
	TCPTimeout      = time.Duration(12) * time.Second
)

type tldServ struct {
	tld    string
	server string
}

type whoisDial func(ctx context.Context, network string, address string) (net.Conn, error)

var tldServers []tldServ

func extractTLD(domain string) (tldServ, bool) {

	for _, s := range tldServers {
		if len(s.tld) > len(domain) {
			continue
		}
		p := len(domain) - len(s.tld)
		if domain[p] != []byte(".")[0] {
			continue
		}
		if domain[p:] == s.tld {
			return s, true
		}
	}

	return tldServ{}, false
}

func queryServer(domain, server string, dial whoisDial) (string, string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), TCPTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", server+Port)
	if err != nil {
		return "", "", err
	}

	_ = conn.SetDeadline(time.Now().Add(ResponseTimeout))

	defer conn.Close()
	fmt.Fprintf(conn, "%s\r\n", domain)
	b, err := ioutil.ReadAll(conn)
	if err != nil {
		return "", "", err
	}

	return server, string(b), nil
}

func whois(domain string, dial whoisDial) (string, string, error) {

	if tld, ok := extractTLD(domain); ok {
		return queryServer(domain, tld.server, dial)
	}
	return "", "", fmt.Errorf("No whois server for %s", domain)
}

// Whois queries the database of the domain's tld
// Use the default net.Dial function to contact the whois server
func Whois(domain string) (string, string, error) {
	d := &net.Dialer{}
	return whois(domain, d.DialContext)
}

// Proxied queries the database of the domain's tld via SOCKS5 proxy
// Uses the proxy.Dialer.Dial function to contact the whois server
// p can be nil if no authentication is required
func Proxied(domain, proxyAddr string, p *proxy.Auth) (string, string, error) {

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, p, proxy.Direct)

	dc := dialer.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	})

	if err != nil {
		return "", "", err
	}
	return whois(domain, dc.DialContext)
}

// OwnDialer supply your own dial function
func OwnDialer(domain string, dialFun whoisDial) (string, string, error) {
	return whois(domain, dialFun)
}

// ProxyAuth authentication object for ProxiedWhois
func ProxyAuth(user, passwd string) *proxy.Auth {
	return &proxy.Auth{User: user, Password: passwd}
}

// Load tld servers
func init() {
	for i, l := range strings.Split(tldServerList, "\n") {
		if l == "" {
			continue
		}
		kv := strings.Split(l, "\t")
		if len(kv) != 2 {
			log.Fatalf("whois:tldserv.go:tldServerList incorrect format %q at line %d", kv, i+1)
			continue
		}

		tldServers = append(tldServers, tldServ{tld: kv[0], server: kv[1]})
	}
}
