package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ntnj/tunwg"
	"github.com/ntnj/tunwg/internal"
	"golang.org/x/crypto/bcrypt"
)

var forwardFlag = flag.String("forward", "", "host to forward to")
var limitFlag = flag.String("limit", "", "limitations")

func main() {
	flag.Parse()
	if *forwardFlag == "" {
		log.Fatalf("empty forwarding: %v", *forwardFlag)
	}
	if internal.TestOnlyRunLocalhost() {
		enableLocahostServerTesting()
	}
	ps := strings.Split(*forwardFlag, ",")
	var g sync.WaitGroup
	for _, p := range ps {
		l, err := tunwg.NewListener(p)
		if err != nil {
			log.Fatalf("failed to connect: %v", err)
		}
		turl := internal.Must(url.Parse(p))
		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				log.Printf("[%v] %v %v%v %v %v", time.Now(), pr.In.Method, pr.In.Host, pr.In.URL.Path, pr.In.RemoteAddr, pr.In.UserAgent())
				pr.Out.URL.Scheme = turl.Scheme
				pr.Out.URL.Host = turl.Host
				// TODO: support base path
				pr.SetXForwarded()
			},
			Transport: &roundTripper{},
		}
		srv := &http.Server{
			Handler: rp,
		}
		g.Add(1)
		go func() {
			defer g.Done()
			log.Fatalf("http server error: %v", srv.Serve(l))
		}()
	}
	g.Wait()
}

type roundTripper struct{}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(*limitFlag) > 0 {
		limit := *limitFlag
		ls := strings.SplitN(limit, ":", 2)
		euser, epass := ls[0], ls[1]
		user, pass, ok := req.BasicAuth()
		if !ok || user != euser || bcrypt.CompareHashAndPassword([]byte(epass), []byte(pass)) != nil {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header: http.Header{
					"WWW-Authenticate": {"Basic realm=access"},
				},
				Body:    io.NopCloser(strings.NewReader("")),
				Request: req,
			}, nil
		}
	}
	return http.DefaultTransport.RoundTrip(req)
}

func enableLocahostServerTesting() {
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, strings.ReplaceAll(addr, internal.ApiDomain(), "127.0.0.1"))
		},
	}
}
