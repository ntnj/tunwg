package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ntnj/tunwg"
	"github.com/ntnj/tunwg/internal"
	"golang.org/x/crypto/bcrypt"
)

var forwardFlag = flag.String("forward", "", "hosts to forward")
var limitFlag = flag.String("limit", "", "username password in htpasswd format. bcrypt and plain text are supported")
var limitOncePerIPFlag = flag.Duration("limit_once_on_ip", 0, "Only ask for basic auth once per ip per duration")
var portFlag = flag.Uint("p", 0, "port to forward")

func main() {
	if os.Getenv("TUNWG_RUN_SERVER") == "true" {
		tunwgServer()
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "tunwgs" || os.Args[1] == "/bin/tunwgs") {
		// Reproduce the older docker environment
		os.Args = append(os.Args[:1], os.Args[2:]...)
		if os.Getenv("TUNWG_KEY") == "" {
			os.Setenv("TUNWG_KEY", "tunwgs")
		}
		tunwgServer()
		return
	} else if len(os.Args) > 1 && os.Args[1] == "tunwg" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	flag.Parse()
	if (*forwardFlag == "") == (*portFlag == 0) {
		log.Fatalf("Specify one of port to forward (-p) or urls to forward (--forward)")
	}
	if internal.TestOnlyRunLocalhost() {
		enableLocahostServerTesting()
	}
	validator := authValidator()
	var ps []string
	if port := *portFlag; port > 0 {
		ps = []string{fmt.Sprintf("http://localhost:%d", port)}
		if os.Getenv("TUNWG_KEY") == "" {
			os.Setenv("TUNWG_KEY", fmt.Sprintf("p%d", port))
		}
	} else {
		ps = strings.Split(*forwardFlag, ",")
	}
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
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("http: proxy error: %v", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("Invalid response from forwarded server"))
			},
		}
		if validator != nil {
			rp.Transport = &roundTripper{
				validator: validator,
				ipValid:   make(map[string]time.Time),
			}
		}
		srv := &http.Server{
			Handler: rp,
		}
		g.Add(1)
		go func() {
			defer g.Done()
			log.Fatalf("proxy error: %v", srv.Serve(l))
		}()
	}
	g.Wait()
}

type roundTripper struct {
	validator func(username, password string) bool
	ipValid   map[string]time.Time
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ip := req.Header.Get("X-Forwarded-For")
	if ip != "" && *limitOncePerIPFlag != 0 {
		pass, ok := r.ipValid[ip]
		if ok && time.Now().Before(pass.Add(*limitOncePerIPFlag)) {
			return http.DefaultTransport.RoundTrip(req)
		}
	}
	user, pass, ok := req.BasicAuth()
	if !ok || !r.validator(user, pass) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"WWW-Authenticate": {"Basic realm=access"},
			},
			Body:    io.NopCloser(strings.NewReader("Unauthorized")),
			Request: req,
		}, nil
	}
	if ip != "" && *limitOncePerIPFlag != 0 {
		r.ipValid[ip] = time.Now()
	}
	return http.DefaultTransport.RoundTrip(req)
}

func authValidator() func(username, password string) bool {
	limit := *limitFlag
	if len(limit) == 0 {
		return nil
	}
	ls := strings.SplitN(limit, ":", 2)
	if len(ls) != 2 {
		log.Fatalf("invalid value for --limit. Use htpasswd format")
	}
	euser, epass := ls[0], ls[1]
	if strings.HasPrefix(epass, "$2") {
		return func(username, password string) bool {
			return username == euser && bcrypt.CompareHashAndPassword([]byte(epass), []byte(password)) == nil
		}
	}
	log.Println("tunwg: using plain text password")
	return func(username, password string) bool {
		return username == euser && password == epass
	}
}

func enableLocahostServerTesting() {
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, strings.ReplaceAll(addr, internal.ApiDomain(), "127.0.0.1"))
		},
	}
}
