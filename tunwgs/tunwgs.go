package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ntnj/tunwg/internal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"inet.af/tcpproxy"
)

func main() {
	if err := internal.Initialize(); err != nil {
		log.Fatalf("failed to initialize: %v", err)
	}
	l, err := internal.ListenTCPWg(&net.TCPAddr{Port: 443})
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	go func() {
		if err := http.Serve(tls.NewListener(l, internal.GetTLSConfig()), apiMux()); err != nil {
			log.Fatalf("failed to serve api: %v", err)
		}
	}()
	go func() {
		if err := http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
				http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
				return
			}
			rp := &httputil.ReverseProxy{
				Rewrite: func(pr *httputil.ProxyRequest) {
					ipport, err := getIPForDomain(pr.In.Host)
					if err != nil {
						log.Printf("unable to find host: %v", pr.In.Host)
						w.WriteHeader(http.StatusNotFound)
						return
					}
					newPort := netip.AddrPortFrom(ipport.Addr(), 80)
					pr.Out.URL.Scheme = "http"
					pr.Out.URL.Host = fmt.Sprintf("%v", newPort.String())
				},
				Transport: &http.Transport{
					DialContext: internal.DialWg,
				},
			}
			rp.ServeHTTP(w, r)
		})); err != nil {
			log.Fatalf("failed to serve redirect handler: %v", err)
		}
	}()
	go globalPersist.loadFromDisk()
	go globalPersist.backgroundWriter(time.Minute)
	go internal.BackgroundLogger(10 * time.Second)
	log.Fatalf("failed to run: %v", runSniProxy())
}

func allowUserKey(key wgtypes.Key, endpoint string) error {
	ipc := []string{
		"public_key=" + hex.EncodeToString(key[:]),
		fmt.Sprintf("allowed_ip=%s/128", internal.GetIPForKey(key)),
	}
	if endpoint != "" {
		ipc = append(ipc, "endpoint="+endpoint)
	}
	return internal.WgSetIpc(ipc)
}

func apiMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		if authKey, reqKey := internal.AuthKey(), r.Header.Get("X-Authorization"); authKey != "" && authKey != reqKey {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		reqBytes, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req := internal.AddPeerReq{}
		if err := json.Unmarshal(reqBytes, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		clientKey, err := wgtypes.NewKey(req.Key)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := allowUserKey(clientKey, ""); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		globalPersist.markDirty()
		key := internal.GetPublicKey()
		resp := internal.AddPeerResp{
			Key:      key[:],
			Endpoint: fmt.Sprintf("%v:%v", internal.ServerIp(), internal.GetListenPort()),
		}
		respBytes, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	})
	return mux
}

func runSniProxy() error {
	var proxy tcpproxy.Proxy
	proxy.AddSNIRoute(":443", internal.ApiDomain(), &tcpproxy.DialProxy{
		Addr:        fmt.Sprintf("[%v]:443", internal.GetLocalWgIp()),
		DialContext: internal.DialWg,
		DialTimeout: time.Second,
	})
	proxy.AddSNIRouteFunc(":443", func(ctx context.Context, sniName string) (tcpproxy.Target, bool) {
		log.Printf("received request for: %v", sniName)
		addr, err := getIPForDomain(sniName)
		if err != nil {
			log.Printf("dispatch error: %v", err)
			return nil, false
		}
		return &tcpproxy.DialProxy{
			Addr:                 addr.String(),
			DialContext:          internal.DialWg,
			DialTimeout:          5 * time.Second,
			ProxyProtocolVersion: 1,
		}, true
	})
	return proxy.Run()
}

func getIPForDomain(sniName string) (*netip.AddrPort, error) {
	encodedIP, matched := strings.CutSuffix(sniName, "."+internal.ApiDomain())
	if !matched {
		cname, err := net.LookupCNAME(sniName)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup cname %v: %v", sniName, err)
		}
		log.Printf("got cname: %v", cname)
		// CNAME can contain a dot the end
		cname, _ = strings.CutSuffix(cname, ".")
		encodedIP, matched = strings.CutSuffix(cname, "."+internal.ApiDomain())
		if !matched {
			return nil, fmt.Errorf("no proper suffix: %v", sniName)
		}
	}
	splits := strings.Split(encodedIP, ".")
	encodedIP = splits[len(splits)-1]
	addr := internal.LookupEncodedIPPort(encodedIP)
	if addr == nil {
		return nil, fmt.Errorf("error in dispatching: %v", sniName)
	}
	return addr, nil
}

// Persist last seen endpoint to disk
// This enables almost instant reconnect after server restart.
var globalPersist = &persistPeers{}

type persistPeers struct {
	dirty atomic.Bool
	peers map[string]struct {
		Endpoint string
	}
}

func (p *persistPeers) markDirty() {
	p.dirty.Store(true)
}

func (p *persistPeers) backgroundWriter(d time.Duration) {
	var lastWritten time.Time
	for range time.Tick(d) {
		if !p.dirty.Swap(false) && time.Since(lastWritten) < 15*time.Minute {
			continue
		}
		log.Println("writing peers to disk")
		if err := p.writeToDisk(); err != nil {
			log.Printf("error writing peers: %v", err)
		}
		lastWritten = time.Now()
	}
}

func (p *persistPeers) writeToDisk() error {
	dev, err := internal.GetConnectedPeers()
	if err != nil {
		return err
	}
	p.peers = make(map[string]struct{ Endpoint string })
	for _, peer := range dev.Peers {
		if time.Since(peer.LastHandshakeTime) < 15*time.Minute {
			// Only write peers who were connected in the last 15 minutes.
			p.peers[string(peer.PublicKey.String())] = struct{ Endpoint string }{
				Endpoint: peer.Endpoint.String(),
			}
		}
	}
	log.Printf("peers to write: %+v", p.peers)
	data, err := json.Marshal(p.peers)
	if err != nil {
		return err
	}
	_ = os.Mkdir(filepath.Join(internal.Keystorage(), "server"), 0o700)
	return os.WriteFile(filepath.Join(internal.Keystorage(), "server/peers.json"), data, 0o600)
}

func (p *persistPeers) loadFromDisk() {
	p.peers = make(map[string]struct{ Endpoint string })
	data, err := os.ReadFile(filepath.Join(internal.Keystorage(), "server/peers.json"))
	if err != nil {
		log.Printf("error reading file: %v", err)
		return
	}
	if err := json.Unmarshal(data, &p.peers); err != nil {
		log.Printf("error unmarshaling: %v", err)
		return
	}
	for k, v := range p.peers {
		key, err := wgtypes.ParseKey(k)
		if err != nil {
			log.Printf("error parsing key: %v", err)
			continue
		}
		// TODO: these writes could be combined to one IPC operation
		if err := allowUserKey(key, v.Endpoint); err != nil {
			log.Printf("error allowing user: %v", err)
		}
	}
}
