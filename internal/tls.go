package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var zsMu sync.Mutex

func GetTLSConfig() *tls.Config {
	le := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  SSLCertificateEmail(),
		Cache:  autocert.DirCache(filepath.Join(Keystorage(), "certs")),
	}
	var zs *autocert.Manager
	return &tls.Config{
		NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if TestOnlyRunLocalhost() {
				return localhostCertificate()
			}
			if cert, err := le.GetCertificate(hello); err == nil {
				return cert, nil
			} else {
				log.Printf("error getting cert from lets encrypt: %v", err)
			}
			zsMu.Lock()
			defer zsMu.Unlock()
			eab, err := getZeroSSLEab()
			if err != nil {
				return nil, err
			}
			if zs == nil {
				zs = &autocert.Manager{
					Client: &acme.Client{
						DirectoryURL: "https://acme.zerossl.com/v2/DV90",
					},
					Prompt:                 autocert.AcceptTOS,
					Email:                  SSLCertificateEmail(),
					Cache:                  autocert.DirCache(filepath.Join(Keystorage(), "certs")),
					ExternalAccountBinding: eab,
				}
			}
			hl, err := ListenTCPWg(&net.TCPAddr{Port: 80})
			if err != nil {
				return nil, err
			}
			defer hl.Close()
			hs := &http.Server{Handler: zs.HTTPHandler(nil)}
			defer hs.Close()
			go hs.Serve(hl)
			return zs.GetCertificate(hello)
		},
	}
}

func getZeroSSLEab() (*acme.ExternalAccountBinding, error) {
	path := filepath.Join(Keystorage(), "certs/zerossl+eab")
	bytes, err := os.ReadFile(path)
	if err == nil {
		res := &acme.ExternalAccountBinding{}
		err := json.Unmarshal(bytes, res)
		return res, err
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	log.Println("tunwg: fetching eab from zerossl")
	zerosslApi := "https://api.zerossl.com/acme/eab-credentials-email"
	form := url.Values{"email": {SSLCertificateEmail()}}
	resp, err := http.Post(zerosslApi, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to generate zerossl EAB: %v %v", resp.StatusCode, string(respBytes))
	}
	var result struct {
		Success    bool   `json:"success"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("failed zerossl eab: %v", string(respBytes))
	}
	log.Printf("tunwg: fetched zerossl credentials: %v", result.EABKID)
	res := &acme.ExternalAccountBinding{
		KID: result.EABKID,
	}
	key, err := base64.RawURLEncoding.DecodeString(result.EABHMACKey)
	if err != nil {
		return nil, err
	}
	res.Key = key
	if fileBytes, err := json.Marshal(res); err == nil {
		err := os.WriteFile(path, fileBytes, 0o600)
		if err != nil {
			log.Printf("Failed to persist eab: %v", err)
		}
	}
	return res, nil
}

func localhostCertificate() (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		Subject:      pkix.Name{CommonName: "localhost"},
		Issuer:       pkix.Name{CommonName: "localhost"},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	return &certificate, err
}
