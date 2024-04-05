package internal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/inetaf/tcpproxy"
	"golang.org/x/crypto/ssh"
)

type SSHState struct {
	Protocol *tcpproxy.TargetListener

	connsMu sync.Mutex
	conns   map[string]*ssh.ServerConn

	tlsConfig *tls.Config
}

type sshSession struct {
	conn *ssh.ServerConn
}

func (s *SSHState) Init() {
	s.Protocol = &tcpproxy.TargetListener{Address: "ssh"}
	s.tlsConfig = GetTLSConfig()
	s.conns = make(map[string]*ssh.ServerConn)
}

func (s *SSHState) Serve() error {
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-tunwg",
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Printf("received key: %v", ssh.FingerprintSHA256(key))
			sha256sum := sha256.Sum256(key.Marshal())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-fp":     ssh.FingerprintSHA256(key),
					"pubkey-domain": strings.ToLower(base32encoding.EncodeToString(sha256sum[:16])),
				},
			}, nil
		},
	}
	key := Must(rsa.GenerateKey(rand.Reader, 2048))
	config.AddHostKey(Must(ssh.NewSignerFromKey(key)))
	for {
		log.Printf("SSHHHHHHHH")
		c, err := s.Protocol.Accept()
		if err != nil {
			log.Printf("error accepting ssh connection: %v", err)
			continue
		}
		go func() {
			conn, chans, reqs, err := ssh.NewServerConn(c, config)
			if err != nil {
				log.Printf("error creating ssh connection: %v", err)
				return
			}
			go s.handleSSHRequests(reqs)
			go handleSSHChannels(chans)
			go s.handleSSHConnClose(conn)
			if conn.Permissions == nil || conn.Permissions.Extensions["pubkey-domain"] == "" {
				conn.Close()
				log.Printf("error in permissions")
				return
			}
			log.Printf("conn from %v %v", conn.User(), *conn.Permissions)
			s.connsMu.Lock()
			defer s.connsMu.Unlock()
			s.conns[conn.Permissions.Extensions["pubkey-domain"]] = conn
		}()
	}
}

func (s *SSHState) handleSSHConnClose(conn *ssh.ServerConn) {
	err := conn.Wait()
	log.Printf("connection closed: %v", err)
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if conn.Permissions != nil && conn.Permissions.Extensions["pubkey-domain"] != "" {
		c, ok := s.conns[conn.Permissions.Extensions["pubkey-domain"]]
		if ok && bytes.Equal(c.SessionID(), conn.SessionID()) {
			delete(s.conns, conn.Permissions.Extensions["pubkey-domain"])
		}
	}
}

func handleSSHChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		log.Printf("channel: %v %v", ch.ChannelType(), ch.ExtraData())
		switch ch.ChannelType() {
		case "session":
			c, reqs, err := ch.Accept()
			if err != nil {
				log.Printf("error in channel: %v", err)
				continue
			}
			go handleSSHSession(c, reqs)
		default:
			ch.Reject(ssh.UnknownChannelType, "bye: "+ch.ChannelType())
		}
	}
}

func handleSSHSession(c ssh.Channel, reqs <-chan *ssh.Request) {
	go func() {
		for req := range reqs {
			log.Printf("session request: %v %v", req.Type, string(req.Payload))
			switch req.Type {
			case "pty-req":
				req.Reply(true, nil)
			case "shell":
				req.Reply(true, nil)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()
	c.Write([]byte("Connected\r\n"))
	for {
		data := make([]byte, 1024)
		n, err := c.Read(data)
		if err != nil {
			log.Printf("got error on session read: %v", err)
			break
		}
		if data[0] == 'q' {
			c.Close()
			break
		}
		log.Printf("got data: %v", string(data[:n]))
	}
}

func (s *SSHState) handleSSHRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("global request: %v %v", req.Type, string(req.Payload))
		switch req.Type {
		case "tcpip-forward":
			type forwardMsg struct {
				Addr string
				Port uint32
			}
			msg := &forwardMsg{}
			if err := ssh.Unmarshal(req.Payload, msg); err != nil {
				log.Printf("error in forwarding: %v", err)
				req.Reply(false, nil)
				continue
			}
			log.Printf("received: %v", msg)
			type replyMsg struct {
				Port uint32
			}
			func() {
				s.connsMu.Lock()
				defer s.connsMu.Unlock()
			}()
			rmsg := &replyMsg{msg.Port}
			req.Reply(true, ssh.Marshal(rmsg))
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *SSHState) TargetForKey(sni string) (tcpproxy.Target, bool) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	c, ok := s.conns[sni]
	if !ok {
		return nil, false
	}
	return s.handleHTTP(c), true
}

func (s *SSHState) handleHTTP(c *ssh.ServerConn) tcpproxy.Target {
	l := &tcpproxy.TargetListener{Address: "http"}
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = r.Host
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				type payloadT struct {
					Addr  string
					Port  uint32
					RAddr string
					RPort uint32
				}
				payload := &payloadT{"localhost", 80, "localhost", 5678}
				ch, reqs, err := c.OpenChannel("forwarded-tcpip", ssh.Marshal(payload))
				if err != nil {
					return nil, err
				}
				go ssh.DiscardRequests(reqs)
				return &sshConn{ch}, nil
			},
		},
	}
	go func() {
		log.Printf("starting HTTP server")
		err := http.Serve(tls.NewListener(l, s.tlsConfig), rp)
		log.Printf("stopping HTTP server: %v", err)
	}()
	return &proxyTarget{l}
}

type sshConn struct {
	ssh.Channel
}

func (c *sshConn) LocalAddr() net.Addr {
	return nil
}

func (c *sshConn) RemoteAddr() net.Addr {
	return nil
}

func (c *sshConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *sshConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *sshConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type proxyTarget struct {
	inner *tcpproxy.TargetListener
}

func (t *proxyTarget) HandleConn(c net.Conn) {
	t.inner.HandleConn(c)
	t.inner.Close()
}
