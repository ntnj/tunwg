package internal

import (
	"net"
)

func RelayServer(tcpConn net.Conn, udpConn *net.UDPConn, addr net.Addr) error {
	done := make(chan error, 1)
	// tcp to udp
	go func() {
		tub := make([]byte, 4096)
		for {
			defer udpConn.Close()
			n, err := tcpConn.Read(tub)
			if err != nil {
				done <- err
				return
			}
			if _, err := udpConn.WriteTo(tub[:n], addr); err != nil {
				done <- err
				return
			}
		}
	}()
	// udp to tcp
	utb := make([]byte, 4096)
	for {
		n, err := udpConn.Read(utb)
		if err != nil {
			break
		}
		if _, err := tcpConn.Write(utb[:n]); err != nil {
			break
		}
	}
	tcpConn.Close()
	return <-done
}
