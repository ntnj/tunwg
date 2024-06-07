package internal

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	wgDevice *device.Device
	wgNet    *netstack.Net
	wgPubKey *wgtypes.Key
	wgError  error
	initOnce sync.Once
)

func generateKey(name string) (wgtypes.Key, error) {
	path := filepath.Join(Keystorage(), "keys", name)
	if bytes, err := os.ReadFile(path); err == nil {
		return wgtypes.NewKey(bytes)
	} else if !os.IsNotExist(err) {
		return wgtypes.Key{}, err
	}
	privkey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return wgtypes.Key{}, err
	}
	if err := os.WriteFile(path, privkey[:], 0o400); err != nil {
		return wgtypes.Key{}, err
	}
	return privkey, nil
}

func initializeOnce() error {
	privkey, err := generateKey(getKeyName())
	if err != nil {
		return err
	}
	pubkey := privkey.PublicKey()
	wgPubKey = &pubkey
	wgtun, wgnet, err := netstack.CreateNetTUN([]netip.Addr{GetIPForKey(pubkey)}, nil, 1400)
	if err != nil {
		return err
	}
	wgNet = wgnet
	wgdev := device.NewDevice(wgtun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "tunwg: "))
	if err := wgdev.Up(); err != nil {
		return err
	}
	if err := wgdev.IpcSet(fmt.Sprintf(`private_key=%s`, hex.EncodeToString(privkey[:]))); err != nil {
		return err
	}
	if port := GetListenPort(); port > 0 {
		if err := wgdev.IpcSet(fmt.Sprintf(`listen_port=%d`, port)); err != nil {
			return err
		}
	}
	wgDevice = wgdev
	return nil
}

func Initialize() error {
	initOnce.Do(func() {
		wgError = initializeOnce()
	})
	return wgError
}

func ListenTCPWg(addr *net.TCPAddr) (net.Listener, error) {
	return wgNet.ListenTCP(addr)
}

func GetPublicKey() wgtypes.Key {
	return *wgPubKey
}

func WgSetIpc(ins []string) error {
	return wgDevice.IpcSet(strings.Join(ins, "\n"))
}

func DialWg(ctx context.Context, network, address string) (net.Conn, error) {
	return wgNet.DialContext(ctx, network, address)
}

func BackgroundLogger(d time.Duration) {
	for range time.Tick(d) {
		dev := Must(GetWgDeviceInfo())
		msg := ""
		slices.SortFunc(dev.Peers, func(a, b wgtypes.Peer) int { return b.LastHandshakeTime.Compare(a.LastHandshakeTime) })
		for _, peer := range dev.Peers {
			msg += fmt.Sprintf("key:%v,ep:%v,time:%v\n", peer.PublicKey, peer.Endpoint, peer.LastHandshakeTime)
		}
		log.Printf("Peers:\n%v", msg)
	}
}

func GetWgDeviceInfo() (*wgtypes.Device, error) {
	raw, err := wgDevice.IpcGet()
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	dev := &wgtypes.Device{}
	var lastPeer *wgtypes.Peer
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if lastPeer != nil {
				dev.Peers = append(dev.Peers, *lastPeer)
				lastPeer = nil
			}
			return dev, nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("failed to parse line: %v", line)
		}
		if key == "public_key" {
			if lastPeer != nil {
				dev.Peers = append(dev.Peers, *lastPeer)
				lastPeer = nil
			}
			lastPeer = &wgtypes.Peer{PublicKey: Must(wgtypes.NewKey(Must(hex.DecodeString(value))))}
		}
		if lastPeer == nil {
			switch key {
			case "listen_port":
				dev.ListenPort = int(Must(strconv.ParseInt(value, 10, 64)))
			}
		} else {
			switch key {
			case "rx_bytes":
				lastPeer.ReceiveBytes = Must(strconv.ParseInt(value, 10, 64))
			case "tx_bytes":
				lastPeer.TransmitBytes = Must(strconv.ParseInt(value, 10, 64))
			case "last_handshake_time_sec":
				lastPeer.LastHandshakeTime = time.Unix(Must(strconv.ParseInt(value, 10, 64)), int64(lastPeer.LastHandshakeTime.Nanosecond()))
			case "last_handshake_time_nsec":
				lastPeer.LastHandshakeTime = time.Unix(int64(lastPeer.LastHandshakeTime.Unix()), Must(strconv.ParseInt(value, 10, 64)))
			case "endpoint":
				host, ports, err := net.SplitHostPort(value)
				if err != nil {
					continue
				}
				port, err := strconv.Atoi(ports)
				if err != nil {
					continue
				}
				ip := net.ParseIP(host)
				lastPeer.Endpoint = &net.UDPAddr{IP: ip, Port: port}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if lastPeer != nil {
		dev.Peers = append(dev.Peers, *lastPeer)
		lastPeer = nil
	}
	return dev, nil
}
