package internal

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	base32encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

const ipv6Subnet = "\xfd\xb0\x01\xad\x4d\x05\x81\x42"

func GetIPForKey(pub wgtypes.Key) netip.Addr {
	sum := sha256.Sum256(pub[:])
	ip, ok := netip.AddrFromSlice(append([]byte(ipv6Subnet), sum[:8]...))
	if !ok {
		return netip.Addr{}
	}
	return ip
}

func GetEncodedIPPort(addr netip.AddrPort) string {
	if !addr.Addr().Is6() {
		return ""
	}
	bs := addr.Addr().AsSlice()
	return strings.ToLower(base32encoding.EncodeToString(binary.LittleEndian.AppendUint16(bs[8:], addr.Port())))
}

func LookupEncodedIPPort(sni string) *netip.AddrPort {
	decoded, err := base32encoding.DecodeString(strings.ToUpper(sni))
	if err != nil || len(decoded) > 10 || len(decoded) == 0 {
		return nil
	}
	padded := append(make([]byte, 10-len(decoded)), decoded...)
	ip, ok := netip.AddrFromSlice(append([]byte(ipv6Subnet), padded[:8]...))
	if !ok {
		return nil
	}
	port := binary.LittleEndian.Uint16(padded[8:])
	addr := netip.AddrPortFrom(ip, port)
	return &addr
}

func GetLocalWgIp() netip.Addr {
	return GetIPForKey(GetPublicKey())
}
