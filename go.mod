module github.com/ntnj/tunwg

go 1.22.0

toolchain go1.22.4

require (
	github.com/armon/go-proxyproto v0.1.0
	github.com/inetaf/tcpproxy v0.0.0-20240214030015-3ce58045626c
	github.com/tailscale/wireguard-go v0.0.0-20240429185444-03c5a0ccf754
	golang.org/x/crypto v0.24.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20240606171714-84a1fb8cc463 // indirect
)

replace github.com/tailscale/wireguard-go => github.com/coder/wireguard-go v0.0.0-20240522052547-769cdd7f7818
