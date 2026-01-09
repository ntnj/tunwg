package internal

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func GetListenPort() int {
	if port := os.Getenv("TUNWG_PORT"); port != "" {
		return Must(strconv.Atoi(port))
	}
	return 0
}

func Keystorage() string {
	store := os.Getenv("TUNWG_PATH")
	if store == "" {
		store = filepath.Join(Must(os.UserConfigDir()), "tunwg")
	}
	return store
}

func getKeyName() string {
	name := os.Getenv("TUNWG_KEY")
	if name == "" {
		name = filepath.Base(Must(os.Executable()))
	}
	return name
}

func ApiDomain() string {
	if domain := os.Getenv("TUNWG_API"); domain != "" {
		return domain
	}
	return "l.tunwg.com"
}

func AuthKey() string {
	return os.Getenv("TUNWG_AUTH")
}

func ServerIp() string {
	ip := os.Getenv("TUNWG_IP")
	return ip
}

// This returns all the configured server IP addresses
func ServerIps() []string {
	ip := os.Getenv("TUNWG_IP")
	if ip == "" {
		return nil
	}

	if !strings.Contains(ip, ",") {
		return []string{ip}
	}

	var result []string
	for _, addr := range strings.Split(ip, ",") {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			result = append(result, addr)
		}
	}
	return result
}

func SSLCertificateEmail() string {
	if email := os.Getenv("TUNWG_SSL_EMAIL"); email != "" {
		return email
	}
	return "certs@tunwg.com"
}

func UseRelay() bool {
	return os.Getenv("TUNWG_RELAY") != ""
}

func TestOnlyRunLocalhost() bool {
	return os.Getenv("TUNWG_TEST_LOCALHOST") == "true"
}
