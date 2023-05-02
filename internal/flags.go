package internal

import (
	"os"
	"path/filepath"
	"strconv"
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

func SSLCertificateEmail() string {
	if email := os.Getenv("TUNWG_SSL_EMAIL"); email != "" {
		return email
	}
	return "certs@tunwg.com"
}
