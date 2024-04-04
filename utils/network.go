package utils

import (
	"net"
)

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func IsIpAddr(ipAddr string) bool {
	addr := net.ParseIP(ipAddr)
	return addr != nil
}

func IsIpNet(ipAddr string) bool {
	addr, _, _ := net.ParseCIDR(ipAddr)
	return addr != nil
}

func IdentifyTarget(target string) {
	isNetwork := IsIpNet(target)
	if isNetwork {
		Networks = append(Networks, target)
	}

	if !isNetwork && IsIpAddr(target) {
		Hosts = append(Hosts, target)
	} else {
		Domains = append(Domains, target)
	}
}
