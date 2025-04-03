package check

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// proxyInfo holds the data for the CommonProxy check and implements IpInfo.
type proxyInfo struct {
	OpenPorts []int `json:"open_ports"`
}

// Summary returns a short summary of the proxy check result.
func (p proxyInfo) Summary() string {
	if len(p.OpenPorts) == 0 {
		return "no common proxy ports open"
	}
	return fmt.Sprintf("open proxy ports: %v", p.OpenPorts)
}

// Json returns the JSON encoding of the proxyInfo.
func (p proxyInfo) Json() ([]byte, error) {
	return json.Marshal(p)
}

// CommonProxy checks an IP address by scanning 20 common proxy-related ports.
// If any of these ports are open, the check marks the IP as being a potential proxy.
func CommonProxy(ipaddr net.IP) (Check, error) {
	result := Check{
		Description: "common proxy",
		Type:        InfoAndIsMalicious,
	}

	// List of 20 ports commonly used for proxy servers.
	commonProxyPorts := []int{
		80,    // HTTP
		8080,  // HTTP alternative
		3128,  // Squid proxy
		8000,  // HTTP alternative
		8008,  // HTTP alternative
		8888,  // HTTP alternative
		1080,  // SOCKS proxy
		8081,  // HTTP alternative
		3129,  // Alternative proxy port
		9000,  // Common alternative HTTP
		2000,  // Sometimes used for proxy services
		9001,  // Another alternative
		9090,  // Common management port
		7070,  // Alternative service port
		6060,  // Alternative service port
		3000,  // Development servers (sometimes used in proxy scenarios)
		5000,  // Common in development/proxy environments
		1234,  // Occasionally seen
		8082,  // HTTP alternative
		8118,  // Privoxy, commonly used for web filtering proxies
	}

	var openPorts []int
	timeout := 1 * time.Second

	// Iterate through the list and try to dial each port.
	for _, port := range commonProxyPorts {
		address := fmt.Sprintf("%s:%d", ipaddr.String(), port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			// Port is open; record this port.
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}

	// Wrap the scanning results in our proxyInfo struct.
	result.IpAddrInfo = proxyInfo{OpenPorts: openPorts}

	// Mark the IP as potentially malicious if any common proxy port is open.
	if len(openPorts) > 0 {
		result.IpAddrIsMalicious = true
	}

	return result, nil
}