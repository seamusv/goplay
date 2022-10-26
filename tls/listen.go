package tls

import (
	"crypto/tls"
	"net"
)

func Listen(network, laddr string, config *tls.Config) (net.Listener, error) {
	return tls.Listen(network, laddr, config)
}
