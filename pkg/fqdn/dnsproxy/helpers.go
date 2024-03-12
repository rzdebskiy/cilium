// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/dns"
)

// lookupTargetDNSServer finds the intended DNS target server for a specific
// request (passed in via ServeDNS). The IP:port:protocol combination is
// returned.
func lookupTargetDNSServer(w dns.ResponseWriter) (serverIP net.IP, serverPort uint16, serverProtocol uint8, addrStr string, err error) {
	switch addr := (w.LocalAddr()).(type) {
	case *net.UDPAddr:
		return addr.IP, uint16(addr.Port), uint8(u8proto.UDP), addr.String(), nil
	case *net.TCPAddr:
		return addr.IP, uint16(addr.Port), uint8(u8proto.TCP), addr.String(), nil
	default:
		return nil, 0, 0, addr.String(), fmt.Errorf("Cannot extract address information for type %T: %+v", addr, addr)
	}
}
