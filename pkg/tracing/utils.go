package tracing

import (
	"encoding/binary"
	"net"
	"syscall"
)

func ParseSockaddr(raw []byte) Sockaddr {
	addr := raw[8:24] // 16 bytes
	ret := Sockaddr{
		Port: binary.BigEndian.Uint16(raw[2:4]),
		Addr: net.IP(addr),
	}
	if ret.Addr.To4() != nil {
		ret.Family = syscall.AF_INET
	} else {
		ret.Family = syscall.AF_INET6
	}
	return ret
}
