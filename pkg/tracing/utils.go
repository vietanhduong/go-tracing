package tracing

import (
	"syscall"
	"unsafe"
)

func ParseSockaddr(raw []byte) Sockaddr {
	rsa := (*syscall.RawSockaddrAny)(unsafe.Pointer(&raw[0]))
	return anyToSockaddr(rsa)
}

func anyToSockaddr(rsa *syscall.RawSockaddrAny) Sockaddr {
	switch rsa.Addr.Family {
	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.Addr = pp.Addr
		return Sockaddr{
			Family: syscall.AF_INET,
			Port:   uint16(sa.Port),
			Addr:   sa.Addr[:],
		}

	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		sa.Addr = pp.Addr
		return Sockaddr{
			Family: syscall.AF_INET6,
			Port:   uint16(sa.Port),
			Addr:   sa.Addr[:],
		}
	}
	return Sockaddr{}
}
