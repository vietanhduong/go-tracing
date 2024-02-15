package tracing

import (
	"fmt"
	"net"
)

type ConnId struct {
	Pid  int32
	Fd   int32
	TsId uint64
}

type Sockaddr struct {
	Family uint16
	Port   uint16
	Addr   net.IP
}

type Srcfn int32

const (
	UnknownSrc      Srcfn = 0
	SyscallAccept   Srcfn = 1
	SyscallConnect  Srcfn = 2
	SyscallClose    Srcfn = 3
	SyscallRecvFrom Srcfn = 4
)

type ConnInfo struct {
	Id    ConnId
	Laddr [28]byte
	Raddr [28]byte

	SrcFn Srcfn
	_     [4]byte // pad

	IsHttp  bool
	_       [7]byte // pad
	WrBytes int64
	RdBytes int64
}

type EventType int32

const (
	SocketOpen  EventType = 0
	SocketClose EventType = 1
)

type SocketEvent struct {
	Type        EventType
	SrcFn       Srcfn
	TimestampNs uint64
	ConnId      ConnId
}

func (s *Sockaddr) String() string {
	return fmt.Sprintf("af=0x%x addr=%s port=%d", s.Family, s.Addr, s.Port)
}

func (s *SocketEvent) String() string {
	return fmt.Sprintf("type=%s srcfn=%s ts=%d connid=%d", s.Type, s.SrcFn, s.TimestampNs, s.ConnId.TgidFd())
}

func (e EventType) String() string {
	switch e {
	case SocketOpen:
		return "OPEN"
	case SocketClose:
		return "CLOSE"
	default:
		return "UNKNOWN"
	}
}

func (s Srcfn) String() string {
	switch s {
	case SyscallAccept:
		return "ACCEPT"
	case SyscallConnect:
		return "CONNECT"
	case SyscallClose:
		return "CLOSE"
	case SyscallRecvFrom:
		return "RECVFROM"
	default:
		return "UNKNOWN"
	}
}

func (c *ConnId) TgidFd() uint64 {
	return uint64(c.Pid)<<32 | uint64(c.Fd)
}
