package main

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

type ConnInfo struct {
	Id    ConnId
	Laddr [28]byte
	Raddr [28]byte

	IsHttp  bool
	_       [7]byte // pad
	WrBytes int64
	RdBytes int64
}

func (s *Sockaddr) String() string {
	return fmt.Sprintf("af=0x%x addr=%s port=%d", s.Family, s.Addr, s.Port)
}
