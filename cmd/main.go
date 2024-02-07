package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vietanhduong/wbpf"
	"github.com/vietanhduong/wbpf/compiler"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGKILL)
	defer cancel()

	// src := fmt.Sprintf("%s/bpf/socket_trace.bpf.o", root())
	// if _, err := os.Stat(src); err != nil {
	src, err := compiler.Compile(ctx,
		fmt.Sprintf("%s/bpf/socket_trace.bpf.c", root()),
		compiler.WithInclude(fmt.Sprintf("%s/bpf", root()), fmt.Sprintf("%s/bpf/include", root())),
		compiler.WithCFlags("-DCFG_RINGBUF_MAX_ENTRIES=16777216",
			"-DCFG_CHUNK_SIZE=84"),
		compiler.WithCompiler(os.Getenv("CC")),
		compiler.WithOutputDir(fmt.Sprintf("%s/bpf", root())),
	)
	if err != nil {
		log.Printf("ERR: Failed to compile: %v", err)
		os.Exit(1)
	}
	// }
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("ERR: Failed to acquire memory lock: %v", err)
		os.Exit(1)
	}
	mod, err := wbpf.NewModule(wbpf.WithElfFile(src))
	if err != nil {
		log.Printf("ERR: Failed to new module: %v", err)
		os.Exit(1)
	}
	defer mod.Close()
	if err = mod.OpenRingBuffer("connections", nil); err != nil {
		log.Printf("ERR: Failed to open ring buffer: %v", err)
		os.Exit(1)
	}

	if err = mod.AttachKprobe("__sys_accept4", "entry_accept4"); err != nil {
		log.Printf("ERR: Failed to attach entry_accept4: %v", err)
		os.Exit(1)
	}
	if err = mod.AttachKretprobe("__sys_accept4", "ret_accept4"); err != nil {
		log.Printf("ERR: Failed to attach ret_accept4: %v", err)
		os.Exit(1)
	}

	log.Printf("INFO: Tracing started")
	buf := mod.GetRingBuffer("connections")
	go func() {
		<-ctx.Done()
		buf.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			rec, err := buf.Read()
			if err != nil {
				log.Printf("ERR: Failed to read record: %v", err)
				continue
			}
			process(rec.RawSample)
		}
	}
}

func process(raw []byte) {
	conn := (*ConnInfo)(unsafe.Pointer(&raw[0]))
	log.Printf("INFO: PID: %d", conn.Id.Pid)
	sock := parseSockaddr(conn.Raddr[:])
	log.Printf("RADDR: %s", sock.String())
	// log.Printf("INFO: RAddr: AF=%d, Port=%d, Addr=%v, raw=%v",
	// 	byteorder.GetHostByteOrder().Uint16(rawAddr[0:2]),
	// 	Htons(byteorder.GetHostByteOrder().Uint16(rawAddr[2:4])),
	// 	ip(Htonl(byteorder.GetHostByteOrder().Uint32(rawAddr[20:24]))),
	// 	rawAddr,
	// )
	log.Printf("============")
}

func parseSockaddr(raw []byte) Sockaddr {
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

func root() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("No caller information")
	}
	p, err := filepath.Abs(filepath.Dir(filename) + "/..")
	if err != nil {
		panic(err)
	}
	return p
}

func ip(val uint32) net.IP {
	ret := make(net.IP, 16)

	binary.BigEndian.PutUint32(ret, val)
	return ret
}

func Ntohl(i uint32) uint32 {
	return binary.BigEndian.Uint32((*(*[4]byte)(unsafe.Pointer(&i)))[:])
}

func Htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func Ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&i)))[:])
}

func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
