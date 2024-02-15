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
		compiler.WithCFlags("-DCFG_RINGBUF_SIZE=16777216",
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
	if err = mod.AttachFExit("sys_accept4"); err != nil {
		log.Printf("ERR: Failed to attach sys_accept4: %v", err)
		os.Exit(1)
	}

	if err = mod.AttachFExit("sys_recvfrom"); err != nil {
		log.Printf("ERR: Failed to attach sys_recvfrom: %v", err)
		os.Exit(1)
	}

	closeSyscall := wbpf.FixSyscallName("sys_close")
	if err = mod.AttachKprobe(closeSyscall, "entry_close"); err != nil {
		log.Printf("ERR: Failed to attach kprobe (syscall=%s): %v", closeSyscall, err)
		os.Exit(1)
	}

	if err = mod.AttachKretprobe(closeSyscall, "ret_close"); err != nil {
		log.Printf("ERR: Failed to attach kretprobe (syscall=%s): %v", closeSyscall, err)
		os.Exit(1)
	}

	log.Printf("INFO: Tracing started")
	<-ctx.Done()
}

func process(raw []byte) {
	conn := (*ConnInfo)(unsafe.Pointer(&raw[0]))
	log.Printf("INFO: PID: %d, EVENT: %s", conn.Id.Pid, conn.Event)
	sock := parseSockaddr(conn.Raddr[:])
	log.Printf("RADDR: %s", sock.String())
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
