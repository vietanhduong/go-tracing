package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

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
