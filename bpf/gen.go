package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type conn_info_t -type sockaddr_t -type sockaddr -type sockaddr_in -type sockaddr_in6 test socket_trace.bpf.c  -- -DCFG_RINGBUF_MAX_ENTRIES=16777216 -DCFG_CHUNK_SIZE=84 -I. -I./include -D__TARGET_ARCH_x86
