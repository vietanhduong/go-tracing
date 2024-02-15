#pragma once

#include <lib/sections.h>

#define MAX_MSG_SIZE 30720 // 30KiB
#define CHUNK_SIZE   CFG_CHUNK_SIZE
#define AF_UNKNOWN   0xff
#define AF_INET	     0x02
#define AF_INET6     0x0a

typedef __u32 socklen_t;

union sockaddr_t {
	struct sockaddr sa;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
};

struct conn_id_t {
	int32_t pid;
	int32_t fd;
	uint64_t tsid;
};

struct conn_info_t {
	struct conn_id_t id;
	// IP address of the local endpoint.
	union sockaddr_t laddr;
	// IP address of the remote endpoint.
	union sockaddr_t raddr;

	socklen_t addrlen;

	bool is_http;
	int64_t wr_bytes;
	int64_t rd_bytes;
};

struct accept_args_t {
	struct sockaddr *addr;
	struct socket *sock_alloc_socket;
};

struct conn_info_t e__;

// BPF Map Definitions
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CFG_RINGBUF_MAX_ENTRIES);
} connections SEC_MAPS_BPF;
