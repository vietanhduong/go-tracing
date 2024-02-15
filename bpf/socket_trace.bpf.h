#pragma once

#include <lib/sections.h>

#define EINPROGRESS  115

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
	__s32 pid;
	int fd;
	__u64 tsid;
};

enum srcfn_t {
	UnknownFunc = 0,
	SyscallAccept,
	SyscallConnect,
	SyscallClose,
	SyscallRecvFrom,
};

struct conn_info_t {
	struct conn_id_t id;
	// IP address of the local endpoint.
	union sockaddr_t laddr;
	// IP address of the remote endpoint.
	union sockaddr_t raddr;

	enum srcfn_t src_fn;

	bool is_http;
	__s64 wr_bytes;
	__s64 rd_bytes;
};

struct accept_args_t {
	struct sockaddr *addr;
	struct socket *sock_alloc_socket;
};

struct data_args_t {
	enum srcfn_t src_fn;

	__s32 fd;

	const struct iovec *iov;
	__u64 iovlen;

	unsigned int *msg_len;

	const char *buf;
};

struct close_args_t {
	int fd;
};

enum event_t {
	SocketOpen,
	SocketClose,
};

struct socket_event_t {
	enum event_t type;
	enum srcfn_t src_fn;
	__u64 timestamp_ns;
	struct conn_id_t conn_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 131072);
	__type(key, __u64);
	__type(value, struct conn_info_t);
} conn_map SEC_MAPS_BPF;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CFG_RINGBUF_SIZE);
} socket_events SEC_MAPS_BPF;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct close_args_t);
} stash_close_map SEC_MAPS_BPF;
