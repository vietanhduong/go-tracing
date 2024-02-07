#include <vmlinux/vmlinux.h>
#include <libbpf/bpf_helpers.h>
#include <libbpf/bpf_tracing.h>
#include <libbpf/bpf_core_read.h>
#include <libbpf/bpf_endian.h>

#include <socket_trace.bpf.h>

static __inline struct conn_info_t build_conn_info(uint32_t tgid, int32_t fd)
{
	struct conn_id_t id = {};
	id.pid = tgid;
	id.fd = fd;
	id.tsid = bpf_ktime_get_ns();
	struct conn_info_t conn_info = {};
	conn_info.id = id;
	conn_info.laddr.sa.sa_family = AF_UNKNOWN;
	conn_info.raddr.sa.sa_family = AF_UNKNOWN;

	return conn_info;
}

// static __inline void
// read_sockaddr_kernel(struct conn_info_t *conn_info, const struct socket *socket)
// {
// 	struct sock *sk = NULL;
// 	bpf_probe_read_kernel(&sk, sizeof(sk), &socket->sk);
// 	struct sock_common *sk_common = &sk->__sk_common;
// 	__u16 family = -1;
// 	__u16 lport = -1;
// 	__u16 rport = -1;

// 	bpf_probe_read_kernel(&family, sizeof(family), &sk_common->skc_family);
// 	bpf_probe_read_kernel(&lport, sizeof(lport), &sk_common->skc_num);
// 	bpf_probe_read_kernel(&rport, sizeof(rport), &sk_common->skc_dport);

// 	conn_info->laddr.sa_family = family;
// 	conn_info->raddr.sa_family = family;
// 	conn_info->laddr.port = lport;
// 	conn_info->raddr.port = rport;

// 	if (family == AF_INET) {
// 		size_t size = sizeof(sk_common->skc_rcv_saddr);
// 		bpf_probe_read_kernel(
// 			&conn_info->laddr.addr, size, &sk_common->skc_rcv_saddr);
// 		bpf_probe_read_kernel(
// 			&conn_info->raddr.addr, size, &sk_common->skc_rcv_saddr);
// 	} else if (family == AF_INET6) {
// 		size_t size = sizeof(sk_common->skc_v6_rcv_saddr);
// 		bpf_probe_read_kernel(
// 			&conn_info->laddr.addr, size,
// 			&sk_common->skc_v6_rcv_saddr);
// 		bpf_probe_read_kernel(
// 			&conn_info->raddr.addr, size,
// 			&sk_common->skc_v6_rcv_saddr);
// 	}
// }

static __inline void
submit_new_conn(uint32_t tgid, int fd, struct accept_args_t *args)
{
	struct conn_info_t conn_info = build_conn_info(tgid, fd);
	if (args->sock_alloc_socket != NULL) {
		// read_sockaddr_kernel(&conn_info, args->sock_alloc_socket);
	} else if (args->addr != NULL) {
		bpf_probe_read_user(
			&conn_info.raddr, sizeof(conn_info.raddr), args->addr);
	}
	bpf_ringbuf_output(&connections, &conn_info, sizeof(conn_info), 0);
}

static __inline void on_accept(uint64_t upid, int fd, struct accept_args_t *args)
{
	uint32_t tgid = upid >> 32;
	if (fd < 0) {
		return;
	}
	submit_new_conn(tgid, fd, args);
}

struct sockaddr_storage {
	__u16 ss_family;
	char data[118];
	__u64 __padding;
};

SEC("kprobe/sys_accept4")
int BPF_KPROBE(entry_accept4, int fd, struct sockaddr *addr, int *addrlen, int flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct accept_args_t args = {};
	bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/__sys_accept4")
int ret_accept4(struct pt_regs *ctx)
{
	int ret_fd = PT_REGS_RC(ctx);
	__u64 id = bpf_get_current_pid_tgid();
	struct accept_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
	if (args != NULL) {
		on_accept(id, ret_fd, args);
	}
	bpf_map_delete_elem(&active_accept_args, &id);
	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
