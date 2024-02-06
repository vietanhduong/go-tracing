#include "include/vmlinux/vmlinux-x86.h"
#include <vmlinux/vmlinux.h>
#include <libbpf/bpf_helpers.h>
#include <libbpf/bpf_tracing.h>
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

static __inline void
read_sockaddr_kernel(struct conn_info_t *conn_info, const struct socket *socket)
{
	struct sock *sk = NULL;
	bpf_probe_read_kernel(&sk, sizeof(sk), &socket->sk);
	struct sock_common *sk_common = &sk->__sk_common;
	uint16_t family = -1;
	uint16_t lport = -1;
	uint16_t rport = -1;

	bpf_probe_read_kernel(&family, sizeof(family), &sk_common->skc_family);
	bpf_probe_read_kernel(&lport, sizeof(lport), &sk_common->skc_num);
	bpf_probe_read_kernel(&rport, sizeof(rport), &sk_common->skc_dport);

	conn_info->laddr.sa.sa_family = family;
	conn_info->raddr.sa.sa_family = family;

	if (family == AF_INET) {
		conn_info->laddr.in4.sin_port = lport;
		conn_info->raddr.in4.sin_port = rport;
		bpf_probe_read_kernel(
			&conn_info->laddr.in4.sin_addr.s_addr,
			sizeof(conn_info->laddr.in4.sin_addr.s_addr),
			&sk_common->skc_rcv_saddr);
		bpf_probe_read_kernel(
			&conn_info->raddr.in4.sin_addr.s_addr,
			sizeof(conn_info->raddr.in4.sin_addr.s_addr),
			&sk_common->skc_daddr);
	} else if (family == AF_INET6) {
		conn_info->laddr.in6.sin6_port = lport;
		conn_info->raddr.in6.sin6_port = rport;
		bpf_probe_read_kernel(
			&conn_info->laddr.in6.sin6_addr,
			sizeof(conn_info->laddr.in6.sin6_addr),
			&sk_common->skc_v6_rcv_saddr);
		bpf_probe_read_kernel(
			&conn_info->raddr.in6.sin6_addr,
			sizeof(conn_info->raddr.in6.sin6_addr),
			&sk_common->skc_v6_daddr.in6_u);
	}
}

static __inline void
submit_new_conn(uint32_t tgid, int32_t fd, const struct sockaddr *addr,
		const struct socket *socket)
{
	struct conn_info_t conn_info = build_conn_info(tgid, fd);
	if (socket != NULL) {
		read_sockaddr_kernel(&conn_info, socket);
	} else if (addr != NULL) {
		conn_info.raddr.sa = *addr;
	}
	bpf_ringbuf_output(&connections, &conn_info, sizeof(conn_info), 0);
}

static __inline void on_accept(uint64_t upid, struct accept_args_t *args)
{
	uint32_t tgid = upid >> 32;
	submit_new_conn(tgid, args->fd, args->addr, args->sock_alloc_socket);
}

SEC("fexit/__sys_accept4")
int BPF_PROG(sys_accept4, int sockfd, struct sockaddr *addr, int *addrlen,
	     int flags, int ret_fd)
{
	if (ret_fd < 0) {
		return 0;
	}

	uint64_t upid = bpf_get_current_pid_tgid();
	struct accept_args_t args = {};
	args.addr = addr;
	args.fd = ret_fd;
	on_accept(upid, &args);
	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
