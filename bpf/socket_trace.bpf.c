#include <vmlinux/vmlinux.h>
#include <libbpf/bpf_helpers.h>
#include <libbpf/bpf_tracing.h>
#include <libbpf/bpf_core_read.h>
#include <libbpf/bpf_endian.h>

#include <socket_trace.bpf.h>

static __inline __u64 gen_tgid_fd(__u32 tgid, int fd)
{
	return ((__u64)tgid << 32) | (__u32)fd;
}

static __inline bool should_trace_af(sa_family_t family)
{
	return family == AF_UNKNOWN || family == AF_INET || family == AF_INET6;
}

static __inline struct conn_info_t build_conn_info(__u32 tgid, int fd)
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
	__u16 family = -1;
	__u16 lport = -1;
	__u16 rport = -1;

	bpf_probe_read_kernel(&family, sizeof(family), &sk_common->skc_family);
	bpf_probe_read_kernel(&lport, sizeof(lport), &sk_common->skc_num);
	bpf_probe_read_kernel(&rport, sizeof(rport), &sk_common->skc_dport);

	conn_info->laddr.sa.sa_family = family;
	conn_info->raddr.sa.sa_family = family;

	if (family == AF_INET) {
		size_t size = sizeof(sk_common->skc_rcv_saddr);
		conn_info->laddr.in4.sin_port = lport;
		conn_info->raddr.in4.sin_port = rport;
		bpf_probe_read_kernel(
			&conn_info->laddr.in4.sin_addr.s_addr, size,
			&sk_common->skc_rcv_saddr);
		bpf_probe_read_kernel(
			&conn_info->raddr.in4.sin_addr.s_addr, size,
			&sk_common->skc_rcv_saddr);
	} else if (family == AF_INET6) {
		size_t size = sizeof(sk_common->skc_v6_rcv_saddr);
		conn_info->laddr.in6.sin6_port = lport;
		conn_info->raddr.in6.sin6_port = rport;
		bpf_probe_read_kernel(
			&conn_info->laddr.in6.sin6_addr, size,
			&sk_common->skc_v6_rcv_saddr);
		bpf_probe_read_kernel(
			&conn_info->laddr.in6.sin6_addr, size,
			&sk_common->skc_v6_rcv_saddr);
	}
}

static __inline void
submit_new_conn(__u32 tgid, int fd, const struct accept_args_t *args,
		const enum srcfn_t src_fn)
{
	struct conn_info_t conn_info = build_conn_info(tgid, fd);
	conn_info.src_fn = src_fn;
	if (args->sock_alloc_socket != NULL) {
		read_sockaddr_kernel(&conn_info, args->sock_alloc_socket);
	} else if (args->addr != NULL) {
		bpf_probe_read_user(
			&conn_info.raddr, sizeof(conn_info.raddr), args->addr);
	}
	__u64 tgid_fd = gen_tgid_fd(tgid, fd);
	bpf_map_update_elem(&conn_map, &tgid_fd, &conn_info, BPF_ANY);

	if (!should_trace_af(conn_info.raddr.sa.sa_family)) {
		return;
	}
	struct socket_event_t event = {};
	event.type = SocketOpen;
	event.timestamp_ns = bpf_ktime_get_ns();
	event.conn_id = conn_info.id;
	event.src_fn = src_fn;
	bpf_ringbuf_output(&socket_events, &event, sizeof(event), 0);
}

static __inline void
submit_close_conn(struct conn_info_t *conn_info, enum srcfn_t src_fn)
{
	if (conn_info == NULL) {
		return;
	}
	struct socket_event_t event = {};
	event.type = SocketClose;
	event.timestamp_ns = bpf_ktime_get_ns();
	event.conn_id = conn_info->id;
	event.src_fn = src_fn;
	bpf_ringbuf_output(&socket_events, &event, sizeof(event), 0);
}

static __inline void process_close_conn(__u32 tgid, int fd)
{
	if (fd < 0) {
		return;
	}
	__u64 tgid_fd = gen_tgid_fd(tgid, fd);
	struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_map, &tgid_fd);
	if (conn_info == NULL) {
		return;
	}
	bpf_printk("close %d %d tgid_fd: %d\n", tgid, fd, tgid_fd);
	if (should_trace_af(conn_info->raddr.sa.sa_family)) {
		submit_close_conn(conn_info, SyscallClose);
	}
	bpf_map_delete_elem(&conn_map, &tgid_fd);
}

static __inline void
process_data(const bool vecs, __u64 id, const struct data_args_t *args,
	     ssize_t bytes_count)
{
}

static __inline void
process_syscall_data(__u64 id, const struct data_args_t *args, ssize_t bytes_count)
{
	process_data(false, id, args, bytes_count);
}

static __inline void process_syscall_vecs_data(
	__u64 id, const struct data_args_t *args, ssize_t bytes_count)
{
	process_data(true, id, args, bytes_count);
}

SEC("fexit/__sys_accept4")
int BPF_PROG2(sys_accept4, int, sockfd, struct sockaddr *, addr, int *, addrlen,
	      int, flags, int, ret_fd)
{
	if (ret_fd < 0) {
		return 0;
	}

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct accept_args_t args = {};
	args.sock_alloc_socket = NULL;
	args.addr = addr;
	submit_new_conn(tgid, ret_fd, &args, SyscallAccept);
	return 0;
}

SEC("fexit/__sys_recvfrom")
int BPF_PROG2(sys_recvfrom, int, sockfd, char *, buf, size_t, size, int, flags,
	      struct sockaddr *, addr, int *, addr_len, ssize_t, ret)
{
	// bpf_printk("sys_recvfrom: count=%d, ret=%d\n", size, ret);
	return 0;
}

SEC("kprobe/close")
int BPF_KPROBE(entry_close, int fd)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct close_args_t args = {};
	args.fd = fd;
	bpf_map_update_elem(&stash_close_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/close")
int BPF_KRETPROBE(ret_close, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct close_args_t *args = bpf_map_lookup_elem(&stash_close_map, &id);
	if (args != NULL && ret == 0) {
		process_close_conn(id >> 32, args->fd);
	}
	bpf_map_delete_elem(&stash_close_map, &id);
	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
