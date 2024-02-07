// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include <libbpf/bpf_helpers.h>

#ifndef SEC_LICENSE
# define SEC_LICENSE SEC("license")
#endif

#ifndef SEC_MAPS
# define SEC_MAPS SEC("maps")
#endif

#ifndef SEC_MAPS_BPF
# define SEC_MAPS_BPF SEC(".maps")
#endif

#ifndef BPF_LICENSE
# define BPF_LICENSE(NAME) char ____license[] SEC_LICENSE = NAME
#endif

#undef bpf_printk
#define bpf_printk(fmt, ...)                          \
 ({                                                   \
static const char ____fmt[] = fmt;                         \
bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
 })
