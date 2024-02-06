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
