SHELL=/usr/bin/env bash

REPO_ROOT=$$(git rev-parse --show-toplevel)

LIBBPF_VERSION=1.3.0
LIBBPF_PREFIX=libbpf-$(LIBBPF_VERSION)

LIBBPF_HEADERS=$(LIBBPF_PREFIX)/src/bpf_core_read.h \
	$(LIBBPF_PREFIX)/src/bpf_endian.h \
	$(LIBBPF_PREFIX)/src/bpf_helper_defs.h \
	$(LIBBPF_PREFIX)/src/bpf_helpers.h \
	$(LIBBPF_PREFIX)/src/bpf_tracing.h

.PHONY: update-libbpf-headers
update-libbpf-headers:
	mkdir -p ./include/libbpf && \
		curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v$(LIBBPF_VERSION).tar.gz" | \
		tar xz --xform='s#.*/#./include/libbpf/#' $(LIBBPF_HEADERS)
