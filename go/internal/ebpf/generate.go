//go:build ignore

package main

// This file is used by go generate to compile the BPF program.
// Run: go generate ./internal/ebpf/...

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -target amd64 bpf bpf/s3slower.c -- -I/usr/include -Ibpf
