// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *bpfObjects
//     *bpfPrograms
//     *bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	BpfTcpV4Connect    *ebpf.ProgramSpec `ebpf:"bpf_tcp_v4_connect"`
	BpfTcpV4ConnectRet *ebpf.ProgramSpec `ebpf:"bpf_tcp_v4_connect_ret"`
	BpfTcpV6Connect    *ebpf.ProgramSpec `ebpf:"bpf_tcp_v6_connect"`
	BpfTcpV6ConnectRet *ebpf.ProgramSpec `ebpf:"bpf_tcp_v6_connect_ret"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	ConnectSockets *ebpf.MapSpec `ebpf:"connect_sockets"`
	Counts         *ebpf.MapSpec `ebpf:"counts"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	ConnectSockets *ebpf.Map `ebpf:"connect_sockets"`
	Counts         *ebpf.Map `ebpf:"counts"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.ConnectSockets,
		m.Counts,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	BpfTcpV4Connect    *ebpf.Program `ebpf:"bpf_tcp_v4_connect"`
	BpfTcpV4ConnectRet *ebpf.Program `ebpf:"bpf_tcp_v4_connect_ret"`
	BpfTcpV6Connect    *ebpf.Program `ebpf:"bpf_tcp_v6_connect"`
	BpfTcpV6ConnectRet *ebpf.Program `ebpf:"bpf_tcp_v6_connect_ret"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.BpfTcpV4Connect,
		p.BpfTcpV4ConnectRet,
		p.BpfTcpV6Connect,
		p.BpfTcpV6ConnectRet,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfel.o
var _BpfBytes []byte
