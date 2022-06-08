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
	SecuritySocketRecvmsg *ebpf.ProgramSpec `ebpf:"security_socket_recvmsg"`
	SecuritySocketSendmsg *ebpf.ProgramSpec `ebpf:"security_socket_sendmsg"`
	SockAllocRet          *ebpf.ProgramSpec `ebpf:"sock_alloc_ret"`
	SysAccept             *ebpf.ProgramSpec `ebpf:"sys_accept"`
	SysAcceptRet          *ebpf.ProgramSpec `ebpf:"sys_accept_ret"`
	SysClose              *ebpf.ProgramSpec `ebpf:"sys_close"`
	SysCloseRet           *ebpf.ProgramSpec `ebpf:"sys_close_ret"`
	SysConnect            *ebpf.ProgramSpec `ebpf:"sys_connect"`
	SysConnectRet         *ebpf.ProgramSpec `ebpf:"sys_connect_ret"`
	SysRead               *ebpf.ProgramSpec `ebpf:"sys_read"`
	SysReadRet            *ebpf.ProgramSpec `ebpf:"sys_read_ret"`
	SysRecvfrom           *ebpf.ProgramSpec `ebpf:"sys_recvfrom"`
	SysRecvfromRet        *ebpf.ProgramSpec `ebpf:"sys_recvfrom_ret"`
	SysSend               *ebpf.ProgramSpec `ebpf:"sys_send"`
	SysSendRet            *ebpf.ProgramSpec `ebpf:"sys_send_ret"`
	SysSendmmsg           *ebpf.ProgramSpec `ebpf:"sys_sendmmsg"`
	SysSendmmsgRet        *ebpf.ProgramSpec `ebpf:"sys_sendmmsg_ret"`
	SysSendmsg            *ebpf.ProgramSpec `ebpf:"sys_sendmsg"`
	SysSendmsgRet         *ebpf.ProgramSpec `ebpf:"sys_sendmsg_ret"`
	SysSendto             *ebpf.ProgramSpec `ebpf:"sys_sendto"`
	SysSendtoRet          *ebpf.ProgramSpec `ebpf:"sys_sendto_ret"`
	SysWrite              *ebpf.ProgramSpec `ebpf:"sys_write"`
	SysWriteRet           *ebpf.ProgramSpec `ebpf:"sys_write_ret"`
	SysWritev             *ebpf.ProgramSpec `ebpf:"sys_writev"`
	SysWritevRet          *ebpf.ProgramSpec `ebpf:"sys_writev_ret"`
	TcpConnect            *ebpf.ProgramSpec `ebpf:"tcp_connect"`
	TcpRcvEstablished     *ebpf.ProgramSpec `ebpf:"tcp_rcv_established"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	AcceptingArgs           *ebpf.MapSpec `ebpf:"accepting_args"`
	ActiveConnectionMap     *ebpf.MapSpec `ebpf:"active_connection_map"`
	ClosingArgs             *ebpf.MapSpec `ebpf:"closing_args"`
	ConectingArgs           *ebpf.MapSpec `ebpf:"conecting_args"`
	SockDataEventCreatorMap *ebpf.MapSpec `ebpf:"sock_data_event_creator_map"`
	SocketDataEventsQueue   *ebpf.MapSpec `ebpf:"socket_data_events_queue"`
	SocketOptsEventsQueue   *ebpf.MapSpec `ebpf:"socket_opts_events_queue"`
	WritingArgs             *ebpf.MapSpec `ebpf:"writing_args"`
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
	AcceptingArgs           *ebpf.Map `ebpf:"accepting_args"`
	ActiveConnectionMap     *ebpf.Map `ebpf:"active_connection_map"`
	ClosingArgs             *ebpf.Map `ebpf:"closing_args"`
	ConectingArgs           *ebpf.Map `ebpf:"conecting_args"`
	SockDataEventCreatorMap *ebpf.Map `ebpf:"sock_data_event_creator_map"`
	SocketDataEventsQueue   *ebpf.Map `ebpf:"socket_data_events_queue"`
	SocketOptsEventsQueue   *ebpf.Map `ebpf:"socket_opts_events_queue"`
	WritingArgs             *ebpf.Map `ebpf:"writing_args"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.AcceptingArgs,
		m.ActiveConnectionMap,
		m.ClosingArgs,
		m.ConectingArgs,
		m.SockDataEventCreatorMap,
		m.SocketDataEventsQueue,
		m.SocketOptsEventsQueue,
		m.WritingArgs,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	SecuritySocketRecvmsg *ebpf.Program `ebpf:"security_socket_recvmsg"`
	SecuritySocketSendmsg *ebpf.Program `ebpf:"security_socket_sendmsg"`
	SockAllocRet          *ebpf.Program `ebpf:"sock_alloc_ret"`
	SysAccept             *ebpf.Program `ebpf:"sys_accept"`
	SysAcceptRet          *ebpf.Program `ebpf:"sys_accept_ret"`
	SysClose              *ebpf.Program `ebpf:"sys_close"`
	SysCloseRet           *ebpf.Program `ebpf:"sys_close_ret"`
	SysConnect            *ebpf.Program `ebpf:"sys_connect"`
	SysConnectRet         *ebpf.Program `ebpf:"sys_connect_ret"`
	SysRead               *ebpf.Program `ebpf:"sys_read"`
	SysReadRet            *ebpf.Program `ebpf:"sys_read_ret"`
	SysRecvfrom           *ebpf.Program `ebpf:"sys_recvfrom"`
	SysRecvfromRet        *ebpf.Program `ebpf:"sys_recvfrom_ret"`
	SysSend               *ebpf.Program `ebpf:"sys_send"`
	SysSendRet            *ebpf.Program `ebpf:"sys_send_ret"`
	SysSendmmsg           *ebpf.Program `ebpf:"sys_sendmmsg"`
	SysSendmmsgRet        *ebpf.Program `ebpf:"sys_sendmmsg_ret"`
	SysSendmsg            *ebpf.Program `ebpf:"sys_sendmsg"`
	SysSendmsgRet         *ebpf.Program `ebpf:"sys_sendmsg_ret"`
	SysSendto             *ebpf.Program `ebpf:"sys_sendto"`
	SysSendtoRet          *ebpf.Program `ebpf:"sys_sendto_ret"`
	SysWrite              *ebpf.Program `ebpf:"sys_write"`
	SysWriteRet           *ebpf.Program `ebpf:"sys_write_ret"`
	SysWritev             *ebpf.Program `ebpf:"sys_writev"`
	SysWritevRet          *ebpf.Program `ebpf:"sys_writev_ret"`
	TcpConnect            *ebpf.Program `ebpf:"tcp_connect"`
	TcpRcvEstablished     *ebpf.Program `ebpf:"tcp_rcv_established"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.SecuritySocketRecvmsg,
		p.SecuritySocketSendmsg,
		p.SockAllocRet,
		p.SysAccept,
		p.SysAcceptRet,
		p.SysClose,
		p.SysCloseRet,
		p.SysConnect,
		p.SysConnectRet,
		p.SysRead,
		p.SysReadRet,
		p.SysRecvfrom,
		p.SysRecvfromRet,
		p.SysSend,
		p.SysSendRet,
		p.SysSendmmsg,
		p.SysSendmmsgRet,
		p.SysSendmsg,
		p.SysSendmsgRet,
		p.SysSendto,
		p.SysSendtoRet,
		p.SysWrite,
		p.SysWriteRet,
		p.SysWritev,
		p.SysWritevRet,
		p.TcpConnect,
		p.TcpRcvEstablished,
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
