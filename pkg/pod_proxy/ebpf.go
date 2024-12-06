// test
//test

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf src/xdp_redirect.c -- -I ./
package pod_proxy

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
)

type Dpmap map[uint16]uint8

type XdpRedirector struct {
	Ports   []uint16
	SubInfo bpfInfo
}

const nameRedirectProg = "/sys/fs/bpf/xdp/globals/redirect"
const nameDPMap = "/sys/fs/bpf/xdp/globals/Dmap-redirect"
const nameXdpLink = "/sys/fs/bpf/xdp/globals/xdp-link"

var objs bpfObjects
var l, l2 link.Link

func Info(daddr uint32, dport uint16, dhwaddr [6]uint8) bpfInfo {
	return bpfInfo{daddr, dport, dhwaddr}
}

func NewXdpRedirector(subInfo bpfInfo) *XdpRedirector {
	xdpRedirecotr := XdpRedirector{
		SubInfo: subInfo,
	}
	log.Printf("new XdpRedirector subInfo: %v .", subInfo)
	return &xdpRedirecotr
}

func (x *XdpRedirector) Init(ports []uint16, ifName string) {
	x.Ports = ports
	objs = bpfObjects{}
	var err error
	// Allow locking memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Unable to remove mem locak: %s", err)
	}

	if err = loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifName, err)
	}

	l, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		log.Fatalf("could not attach XDP program: %s", err)
	}

	// Pin
	if err = objs.XdpProgFunc.Pin(nameRedirectProg); err != nil {
		objs.Close()
		l.Close()
		log.Fatalf("could not pin XDP redirect program, err %s", err)
	}

	if err = l.Pin(nameXdpLink); err != nil {
		objs.Close()
		l.Close()
		objs.XdpProgFunc.Unpin()
		log.Fatalf("could not attach xdp link, %s", err)
	}

	if err = objs.Dpmap.Pin(nameDPMap); err != nil {
		objs.Close()
		l.Close()
		objs.XdpProgFunc.Unpin()
		l.Unpin()
		log.Fatalf("could not attach XDP map, %s", err)
	}
	x.UpdatePorts(objs.Dpmap)

	if err := objs.Sub.Put(uint16(0), &(x.SubInfo)); err != nil {
		fmt.Println(err.Error())
		x.Close()
		os.Exit(1)
	}
}

func (x *XdpRedirector) UpdatePorts(hashMap *ebpf.Map) {
	fmt.Println("updatePorts: ", x.Ports)
	for _, v := range x.Ports {
		if err := hashMap.Put(v, uint8(0)); err != nil {
			panic(err)
		}
	}
}

func (x *XdpRedirector) Close() {
	objs.Close()
	l.Close()
	objs.XdpProgFunc.Unpin()
	objs.Dpmap.Unpin()
	l.Unpin()
}
