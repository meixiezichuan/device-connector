// test
//test

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf src/xdp_redirect.c -- -I ./
package device_proxy

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/meixiezichuan/device-connector/utils"
	"log"
	"net"
	"os"
)

type Dmap map[uint16]bpfInfo

type XdpRedirector struct {
	UpIf     *net.Interface
	DownIf   *net.Interface
	Dmap     Dmap
	PodProxy bpfInfo
}

const nameRedirectProg = "/sys/fs/bpf/xdp/globals/redirect"
const nameBackMap = "/sys/fs/bpf/xdp/globals/Dmap-redirect"
const nameLocalMap = "/sys/fs/bpf/xdp/globals/local"
const nameXdpLink = "/sys/fs/bpf/xdp/globals/xdp-link"
const nameRedirectPlacerLink = "/sys/fs/bpf/xdp/globals/redirect-placer-link"

var objs bpfObjects
var l, l2 link.Link

func Info(daddr uint32, dport uint16, dhwaddr [6]uint8) bpfInfo {
	return bpfInfo{daddr, dport, dhwaddr}
}

func NewDmap() Dmap {
	return make(map[uint16]bpfInfo)
}

func NewXdpRedirector(uIf *net.Interface, dIf *net.Interface, podProxy bpfInfo) *XdpRedirector {
	xdpRedirecotr := XdpRedirector{
		UpIf:     uIf,
		DownIf:   dIf,
		Dmap:     make(map[uint16]bpfInfo),
		PodProxy: podProxy,
	}
	log.Printf("new XdpRedirector %v .", xdpRedirecotr)
	return &xdpRedirecotr
}

func (x *XdpRedirector) Init(Dmap Dmap) {
	x.Dmap = Dmap
	objs = bpfObjects{}
	var err error
	// Allow locking memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Unable to remove mem locak: %s", err)
	}

	if err = loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	l, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: x.UpIf.Index,
	})
	if err != nil {
		objs.Close()
		log.Fatalf("could not attach XDP program: %s", err)
	}

	//defer l.Close()

	l2, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.BpfRedirectPlaceholder,
		Interface: x.DownIf.Index,
	})
	if err != nil {
		objs.Close()
		l.Close()
		log.Fatalf("could not attach bpfredirect place holder program: %s", err)
	}

	//defer l2.Close()

	// Pin
	if err = objs.XdpProgFunc.Pin(nameRedirectProg); err != nil {
		objs.Close()
		l.Close()
		l2.Close()
		log.Fatalf("could not pin XDP redirect program, err %s", err)
	}
	if err = objs.Dmap.Pin(nameBackMap); err != nil {
		objs.Close()
		l.Close()
		l2.Close()
		objs.XdpProgFunc.Unpin()
		log.Fatalf("could not attach XDP map, %s", err)
	}
	if err = objs.Local.Pin(nameLocalMap); err != nil {
		objs.Close()
		l.Close()
		l2.Close()
		objs.XdpProgFunc.Unpin()
		objs.Dmap.Unpin()
		log.Fatalf("could not attach local map, %s", err)
	}
	if err = l.Pin(nameXdpLink); err != nil {
		objs.Close()
		l.Close()
		l2.Close()
		objs.XdpProgFunc.Unpin()
		objs.Dmap.Unpin()
		objs.Local.Unpin()
		log.Fatalf("could not attach xdp link, %s", err)
	}
	if err = l.Pin(nameRedirectPlacerLink); err != nil {
		objs.Close()
		l.Close()
		l2.Close()
		objs.XdpProgFunc.Unpin()
		objs.Dmap.Unpin()
		objs.Local.Unpin()
		l.Unpin()
		log.Fatalf("could not attach redirect placer link, %s", err)
	}

	uip, umac := utils.GetIPAndMac(x.UpIf)
	dip, dmac := utils.GetIPAndMac(x.DownIf)
	l := bpfLocal{
		Uaddr:    uip,
		Uhwaddr:  umac,
		Daddr:    dip,
		Dhwaddr:  dmac,
		Uifindex: uint16(x.UpIf.Index),
		Difindex: uint16(x.DownIf.Index),
	}
	if err := objs.Local.Put(uint16(0), &l); err != nil {
		fmt.Println(err.Error())
		x.Close()
		os.Exit(1)
	}

	// put podProxy
	if err := objs.PodProxy.Put(uint16(0), &x.PodProxy); err != nil {
		fmt.Println(err.Error())
		x.Close()
		os.Exit(1)
	}

	log.Printf("xdp ebpf load Dmap %v .", Dmap)
	for p, b := range Dmap {
		if err := objs.Dmap.Put(p, b); err != nil {
			fmt.Println(err.Error())
			x.Close()
			os.Exit(1)
		}
	}

	log.Printf("xdpf eBPF init succeed, Dmap %v", Dmap)
}

func (x *XdpRedirector) UpdateBackend(b bpfInfo, port uint16) {
	if err := objs.Dmap.Update(port, b, ebpf.UpdateAny); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func (x *XdpRedirector) Close() {
	objs.Close()
	l.Close()
	l2.Close()
	objs.XdpProgFunc.Unpin()
	objs.Dmap.Unpin()
	objs.Local.Unpin()
	l.Unpin()
	l2.Unpin()
}
