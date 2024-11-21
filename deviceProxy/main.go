package main

import (
	"fmt"
	"github.com/meixiezichuan/device-connector/kube"
	"github.com/meixiezichuan/device-connector/pkg/device_proxy"
	"github.com/meixiezichuan/device-connector/utils"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	kube.Start()
	portNode := kube.GetDeviceNodeMap()

	Redirect(portNode)
}

func Redirect(portNode map[uint16]kube.Node) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)
	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
	}()

	uifaceName := os.Getenv("UPIFACE")
	uiface, err := net.InterfaceByName(uifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", uifaceName, err)
	}

	difaceName := os.Getenv("DOWNIFACE")
	diface, err := net.InterfaceByName(difaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", difaceName, err)
	}

	podProxyMAC := os.Getenv("PODPROXY_MAC")
	podProxyIP := os.Getenv("PODPROXY_IP")
	podProxy := device_proxy.Info(utils.Ip2int(net.ParseIP(podProxyIP)), 0, utils.Hwaddr2bytes(podProxyMAC))
	xdpr := device_proxy.NewXdpRedirector(uiface, diface, podProxy)
	backends := device_proxy.NewDmap()
	for p, n := range portNode {
		nparts := strings.Split(n.IP, ":")
		nhost := nparts[0]
		nport_str := nparts[1]
		nport, err := strconv.ParseUint(nport_str, 0, 16)
		if err != nil {
			nport = 0
		}
		nip := net.ParseIP(nhost)
		nmac := n.MAC
		b := device_proxy.Info(utils.Ip2int(nip), uint16(nport), utils.Hwaddr2bytes(nmac))
		backends[p] = b
	}
	xdpr.Init(backends)
	fmt.Println("awaiting signal")
	<-done
	fmt.Println("exiting")
	xdpr.Close()
}

