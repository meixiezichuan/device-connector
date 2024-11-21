package main

import (
	"github.com/meixiezichuan/device-connector/kube"
	"github.com/meixiezichuan/device-connector/pkg/pod_proxy"
	"github.com/meixiezichuan/device-connector/utils"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	kube.Start()
	portMap := kube.GetDevicePortMap()
	var ports []uint16
	for _, value := range portMap {
		ports = append(ports, value)
	}
	subIP := os.Getenv("SUBIP")
	//subIP := "10.0.2.6"
	subMac := os.Getenv("SUBMAC")
	//subMac := "00:0d:3a:41:ce:f0"

	PodProxy(ports, subIP, subMac)
}

func PodProxy(ports []uint16, subIP string, subMac string) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	sIP := utils.Ip2int(net.ParseIP(subIP))
	sMac := utils.Hwaddr2bytes(subMac)
	sub := pod_proxy.Info(sIP, 0, sMac)

	x := pod_proxy.NewXdpRedirector(sub)
	x.Init(ports)

	<-sigs
	x.Close()
}
