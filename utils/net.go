package utils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

func GetMACAddress(ip net.IP) (net.HardwareAddr, uint16, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, 0, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.Contains(ip) {
					return iface.HardwareAddr, uint16(iface.Index), nil
				}
			}
		}
	}

	return nil, 0, fmt.Errorf("MAC address not found for IP: %s", ip.String())
}

func Ip2int(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

func Hwaddr2bytes(hwaddr string) [6]uint8 {
	parts := strings.Split(hwaddr, ":")
	if len(parts) != 6 {
		return [6]uint8{0}
	}

	var hwaddrB [6]uint8
	for i, hexPart := range parts {
		bs, err := hex.DecodeString(hexPart)
		if err != nil {
			panic(err)
		}
		if len(bs) != 1 {
			panic("invalid hwaddr part")
		}
		hwaddrB[i] = uint8(bs[0])
	}
	return hwaddrB
}

func GetIPAndMac(i *net.Interface) (uint32, [6]uint8) {
	rmac := [6]uint8{0}
	addrs, err := i.Addrs()
	fmt.Println("addrs: ", addrs)
	if err != nil {
		return 0, rmac
	}
	var ip net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		// Skip loopback and non-IPv4 addresses
		if ipNet.IP.To4() == nil {
			continue
		}
		ip = ipNet.IP
		fmt.Printf("IP Address: %s\n", ipNet.IP.String())
	}
	mac := Hwaddr2bytes(i.HardwareAddr.String())

	for i := 0; i < 6; i++ {
		rmac[i] = mac[i]
	}
	return Ip2int(ip), rmac
}
