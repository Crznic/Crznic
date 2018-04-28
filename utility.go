package crznic

import (
	"net"
	"os"
	"bufio"
	"strings"
	"errors"
	"encoding/hex"
	"fmt"
)

// getMacAddr gets the MAC hardware
// address of the host machine
func GetMacAddr() (addr string) {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
				// Don't use random as we have a real address
				addr = i.HardwareAddr.String()
				break
			}
		}
	}
	return
}

func GetRouterMAC() (net.HardwareAddr, error) {
	// get the default gateway address from routes
	gatewayAddr := ""
	fRoute, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer fRoute.Close()

	s := bufio.NewScanner(fRoute)
	s.Scan()

	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if fields[1] == "00000000" {
			decode, err := hex.DecodeString(fields[2])
			if err != nil {
				return nil, err
			}

			gatewayAddr = fmt.Sprintf("%v.%v.%v.%v", decode[3], decode[2], decode[1], decode[0])
		}
	}

	if gatewayAddr == "" {
		return nil, errors.New("no gateway found in routes")
	}

	// look through arp tables for match to gateway address
	fArp, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer fArp.Close()

	s = bufio.NewScanner(fArp)
	s.Scan()

	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if fields[0] == gatewayAddr {
			return net.ParseMAC(fields[3])
		}
	}

	return nil, errors.New("no gateway found")
}
