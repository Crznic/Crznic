package crznic

import (
	"net"
	"os"
	"bufio"
	"strings"
	"errors"
)

func GetRouterMAC() (net.HardwareAddr, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Scan()

	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if fields[0] == "gateway" {
			return net.ParseMAC(fields[1])
		}
	}

	return nil, errors.New("no gateway found")
}
