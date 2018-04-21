package main

import (
  "net"
  "log"
  "syscall"
  "strings"
  "encoding/hex"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)


func getLocalIP() net.IP {
  ifaces, _ := net.Interfaces()
  var ip net.IP

  for _, i := range ifaces {
	addrs, _ := i.Addrs()
	splitAddr := strings.Split(addrs[len(addrs) - 2].String(), "/")
	ip = net.ParseIP(splitAddr[0])
  }
  
  return ip
}


func sendPacket(pkt []byte, interf string) {
  fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
  if_info, _ := net.InterfaceByName(interf)

  var haddr [8]byte
  copy(haddr[0:7], if_info.HardwareAddr[0:7])
  addr := syscall.SockaddrLinklayer{
	Protocol: syscall.ETH_P_IP,
	Ifindex:  if_info.Index,
    Halen:    uint8(len(if_info.HardwareAddr)),
	Addr:     haddr,
  }

  syscall.Bind(fd, &addr)
  syscall.SetLsfPromisc(interf, true)
  syscall.Write(fd, pkt)
  syscall.SetLsfPromisc(interf, false)
}


func main() {
  srcport := layers.TCPPort(80)
  srcip := getLocalIP()

  dstaddrs, _ := net.LookupIP("10.0.0.1")
  dstip := dstaddrs[0].To4()
  dstport := layers.TCPPort(80)

  srcmac, _ := net.ParseMAC("02:00:00:00:00:00")
  dstmac, _ := net.ParseMAC("04:00:00:00:00:00") 

  ethernet := &layers.Ethernet{
	SrcMAC:	srcmac,
	DstMAC:	dstmac,
	EthernetType: 0x800,
  }
  
  ip := &layers.IPv4{
	Version:	4,
	IHL:		5,
	TOS:		0,
	Id:			0,
	Flags:		0,
	FragOffset:	0,
	TTL:		225,
	SrcIP:		srcip,
	DstIP:		dstip,
	Protocol:	layers.IPProtocolTCP,
  }

  tcp := &layers.TCP{
	SrcPort:	srcport,
	DstPort:	dstport,
	Seq:		1,
	SYN:		true,
	Window:		14600,
  }
  tcp.SetNetworkLayerForChecksum(ip)

  buf := gopacket.NewSerializeBuffer()
  opts := gopacket.SerializeOptions{
	ComputeChecksums:	true,
	FixLengths:		true,
  }
  if err := gopacket.SerializeLayers(buf, opts, ethernet, ip, tcp, gopacket.Payload("{'json':'data'}")); err != nil {
	log.Fatal(err)
  }

  log.Print(hex.Dump(buf.Bytes()))

  sendPacket(buf.Bytes(), "eth0")
}
