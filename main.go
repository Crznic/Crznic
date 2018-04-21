package main

import (
  "net"
  "log"
  "syscall"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)


type Host struct{
  Ip		net.IP
  Mac		net.HardwareAddr
  Port		layers.TCPPort
}


type Crznic struct {
  Inter		string
  Src		*Host
  Dst		*Host
  Seq		uint32
}


func newHost(ip net.IP, mac net.HardwareAddr, port layers.TCPPort) *Host {
  anewHost := &Host{
	Ip:		ip,
	Mac:	mac,
	Port:	port,
  }

  return anewHost
}


func newCrznic(inter string, src, dst *Host, seq uint32) *Crznic {
  anewCrznic := &Crznic{
	Inter:	inter,
	Src:		src,
	Dst:		dst,
	Seq:		seq,
  }
  return anewCrznic
}


func (c *Crznic) sendPacket(pkt []byte) {
  fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
  if_info, _ := net.InterfaceByName(c.Inter)

  var haddr [8]byte
  copy(haddr[0:7], if_info.HardwareAddr[0:7])
  addr := syscall.SockaddrLinklayer{
	Protocol: syscall.ETH_P_IP,
	Ifindex:  if_info.Index,
    Halen:    uint8(len(if_info.HardwareAddr)),
	Addr:     haddr,
  }

  syscall.Bind(fd, &addr)
  syscall.SetLsfPromisc(c.Inter, true)
  syscall.Write(fd, pkt)
  syscall.SetLsfPromisc(c.Inter, false)
}


func (c *Crznic) sendSYNPacket(payload string) {
  ethernet := &layers.Ethernet{
	SrcMAC:	c.Src.Mac,
	DstMAC:	c.Dst.Mac,
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
	SrcIP:		c.Src.Ip,
	DstIP:		c.Dst.Ip,
	Protocol:	layers.IPProtocolTCP,
  }

  tcp := &layers.TCP{
	SrcPort:	c.Src.Port,
	DstPort:	c.Src.Port,
	Seq:		c.Seq,
	SYN:		true,
	Window:		14600,
  }
  tcp.SetNetworkLayerForChecksum(ip)

  buf := gopacket.NewSerializeBuffer()
  opts := gopacket.SerializeOptions{
	ComputeChecksums:	true,
	FixLengths:			true,
  }
  if err := gopacket.SerializeLayers(buf, opts, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
	log.Fatal(err)
  }

  c.sendPacket(buf.Bytes())
}


func getRouterMAC() (net.HardwareAddr) {
  rifs := RoutedInterface("ip", net.FlagUp | net.FlagBroadcast)
  var dstMac net.HardwareAddr
  if rifs != nil {
	dstMac = rifs.HardwareAddr
  } else {
	log.Fatal("No router address found")
  }

  return dstMac
}


func main() {
  macAddr, _ := net.ParseMAC("0c:02:00:00:00:00")
  dstMac := getRouterMAC()
  srcHost := newHost(net.ParseIP("10.0.0.1"), macAddr, layers.TCPPort(80))
  dstHost := newHost(net.ParseIP("10.0.0.2"), dstMac, layers.TCPPort(80))

  crz := newCrznic("eth0", srcHost, dstHost, 1)
  crz.sendSYNPacket("MESSAGE")
}
