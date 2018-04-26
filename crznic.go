package crznic

import (
  "net"
  "log"
  "syscall"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
	"crypto/x509"
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


func NewHost(ip net.IP, mac net.HardwareAddr, port layers.TCPPort) *Host {
  anewHost := &Host{
		Ip:		ip,
		Mac:	mac,
		Port:	port,
  }

  return anewHost
}


func NewCrznic(inter string, src, dst *Host, seq uint32) *Crznic {
  anewCrznic := &Crznic{
		Inter:	inter,
		Src:		src,
		Dst:		dst,
		Seq:		seq,
  }
  return anewCrznic
}


func (c *Crznic) SendPacket(pkt []byte) {
  fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
  defer syscall.Close(fd)
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


func (c *Crznic) ReadPacket() ([]byte) {
	handle, _ := pcap.OpenLive(c.Inter, 1600, true, pcap.BlockForever)
	handle.SetBPFFilter("tcp and port " + string(c.Src.Ip))
	for {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		packetSentinel := false
		for packet := range packetSource.Packets() {
			for _, layer := range packet.Layers() {
				if layer.LayerType() == layers.LayerTypeTCP {
					tcp, _ := layer.(*layers.TCP)
					if tcp.Ack == 1337 {
						packetSentinel = true
					}
				}
				if layer.LayerType() == gopacket.LayerTypePayload && packetSentinel {
					return layer.LayerContents()
				}
			}
		}
	}
}


func (c *Crznic) SendSYNPacket(payload string) {
  // build ethernet layer
	ethernet := &layers.Ethernet{
		SrcMAC:	c.Src.Mac,
		DstMAC:	c.Dst.Mac,
		EthernetType: 0x800,
  }

  // build ip layer
  ip := &layers.IPv4{
		Version:		4,
		IHL:				5,
		TOS:				0,
		Id:					0,
		Flags:			0,
		FragOffset:	0,
		TTL:				225,
		SrcIP:			c.Src.Ip,
		DstIP:			c.Dst.Ip,
		Protocol:		layers.IPProtocolTCP,
  }

  // build tcp layer
  tcp := &layers.TCP{
		SrcPort:	c.Src.Port,
		DstPort:	c.Src.Port,
		Seq:			c.Seq,
		Ack:			1337,
		SYN:			true,
		Window:		14600,
  }
  tcp.SetNetworkLayerForChecksum(ip)

  // serialize packet
  buf := gopacket.NewSerializeBuffer()
  opts := gopacket.SerializeOptions{
		ComputeChecksums:	true,
		FixLengths:				true,
  }
  if err := gopacket.SerializeLayers(buf, opts, ethernet, ip, tcp, gopacket.Payload(payload)); err != nil {
		log.Fatal(err)
  }

  c.SendPacket(buf.Bytes())
}


func GetLocalMAC() (net.HardwareAddr) {
  rifs := RoutedInterface("ip", net.FlagUp | net.FlagBroadcast)
  var dstMac net.HardwareAddr
  if rifs != nil {
		dstMac = rifs.HardwareAddr
  } else {
		log.Fatal("No router address found")
  }

  return dstMac
}


func sample() {
	macAddr, _ := net.ParseMAC("00:0c:29:24:fa:a9")
	dstMac, _ := net.ParseMAC("00:50:56:fd:25:2c")
	srcHost := NewHost(net.ParseIP("172.16.46.185"), macAddr, layers.TCPPort(80))
	dstHost := NewHost(net.ParseIP("172.217.10.110"), dstMac, layers.TCPPort(80))

	crz := NewCrznic("eth0", srcHost, dstHost, 1)
	crz.SendSYNPacket("MESSAGE")

	crz.ReadPacket()
}