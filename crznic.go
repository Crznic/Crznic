package crznic

import (
  "net"
  "syscall"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
)


type Host struct {
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
  newHost := &Host{
		Ip:		ip,
		Mac:	mac,
		Port:	port,
  }

  return newHost
}


func NewCrznic(inter string, src, dst *Host, seq uint32) *Crznic {
  newCrznic := &Crznic{
		Inter:	inter,
		Src:		src,
		Dst:		dst,
		Seq:		seq,
  }
  return newCrznic
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

func (c *Crznic) SendTCPPacket(syn, ack, fin bool, payload string) {
	// build
	packet := NewPacket(c)
	packet.TCP.SYN = syn
	packet.TCP.ACK = ack
	packet.TCP.FIN = fin

	// serialize
	buf := gopacket.NewSerializeBuffer()
	packet.Serialize(buf, payload)

	// send, update seq
	c.SendPacket(buf.Bytes())
	c.Seq++
}