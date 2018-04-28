package crznic

import (
  "net"
  "syscall"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
	"errors"
)


// the host object, used for keeping track of ip/mac/port associated with each target/source
type Host struct {
  Ip		net.IP
  Mac		net.HardwareAddr
  Port	layers.TCPPort
}

// the connection handler object, keeps track of seq and ack, contains methods for working with the socket
type Crznic struct {
  Inter			string
  Src				*Host
  Dst				*Host
  Seq				uint32
  Ack				uint32
  connected	bool
}


// create a new Host object
func NewHost(ip net.IP, mac net.HardwareAddr, port uint16) *Host {
	layersPort := layers.TCPPort(port)
  newHost := &Host{
		Ip:		ip,
		Mac:	mac,
		Port: layersPort,
  }

  return newHost
}

// create a new Crznic object
func NewCrznic(inter string, src, dst *Host, seq uint32) *Crznic {
  newCrznic := &Crznic{
		Inter:			inter,
		Src:				src,
		Dst:				dst,
		Seq:				seq,
		Ack:				1337,
		connected: 	false,
  }
  return newCrznic
}

// send a constructed packet
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

// read a packet off the wire
func (c *Crznic) ReadPacket() (gopacket.Packet, error) {
	handle, _ := pcap.OpenLive(c.Inter, 1600, true, pcap.BlockForever)
	handle.SetBPFFilter("tcp and port " + string(c.Src.Ip))

	for {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			for _, layer := range packet.Layers() {
				if layer.LayerType() == layers.LayerTypeTCP {
					return packet, nil
				}
			}
		}
	}

	return nil, errors.New("no TCP packet received")
}

// listens for a SYN packet, updates the Crznic object with new data
func (c *Crznic) ListenForSYN() error {
	for {
		packet, err := c.ReadPacket()
		if err != nil {
			return err
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			c.Ack = tcp.Seq + 1
			c.Dst.Port = tcp.SrcPort
			return nil
		}
	}
}

// listens for SYN ACK, updates object
func (c *Crznic) ListenForSYNACK() error {
	for {
		packet, err := c.ReadPacket()
		if err != nil {
			return err
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && tcp.ACK {
			c.Ack = tcp.Seq + 1
			return nil
		}
	}
}

// listen for ACK, update object when received
func (c *Crznic) ListenForACK() error {
	for {
		packet, err := c.ReadPacket()
		if err != nil {
			return err
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.ACK && !tcp.SYN {
			c.Seq = tcp.Ack
			return nil
		}
	}
}

// listen for a tcp packet without flags, update object when received
func (c *Crznic) ListenForPSHACK() (string, error) {
	for {
		packet, err := c.ReadPacket()
		if err != nil {
			return "", err
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		app := packet.ApplicationLayer()
		if tcp.ACK && tcp.PSH {
			c.Ack = tcp.Seq + uint32(len(tcp.Payload))
			c.Seq = tcp.Ack
			return string(app.Payload()), nil
		}
	}
}

// send a TCP packet, use @param flag to specify which flags to set true
func (c *Crznic) SendTCPPacket(flag string, payload string) {
	// build
	packet := NewPacket(c)
  switch {
    case flag == "SYN":
      packet.TCP.SYN = true
		case flag == "SYN-ACK":
			packet.TCP.SYN = true
			packet.TCP.ACK = true
    case flag == "ACK":
      packet.TCP.ACK = true
		case flag == "PSH-ACK":
			packet.TCP.PSH = true
			packet.TCP.ACK = true
		case flag == "PSH":
			packet.TCP.PSH = true
    case flag == "FIN":
      packet.TCP.FIN = true
		case flag == "RST":
			packet.TCP.RST = true
		case flag == "RST-ACK":
			packet.TCP.RST = true
			packet.TCP.ACK = true
  }

	// serialize
	buf := gopacket.NewSerializeBuffer()
	packet.Serialize(buf, payload)

	// send, update seq
	c.SendPacket(buf.Bytes())
}

// start a connection with the destination host
func (c *Crznic) InitiateConnection() error {
	c.SendTCPPacket("SYN", "")
	err := c.ListenForSYNACK()
	if err != nil {
		return err
	}

	c.SendTCPPacket("ACK", "")
	c.connected = true
	return nil
}

// send data to an established connection
func (c *Crznic) SendData(payload string) error {
	if !c.connected {
		return errors.New("no connection established")
	}

	payload = " " + payload

	c.SendTCPPacket("PSH-ACK", payload)
	err := c.ListenForACK()
	if err != nil {
		return err
	}

	return nil
}

// receive data, respond with an ACK
func (c *Crznic) ReceiveData() (string, error) {
	payload, err := c.ListenForPSHACK()
	if err != nil {
		return "", err
	}

	c.SendTCPPacket("ACK", "")

	return payload, err
}