package crznic

import (
	"net"
	"syscall"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"errors"
        "strings"
	"fmt"
)

// the host object, used for keeping track of ip/mac/port associated with each target/source
type Host struct {
	Ip   net.IP
	Mac  net.HardwareAddr
	Port layers.TCPPort
}

// the connection handler object, keeps track of seq and ack, contains methods for working with the socket
type Crznic struct {
	Inter     string
	Src       *Host
	Dst       *Host
	Seq       uint32
	Ack       uint32
	connected bool
	options   []layers.TCPOption
	socket_fd int
}

// create a new Host object
func NewHost(ip net.IP, mac net.HardwareAddr, port uint16) *Host {
	layersPort := layers.TCPPort(port)
	newHost := &Host{
		Ip:   ip,
		Mac:  mac,
		Port: layersPort,
	}

	return newHost
}

// create a new Crznic object
func NewCrznic(inter string, src, dst *Host, seq uint32) *Crznic {
	MSS := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4}, // 1460 bytes
	}

	SACKPermitted := layers.TCPOption{
		OptionType:   layers.TCPOptionKindSACKPermitted,
		OptionLength: 2,
		OptionData:   []byte{}, // must be empty but go packet requires it
	}

	newCrznic := &Crznic{
		Inter:     inter,
		Src:       src,
		Dst:       dst,
		Seq:       seq,
		Ack:       0,
		connected: false,
		options:   []layers.TCPOption{MSS, SACKPermitted},
		socket_fd: -1,
	}

	return newCrznic
}

// send a constructed packet
func (c *Crznic) SendPacket(pkt []byte) {
	if c.socket_fd == -1{
		fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
		c.socket_fd = fd
	}
	if_info, _ := net.InterfaceByName(c.Inter)

	var haddr [8]byte
	copy(haddr[0:7], if_info.HardwareAddr[0:7])
	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  if_info.Index,
		Halen:    uint8(len(if_info.HardwareAddr)),
		Addr:     haddr,
	}

	syscall.Bind(c.socket_fd, &addr)
	syscall.SetLsfPromisc(c.Inter, true)
	syscall.Write(c.socket_fd, pkt)
	syscall.Fsync(c.socket_fd)
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
					tcpLayer := packet.Layer(layers.LayerTypeTCP)
					tcp, _ := tcpLayer.(*layers.TCP)
					if tcp.DstPort == c.Src.Port { // make sure is our tcp stuffs
						return packet, nil
					}
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
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		eth, _ := ethLayer.(*layers.Ethernet)
		if tcp.SYN && !tcp.ACK {
			c.Ack = tcp.Seq + 1
			c.Dst.Port = tcp.SrcPort
			c.Dst.Ip = ip.SrcIP
			c.Dst.Mac = eth.SrcMAC
			c.options = tcp.Options
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
			c.Seq = c.Seq + 1
			return nil
		}
	}
}

// listen for FIN-ACK, update object when received
func (c *Crznic) ListenForFINACK() error {
	for {
		packet, err := c.ReadPacket()
		if err != nil {
			return err
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.ACK && tcp.FIN{
			c.Seq = tcp.Ack
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
		if tcp.ACK {
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
			packet.TCP.Options = c.options
		case flag == "SYN-ACK":
			packet.TCP.SYN = true
			packet.TCP.ACK = true
			packet.TCP.Options = c.options
		case flag == "ACK":
			packet.TCP.ACK = true
		case flag == "PSH-ACK":
			packet.TCP.PSH = true
			packet.TCP.ACK = true
		case flag == "PSH":
			packet.TCP.PSH = true
		case flag == "FIN":
			packet.TCP.FIN = true
		case flag == "FIN-ACK":
			packet.TCP.FIN = true
			packet.TCP.ACK = true
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
	fmt.Println("Connection Opened...")
	return nil
}

// receive a connection as a server
func (c *Crznic) ReceiveConnection() error {
	c.ListenForSYN()
	c.SendTCPPacket("SYN-ACK", "")
	c.ListenForACK()

	c.connected = true
	fmt.Println("Connection Opened...")
	return nil
}

// terminate the connection with a RST packet
func (c *Crznic) TerminateConnection() {
	c.SendTCPPacket("RST", "")
	c.connected = false
	syscall.Close(c.socket_fd)
	fmt.Println("Connection Closed...")
}

// send data to an established connection
func (c *Crznic) SendData(payload string) error {
	if !c.connected {
		return errors.New("no connection established")
	}
	payload = payload + "\n" // for combatibility
	payloadSlices := []string{}
	for i := 0; i < len(payload); i += 1024 {
		if i+1024 > len(payload) {
			payloadSlices = append(payloadSlices, payload[i:])
		} else {
			payloadSlices = append(payloadSlices, payload[i:i+1024])
		}
	}

	for _, part := range payloadSlices {
		c.SendTCPPacket("PSH-ACK", part)
		err := c.ListenForACK()
		if err != nil {
			return err
		}
	}

	
	return nil
}

// receive data, respond with an ACKs, and eventually FIN-ACK (if closed)
func (c *Crznic) ReceiveData() (string, error) {
        if !c.connected {
		return "", errors.New("no connection established")
	}
	data := ""
        var err error
	err = nil
	for {
		packet, _ := c.ReadPacket()
                tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
                if tcp.FIN && tcp.ACK {
			c.Ack = tcp.Seq + 1
			c.SendTCPPacket("ACK", "")
			c.SendTCPPacket("FIN-ACK", "")
			c.connected = false
			break;
                }
                if tcp.RST {
			c.connected = false
			break;
                }
		app := packet.ApplicationLayer()
		if tcp.ACK && tcp.PSH {
			c.Ack = tcp.Seq + uint32(len(tcp.Payload))
			c.Seq = tcp.Ack
			payload := string(app.Payload())
		        c.SendTCPPacket("ACK", "")
                        data = data + payload
                        if strings.HasSuffix(data, "\n"){
				break;
                        }
		}
	}

	return data, err
}

// connect, send and receive data in a full session, then terminate with a reset
func (c *Crznic) FullBeacon(payload string) (string, error) {
	c.InitiateConnection()
	defer c.TerminateConnection()
	c.SendData(payload)
	response, err := c.ReceiveData()

	return response, err
}
