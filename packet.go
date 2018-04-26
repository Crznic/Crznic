package crznic

import (
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"log"
)

type Packet struct {
	Ethernet	*layers.Ethernet
	Ip				*layers.IPv4
	TCP				*layers.TCP
}

func NewPacket(c *Crznic) *Packet {
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
			Window:		14600,
		}
		tcp.SetNetworkLayerForChecksum(ip)

		// build base packet
		packet := &Packet {
			Ethernet:	ethernet,
			Ip:				ip,
			TCP:			tcp,
		}

		return packet
}

func (p *Packet) Serialize(buf gopacket.SerializeBuffer, payload string) {
	opts := gopacket.SerializeOptions{
		ComputeChecksums:	true,
		FixLengths:				true,
	}
	if err := gopacket.SerializeLayers(buf, opts, p.Ethernet, p.Ip, p.TCP, gopacket.Payload(payload)); err != nil {
		log.Fatal(err)
	}
}