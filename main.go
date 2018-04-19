package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strconv"
	"time"
	"errors"
	"encoding/json"
	"fmt"
	"strings"
)

// get the local ip and port based on our destination ip
func localIPPort() (net.IP, layers.TCPPort) {
	ifaces, _ := net.Interfaces()
	var ip net.IP

	// handle err
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		// splitAddr := strings.Split(addrs[len(addrs) - 1].Network(), "/")
		ip = net.IP(addrs[len(addrs) - 1].Network())
	}
	tcpPort := layers.TCPPort(80)
	return ip, tcpPort
}

// gets payload data from a packet
func getPayloadData(packet gopacket.Packet) ([]byte) {
	// print ALL layers from this packet
	for _, layer := range packet.Layers() {
		if layer.LayerType() == gopacket.LayerTypePayload {
			return layer.LayerContents()
		}
	}

	return nil
}

// reads the reply on a connection
func readReply(conn net.PacketConn, dstip net.IP, dstport layers.TCPPort, srcport layers.TCPPort) (error) {
	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			return err
		} else if addr.String() == dstip.String() {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.RST == true {
					continue
				} else if tcp.DstPort == srcport {
					payloadBuf := getPayloadData(packet)
					fmt.Println(string(payloadBuf))
					return nil
				}
			}
		} else {
			continue
		}
	}

	return errors.New("nothing read")
}

// builds and sends a CUSTOM TCP packet
func sendCustom(dstip net.IP, dstport layers.TCPPort, seq uint32, ack uint32, message []byte) (error) {
	srcip, srcport := localIPPort()
	log.Printf("using srcip: %v", srcip.String())

	// Our IP header... not used, but necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}

	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     seq,
		ACK:     true,
		RST:	 false,
		Ack:	 ack,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,

	}
	if err := gopacket.SerializeLayers(buf, opts, tcp, gopacket.Payload(message)); err != nil {
		return err
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		return err
	}

	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	if err := readReply(conn, dstip, dstport, srcport); err != nil {
		return err
	}

	return nil
}

// client main function
func client() {
	// define the seq for this interaction
	var seq uint32
	seq = 2132141

	dstaddrs, err := net.LookupIP(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// parse the destination host and port from the command line os.Args
	dstip := dstaddrs[0].To4()
	var dstport layers.TCPPort
	if d, err := strconv.ParseUint(os.Args[2], 10, 16); err != nil {
		log.Fatal(err)
	} else {
		dstport = layers.TCPPort(d)
	}

	// build JSON
	type Message struct {
		Name string
		Body string
		Time int64
	}
	m := Message{"Alice", "Hello", 1294706395881547000}
	b, _ := json.Marshal(m)

	// define the custom ack number
	var ack uint32
	ack = 1

	// send a json as a custom TCP packet
	err = sendCustom(dstip, dstport, seq, ack, b)
	if err != nil {
		log.Fatal(err)
	}
}

// server main function
func server() {
	if handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			payloadBuf := getPayloadData(packet)
			fmt.Println(string(payloadBuf))
		}
	}
}

func main() {
	if len(os.Args) != 3 {
		log.Printf("Usage: %s <host/ip> <port>\n", os.Args[0])
		os.Exit(-1)
	}
	if os.Args[1] == "server" {
		// run the server main
		for {
			server()
		}
	} else {
		// run the client main
		client()
	}
}
