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
)

// get the local ip and port based on our destination ip
func localIPPort(dstip net.IP) (net.IP, layers.TCPPort) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			tcpPort := layers.TCPPort(udpaddr.Port)
			return udpaddr.IP, tcpPort
		}
	}
	log.Fatal("could not get local ip: " + err.Error())
	return nil, layers.TCPPort(1)
}

// TODO: Reuse more code for standard packet reading
// reads the reply on a connection
func readSynReply(conn net.PacketConn, dstip net.IP, dstport layers.TCPPort, srcport layers.TCPPort) (error) {
	for {
		b := make([]byte, 4096)
		log.Println("reading from conn")
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			return err
		} else if addr.String() == dstip.String() {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == srcport {
					if tcp.SYN && tcp.ACK {
						log.Printf("Recieved syn/ack: %s\n", dstport)
						return nil
					} else {
						return errors.New("did not receive syn/ack")
					}
				}
			}
		} else {
			return errors.New("got packet not matching addr")
		}
	}
}

// builds and sends a CUSTOM TCP packet
func sendCustom(dstip net.IP, dstport layers.TCPPort, seq uint32, ack uint32, message []byte) (error) {
	srcip, srcport := localIPPort(dstip)
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
	log.Println("writing request")
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		return err
	}

	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	return nil
}

// client main function
func client() {
	log.Println("starting")

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

// handle packets server-side
func handlePacket(packet gopacket.Packet) () {
	// print ALL layers from this packet
	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
		if layer.LayerType() == gopacket.LayerTypePayload {
			fmt.Println(string(layer.LayerContents()))
		}
	}
}

// server main function
func server() {
	if handle, err := pcap.OpenLive("lo", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
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
		server()
	} else {
		// run the client main
		client()
	}
}
