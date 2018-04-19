package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strconv"
	"errors"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct __attribute__((packed))
{
    char dest[6];
    char sender[6];
    uint16_t protocolType;
} EthernetHeader;

typedef struct __attribute__((packed))
{
    uint16_t hwType;
    uint16_t protoType;
    char hwLen;
    char protocolLen;
    uint16_t oper;
    char SHA[6];
    char SPA[4];
    char THA[6];
    char TPA[4];
} ArpPacket;

typedef struct __attribute__((packed))
{
    EthernetHeader eth;
    ArpPacket arp;
} EthernetArpPacket;

char* FillRequestPacketFields(char* senderMac, char* senderIp)
{
    EthernetArpPacket * packet = malloc(sizeof(EthernetArpPacket));
    memset(packet, 0, sizeof(EthernetArpPacket));
    // Ethernet header
    // Dest = Broadcast (ff:ff:ff:ff:ff)
    packet->eth.dest[0] = 0xff;
    packet->eth.dest[1] = 0xff;
    packet->eth.dest[2] = 0xff;
    packet->eth.dest[3] = 0xff;
    packet->eth.dest[4] = 0xff;
    packet->eth.dest[5] = 0xff;

    packet->eth.sender[0] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->eth.sender[1] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->eth.sender[2] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->eth.sender[3] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->eth.sender[4] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->eth.sender[5] = strtol(senderMac, NULL, 16);

    packet->eth.protocolType = htons(0x0806); // ARP

    // ARP Packet fields
    packet->arp.hwType = htons(1); // Ethernet
    packet->arp.protoType = htons(0x800); //IP;
    packet->arp.hwLen = 6;
    packet->arp.protocolLen = 4;
    packet->arp.oper = htons(2); // response

    // Sender MAC (same as that in eth header)
    memcpy(packet->arp.SHA, packet->eth.sender, 6);

    // Sender IP
    packet->arp.SPA[0] = strtol(senderIp, NULL, 10); senderIp = strchr(senderIp, '.') + 1;
    packet->arp.SPA[1] = strtol(senderIp, NULL, 10); senderIp = strchr(senderIp, '.') + 1;
    packet->arp.SPA[2] = strtol(senderIp, NULL, 10); senderIp = strchr(senderIp, '.') + 1;
    packet->arp.SPA[3] = strtol(senderIp, NULL, 10);

    // Dest MAC: Same as SHA, as we use an ARP response
    memcpy(packet->arp.THA, packet->arp.SHA, 6);

    // Dest IP: Same as SPA
    memcpy(packet->arp.TPA, packet->arp.SPA, 4);

    return (char*) packet;
}
*/
import "C"

// get the local ip and port based on our destination ip
func localIPPort() (net.IP, layers.TCPPort) {
	ifaces, _ := net.Interfaces()
	var ip net.IP

	// handle err
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		splitAddr := strings.Split(addrs[len(addrs) - 2].String(), "/")
		ip = net.ParseIP(splitAddr[0])
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

	// Our IP header
	ip := &layers.IPv4{
		SrcIP:    	srcip,
		DstIP:    	dstip,
		Protocol: 	layers.IPProtocolTCP,
		Version:  	4,
		Length:		60,
		Flags:		layers.IPv4DontFragment,
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
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(message)); err != nil {
		return err
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return err
	}
	fmt.Println("Obtained fd ", fd)
	defer syscall.Close(fd)

	interf, err := net.InterfaceByName("eth0")
	if err != nil {
		fmt.Println("Could not find vboxnet interface")
		return err
	}

	var addr syscall.SockaddrLinklayer
	addr.Protocol = syscall.ETH_P_ARP
	addr.Ifindex = interf.Index
	addr.Hatype = syscall.ARPHRD_ETHER

	err = syscall.Sendto(fd, buf.Bytes(), 0, &addr)
	if err != nil {
		log.Fatal(err)
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

// test sys arp memes
func supersys() {
	etherArp := new(C.EthernetArpPacket)
	size := uint(unsafe.Sizeof(*etherArp))
	fmt.Println("Size : ", size)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return
	}
	fmt.Println("Obtained fd ", fd)
	defer syscall.Close(fd)

	// Get Mac address of vboxnet1
	interf, err := net.InterfaceByName("eth0")
	if err != nil {
		fmt.Println("Could not find vboxnet interface")
		return
	}

	fmt.Println("Interface hw address: ", interf.HardwareAddr)
	fmt.Println("Creating request for IP 10.10.10.2 from IP 10.10.10.1")

	iface_cstr := C.CString(interf.HardwareAddr.String())
	ip_cstr := C.CString("10.10.10.3")

	packet := C.GoBytes(unsafe.Pointer(C.FillRequestPacketFields(iface_cstr, ip_cstr)) , C.int(size))

	// Send the packet
	var addr syscall.SockaddrLinklayer
	addr.Protocol = syscall.ETH_P_ARP
	addr.Ifindex = interf.Index
	addr.Hatype = syscall.ARPHRD_ETHER

	err = syscall.Sendto(fd, packet, 0, &addr)

	if err != nil {
		fmt.Println("Error: ", err)
	} else {
		fmt.Println("Sent packet")
	}

}

func main() {
	if len(os.Args) != 3 {
		log.Printf("Usage: %s <host/ip> <port>\n", os.Args[0])
		os.Exit(-1)
	}
	if os.Args[1] == "supersys" {
		// run the server main
		for {
			supersys()
		}
	} else {
		// run the client main
		client()
	}
}
