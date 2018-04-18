import (
	"fmt",
	"net"
)

func main() {

	packet := TCPHeader{
		Source: 0xaa47, // Random ephemeral port
    	Destination: 80,
    	SeqNum: rand.Uint32(),
    	AckNum: 0,
    	DataOffset: 5, // 4 bits
    	Reserved: 0, // 3 bits
    	ECN: 0, // 3 bits
    	Ctrl: 2, // 6 bits (000010, SYN bit set)
    	Window: 0xaaaa, // size of your receive window
    	Checksum: 0, // Kernel will set this if it's 0
    	Urgent: 0,
    	Options: []TCPOption{},
	}

	data := packet.Marshal()
	packet.Checksum = csum(data, to4byte(laddr), to4byte(raddr))
	data = packet.Marshal()

	conn, err := net.Dial("ip4:tcp", raddr)
	if err != nil {
		log.Fatalf("dial: %s\n", err)
	}

	conn.Write(data)

}