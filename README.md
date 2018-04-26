# Crznic
A "custom" layer 4 protocol for raw socket communication on linux. Golang library.  

## INSTALL
```
go get github.com/Crznic/Crznic
```

## USAGE
Read sample function

Create MAC addresses for src and dst
```
srcMAC, _ := net.ParseMAC("00:0c:29:24:fa:a9")
dstMAC, _ := net.ParseMAC("00:50:56:fd:25:2c")
```

Create IP addresses for src and dst
```
srcIP = net.ParseIP("172.16.46.185")
dstIP = net.ParseIP("172.217.10.110")
```

Create gopacket TCPPorts
```
srcPort := layers.TCPPort(80)
dstPort := layers.TCPPort(80)
```

Create host structs
```
srcHost := NewHost(srcIP, srcMAC, srcPort)
dstHost := NewHost(dstIP, dstMAC, dstPort)
```

Create crznic handler
```
crz := NewCrznic("eth0", srcHost, dstHost, 1)
```

Send a SYN packet
```
crz.SendTCPPacket("SYN", "MESSAGE")
```

Listen for a packet
```
crz.ReadPacket()
```
