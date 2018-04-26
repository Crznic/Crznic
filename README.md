# Crznic
A "custom" layer 4 protocol for raw socket communication on linux. Golang library.  

## INSTALL
```
go get github.com/Crznic/Crznic
```

## USAGE
Read sample function

Create MAC addresses for local and target
```
macAddr, _ := net.ParseMAC("00:0c:29:24:fa:a9")
dstMac, _ := net.ParseMAC("00:50:56:fd:25:2c")
```

Create host structs
```
srcHost := NewHost(net.ParseIP("172.16.46.185"), macAddr, layers.TCPPort(80))
dstHost := NewHost(net.ParseIP("172.217.10.110"), dstMac, layers.TCPPort(80))
```

Create crznic handler
```
crz := NewCrznic("eth0", srcHost, dstHost, 1)
```

Send a packet
```
crz.SendSYNPacket("MESSAGE")
```

Listen for a packet
```
crz.ReadPacket()
```
