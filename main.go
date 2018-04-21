package main

import (
    "net"
    "syscall"
    "encoding/hex"
)


func main() {
 // TCP SYN from 192.168.58.128:49394 to 172.217.10.36:80
  myHex := "005056ea451c000c29c1beea08004500003c8292400040060604c0a83a80acd90a24c0f200503d64c05f00000000a0027210b2540000020405b40402080a001242cd000000000103030a"
	var pkt []byte
	pkt, _ = hex.DecodeString(myHex)

  fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
  if_info, _ := net.InterfaceByName("eth0")

    var haddr [8]byte
    copy(haddr[0:7], if_info.HardwareAddr[0:7])
    addr := syscall.SockaddrLinklayer{
        Protocol: syscall.ETH_P_IP,
        Ifindex:  if_info.Index,
        Halen:    uint8(len(if_info.HardwareAddr)),
        Addr:     haddr,
    }

    syscall.Bind(fd, &addr)
    syscall.SetLsfPromisc("eth0", true)
    syscall.Write(fd, pkt)
    syscall.SetLsfPromisc("eth0", false)

}
