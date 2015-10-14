package ftp

import (
	"github.com/chrjoh/pcapparse/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Parse go through the given pcap file and selects ftp logins
func Parse(inputFunc string) *ftpLogin {
	if handle, err := pcap.OpenOffline(inputFunc); err != nil {
		panic(err)
	} else {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		ftpResult := NewFtpHandler()
		for packet := range packetSource.Packets() {
			if util.IsTcpPacket(packet) {
				ftpResult.HandlePacket(packet)
			}
		}
		return ftpResult
	}
}
