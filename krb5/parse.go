package krb5

import (
	"github.com/chrjoh/pcapparse/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Parse go through the given pcap file and selects krb5 AS requests sent over UDP
func Parse(inputFunc string) *krbAuth {
	if handle, err := pcap.OpenOffline(inputFunc); err != nil {
		panic(err)
	} else {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		krbResult := NewKrbHandler()
		for packet := range packetSource.Packets() {
			if util.IsUdpPacket(packet) {
				krbResult.HandlePacket(packet)
			}
		}
		return krbResult
	}
}
