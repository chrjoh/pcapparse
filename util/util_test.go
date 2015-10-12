package util

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "eth0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

func TestGetDestIP(t *testing.T) {
	packet := createIPv4TCPPacket([]byte{})
	fmt.Println(packet)
	ip := GetDstIP(packet)
	if ip != "1.2.3.4" {
		t.Fatalf("Could not parse dest ip from packet got: %v, wanted: 1.2.3.4", ip)
	}
}

func createIPv4TCPPacket(payload []byte) gopacket.Packet {

	ipLayer := &layers.IPv4{
		Version: 4,
		TTL:     64,
		SrcIP:   net.IP{127, 0, 0, 1},
		DstIP:   net.IP{1, 2, 3, 4},
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA, 0xFA, 0xAA},
		DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(4321),
		DstPort: layers.TCPPort(80),
	}
	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(payload),
	)
	outgoingPacket := buffer.Bytes()

	return gopacket.NewPacket(outgoingPacket, layers.EthernetTypeIPv4, gopacket.Default)

}
