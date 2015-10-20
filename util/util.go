package util

import (
	"encoding/binary"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GetDstIP returns the destination ipV4§ as a string
func GetDstIP(packet gopacket.Packet) string {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip.DstIP.String()
	}
	return ""
}

// IsTcpPacket returns true if the packet is of TCP type
func IsTcpPacket(packet gopacket.Packet) bool {
	if packet == nil {
		return false
	}
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
		return false
	}
	return true
}

// IsUdpPacket returns true if the packet is of UDP type
func IsUdpPacket(packet gopacket.Packet) bool {
	if packet == nil {
		return false
	}
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
		return false
	}
	return true
}

// ExtractUint32 returns the given byte list as a uint32 take care of Little or Big Endian
func ExtractUint32(b []byte, start, end int) uint32 {
	if isLittleEndian() {
		return binary.LittleEndian.Uint32(b[start:end])
	}
	return binary.BigEndian.Uint32(b[start:end])
}

// ExtractUint16 returns the given byte list as a uint16 take care of Little or Big Endian
func ExtractUint16(b []byte, start, end int) uint16 {
	if isLittleEndian() {
		return binary.LittleEndian.Uint16(b[start:end])
	}
	return binary.BigEndian.Uint16(b[start:end])
}

func isLittleEndian() bool {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	return (b == 0x04)
}
