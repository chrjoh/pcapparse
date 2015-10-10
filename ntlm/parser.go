package ntlm

import (
	"encoding/hex"
	"strings"

	"github.com/chrjoh/pcapparse/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func Parse(inputFunc string, outputFunc string) {
	if handle, err := pcap.OpenOffline(inputFunc); err != nil {
		panic(err)
	} else {
		ntlmResult := ntlm{
			serverResponse:      make(map[uint32]string),
			serverResponsePairs: []challengeResponse{},
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if util.IsTcpPacket(packet) {
				ntlmResult.handlePacket(packet)
			}
		}
		ntlmResult.dumpNtlm(outputFunc)
	}
}

func challenge(s string) bool {
	return regExpCha.FindString(s) != ""
}

func response(s string) bool {
	return regExpRes.FindString(s) != ""
}

func getResponseDataNtLMv1(r responseHeader, b []byte) (string, string, string) {
	if r.UserLen == 0 {
		return "", "", ""
	}
	// each char is null terminated
	user := strings.Replace(string(b[r.UserOffset:r.UserOffset+r.UserLen]), "\x00", "", -1)
	domain := strings.Replace(string(b[r.DomainOffset:r.DomainOffset+r.DomainLen]), "\x00", "", -1)
	lmHash := hex.EncodeToString(b[r.LmOffset : r.LmOffset+r.LmLen])
	return user, domain, lmHash
}

func getResponseDataNtLMv2(r responseHeader, b []byte) (string, string, string, string) {
	if r.UserLen == 0 {
		return "", "", "", ""
	}
	// each char is null terminated
	user := strings.Replace(string(b[r.UserOffset:r.UserOffset+r.UserLen]), "\x00", "", -1)
	nthash := b[r.NtOffset : r.NtOffset+r.NtLen]
	domain := strings.Replace(string(b[r.DomainOffset:r.DomainOffset+r.DomainLen]), "\x00", "", -1)
	nthashOne := hex.EncodeToString(nthash[:16]) // first part of the hash is 16 bytes
	nthashTwo := hex.EncodeToString(nthash[16:])
	return user, domain, nthashOne, nthashTwo
}
