package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var pcapFile = "steg3.pcap"
var regExp = regexp.MustCompile("(WWW-|Proxy-|)(Authenticate|Authorization): (NTLM|Negotiate)")
var regExpCha = regexp.MustCompile("(WWW-|Proxy-|)(Authenticate): (NTLM|Negotiate)")
var regExpRes = regexp.MustCompile("(WWW-|Proxy-|)(Authorization): (NTLM|Negotiate)")

type ChallengeResponse struct {
	Challenge string
	Response  string
}

var (
	NTLM_SIG_OFFSET  = 0
	NTLM_TYPE_OFFSET = 8

	NTLM_TYPE1_FLAGS_OFFSET   = 12
	NTLM_TYPE1_DOMAIN_OFFSET  = 16
	NTLM_TYPE1_WORKSTN_OFFSET = 24
	NTLM_TYPE1_DATA_OFFSET    = 32
	NTLM_TYPE1_MINSIZE        = 16

	NTLM_TYPE2_TARGET_OFFSET     = 12
	NTLM_TYPE2_FLAGS_OFFSET      = 20
	NTLM_TYPE2_CHALLENGE_OFFSET  = 24
	NTLM_TYPE2_CONTEXT_OFFSET    = 32
	NTLM_TYPE2_TARGETINFO_OFFSET = 40
	NTLM_TYPE2_DATA_OFFSET       = 48
	NTLM_TYPE2_MINSIZE           = 32

	NTLM_TYPE3_LMRESP_OFFSET     = 12
	NTLM_TYPE3_NTRESP_OFFSET     = 20
	NTLM_TYPE3_DOMAIN_OFFSET     = 28
	NTLM_TYPE3_USER_OFFSET       = 36
	NTLM_TYPE3_WORKSTN_OFFSET    = 44
	NTLM_TYPE3_SESSIONKEY_OFFSET = 52
	NTLM_TYPE3_FLAGS_OFFSET      = 60
	NTLM_TYPE3_DATA_OFFSET       = 64
	NTLM_TYPE3_MINSIZE           = 52

	NTLM_BUFFER_LEN_OFFSET    = 0
	NTLM_BUFFER_MAXLEN_OFFSET = 2
	NTLM_BUFFER_OFFSET_OFFSET = 4
	NTLM_BUFFER_SIZE          = 8
)
var serverResponse = make(map[uint32]string)
var serverResponsePairs = []ChallengeResponse{}

func main() {

	if handle, err := pcap.OpenOffline(pcapFile); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
		dumpPairs()
	}
}

func handlePacket(packet gopacket.Packet) {
	if packet == nil {
		return
	}

	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
		return
	}
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	n := len(app.Payload())
	values := strings.Split(string(app.Payload()[:n]), "\r\n")
	for _, s := range values {
		match := regExp.FindString(s)
		if match != "" {
			baseStrings := strings.Split(s, " ")
			if len(baseStrings) != 3 {
				return
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			if challenge(s) {
				serverResponse[tcp.Ack] = baseStrings[2]
			} else if response(s) {
				if serverResponse[tcp.Seq] != "" {
					serverResponsePairs = append(serverResponsePairs, ChallengeResponse{
						Challenge: serverResponse[tcp.Seq],
						Response:  baseStrings[2],
					})
				}
			}
		}
	}
}

func challenge(s string) bool {
	return regExpCha.FindString(s) != ""
}

func response(s string) bool {
	return regExpRes.FindString(s) != ""
}

// ntlmv2 challenge type 2
// 0  NTLMSSP Signature
// 8  NTLM Message Type
// 12 Target Name
// 20 Flags
// 24 Challenge
// 32 end of header, start of optional data blocks

// ntlmv2 response type 3
//0 NTLMSSP Signature Null-terminated ASCII "NTLMSSP" (0x4e544c4d53535000)
//8 NTLM Message Type long (0x03000000)
//12 LM/LMv2 Response security buffer
//20 NTLM/NTLMv2 Response security buffer
//28 Target Name security buffer
//36 User Name security buffer
//44 Workstation Name security buffer

func dumpPairs() {
	for _, pair := range serverResponsePairs {
		dataCallenge, _ := base64.StdEncoding.DecodeString(pair.Challenge)
		dataResponse, _ := base64.StdEncoding.DecodeString(pair.Response)

		fmt.Println("======================================================")
		//fmt.Println(base64.StdEncoding.DecodeString(pair.Challenge))
		//offset to the challenge, 8 bytes long
		fmt.Println(hex.EncodeToString(dataCallenge[NTLM_TYPE2_CHALLENGE_OFFSET:NTLM_TYPE2_CONTEXT_OFFSET]))
		fmt.Println("------------------------------------------------------")
		//fmt.Println(base64.StdEncoding.DecodeString(pair.Response))
		fmt.Println(hex.EncodeToString(dataResponse))
		fmt.Println("::::::::::::::::::::::::")
		fmt.Println(hex.EncodeToString(dataResponse[:44]))
		fmt.Println("======================================================")
	}
}
