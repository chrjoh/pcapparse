package main

import (
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
			//		data, err := base64.StdEncoding.DecodeString(base)
			//		if err != nil {
			//			fmt.Println("error:", err)
			//			return
			//		}

			//	fmt.Printf("%q\n", hex.Dump(data))
			//	fmt.Println("-----------------------------------------------------------------------------------------")
			//	}
		}
	}
}

func challenge(s string) bool {
	return regExpCha.FindString(s) != ""
}

func response(s string) bool {
	return regExpRes.FindString(s) != ""
}

func dumpPairs() {
	for _, pair := range serverResponsePairs {
		fmt.Println("======================================================")
		fmt.Println(pair.Challenge)
		fmt.Println("------------------------------------------------------")
		fmt.Println(pair.Response)
		fmt.Println("======================================================")
	}
}
