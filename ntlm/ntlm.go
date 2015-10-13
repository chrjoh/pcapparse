package ntlm

import (
	"os"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ntlm struct {
	serverResponse      map[uint32]string
	serverResponsePairs []challengeResponse
}

var (
	regExp    = regexp.MustCompile("(WWW-|Proxy-|)(Authenticate|Authorization): (NTLM|Negotiate)")
	regExpCha = regexp.MustCompile("(WWW-|Proxy-|)(Authenticate): (NTLM|Negotiate)")
	regExpRes = regexp.MustCompile("(WWW-|Proxy-|)(Authorization): (NTLM|Negotiate)")
)

// NewNtlmHandler returns a ntlm v1 or v2 packet handler
func NewNtlmHandler() *ntlm {
	return &ntlm{
		serverResponse:      make(map[uint32]string),
		serverResponsePairs: []challengeResponse{},
	}
}

func (nt *ntlm) addServerResponse(key uint32, value string) {
	nt.serverResponse[key] = value
}

func (nt *ntlm) addPairs(seq uint32, value string) {
	if nt.serverResponse[seq] != "" {
		c := challengeResponse{
			Challenge: nt.serverResponse[seq],
			Response:  value,
		}
		nt.serverResponsePairs = append(nt.serverResponsePairs, c)
	}
}

func (nt ntlm) serverResp(key uint32) string {
	return nt.serverResponse[key]
}

// assemble the correct challenge with the response
func (nt *ntlm) HandlePacket(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	nlen := len(app.Payload())
	values := strings.Split(string(app.Payload()[:nlen]), "\r\n")
	for _, s := range values {
		if isNtlm(s) {
			baseStrings := strings.Split(s, " ")
			if len(baseStrings) != 3 {
				return
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			if isChallenge(s) {
				nt.addServerResponse(tcp.Ack, baseStrings[2])
			} else if isResponse(s) {
				nt.addPairs(tcp.Seq, baseStrings[2])
			}
		}
	}
}

// Dump write the result to the given file
func (nt ntlm) Dump(outPutFile string) {
	file, _ := os.Create(outPutFile)
	defer file.Close()
	for _, pair := range nt.serverResponsePairs {
		serverChallenge := pair.getServerChallenge()
		data, err := pair.getResponseData()
		if err == nil {
			file.WriteString(data.LcString(serverChallenge))
		}
	}
}

func isNtlm(s string) bool {
	return regExp.FindString(s) != ""
}

func isChallenge(s string) bool {
	return regExpCha.FindString(s) != ""
}

func isResponse(s string) bool {
	return regExpRes.FindString(s) != ""
}
