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
func (nt *ntlm) handlePacket(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	nlen := len(app.Payload())
	values := strings.Split(string(app.Payload()[:nlen]), "\r\n")
	for _, s := range values {
		match := regExp.FindString(s)
		if match != "" {
			baseStrings := strings.Split(s, " ")
			if len(baseStrings) != 3 {
				return
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			if challenge(s) {
				nt.addServerResponse(tcp.Ack, baseStrings[2])
			} else if response(s) {
				nt.addPairs(tcp.Seq, baseStrings[2])
			}
		}
	}
}

func (nt ntlm) dumpNtlm(outPutFile string) {
	file, _ := os.Create(outPutFile)
	defer file.Close()
	for _, pair := range nt.serverResponsePairs {
		dataResponse := pair.hexResponse()
		serverChallenge := pair.getServerChallenge()
		headerValues := pair.getResponseHeader()
		if headerValues.NtLen == 24 {
			user, domain, lmHash := getResponseDataNtLMv1(headerValues, dataResponse)
			if user != "" {
				// NTLM v1 in .lc format
				file.WriteString(user + "::" + domain + ":" + lmHash + ":" + serverChallenge + "\n")
			}
		} else {
			user, domain, nthashOne, nthashTwo := getResponseDataNtLMv2(headerValues, dataResponse)
			if user != "" {
				// Ntlm v2 in .lc format
				file.WriteString(user + "::" + domain + ":" + serverChallenge + ":" + nthashOne + ":" + nthashTwo + "\n")
			}
		}
	}
}
