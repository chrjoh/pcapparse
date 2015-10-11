package ntlm

import (
	"encoding/hex"
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

func (nt ntlm) dump(outPutFile string) {
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
