package ntlm

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/chrjoh/pcapparse/util"
)

type challengeResponse struct {
	Challenge string
	Response  string
}

type responseHeader struct {
	Sig          string
	Type         uint32
	LmLen        uint16
	LmMax        uint16
	LmOffset     uint16
	NtLen        uint16
	NtMax        uint16
	NtOffset     uint16
	DomainLen    uint16
	DomainMax    uint16
	DomainOffset uint16
	UserLen      uint16
	UserMax      uint16
	UserOffset   uint16
	HostLen      uint16
	HostMax      uint16
	HostOffset   uint16
}

// http://davenport.sourceforge.net/ntlm.html
// http://www.opensource.apple.com/source/passwordserver_sasl/passwordserver_sasl-166/cyrus_sasl/plugins/ntlm.c
// offset for the different type of messeges that are sent in a ntlm challenge-response
const (
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

	NtlmV1 = 1
	NtlmV2 = 2
)

func (sr challengeResponse) getServerChallenge() string {
	dataCallenge, _ := base64.StdEncoding.DecodeString(sr.Challenge)
	//offset to the challenge and the challenge is 8 bytes long
	return hex.EncodeToString(dataCallenge[NTLM_TYPE2_CHALLENGE_OFFSET : NTLM_TYPE2_CHALLENGE_OFFSET+8])
}

func (sr challengeResponse) hexChallenge() []byte {
	dataCallenge, _ := base64.StdEncoding.DecodeString(sr.Challenge)
	return dataCallenge
}

func (sr challengeResponse) hexResponse() []byte {
	dataResponse, _ := base64.StdEncoding.DecodeString(sr.Response)
	return dataResponse
}
func (sr *challengeResponse) getResponseData() (challengeResponseParsed, error) {
	if sr.isNtlmV1() {
		return sr.getResponseDataNtLMv1()
	}
	return sr.getResponseDataNtLMv2()
}

func (sr *challengeResponse) getResponseDataNtLMv2() (challengeResponseParsed, error) {
	r := sr.getResponseHeader()
	if r.UserLen == 0 {
		return challengeResponseParsed{}, errors.New("No repsponse data")
	}
	b := sr.hexResponse()
	nthash := b[r.NtOffset : r.NtOffset+r.NtLen]
	// each char in user and domain is null terminated
	return challengeResponseParsed{
		Type:      NtlmV2,
		User:      strings.Replace(string(b[r.UserOffset:r.UserOffset+r.UserLen]), "\x00", "", -1),
		Domain:    strings.Replace(string(b[r.DomainOffset:r.DomainOffset+r.DomainLen]), "\x00", "", -1),
		NtHashOne: hex.EncodeToString(nthash[:16]), // first part of the hash is 16 bytes
		NtHashTwo: hex.EncodeToString(nthash[16:]),
	}, nil
}

func (sr challengeResponse) isNtlmV1() bool {
	headerValues := sr.getResponseHeader()
	return headerValues.NtLen == 24
}

func (sr challengeResponse) getResponseDataNtLMv1() (challengeResponseParsed, error) {
	r := sr.getResponseHeader()
	if r.UserLen == 0 {
		return challengeResponseParsed{}, errors.New("No repsponse data")
	}
	b := sr.hexResponse()
	// each char user and domain is null terminated
	return challengeResponseParsed{
		Type:   NtlmV1,
		User:   strings.Replace(string(b[r.UserOffset:r.UserOffset+r.UserLen]), "\x00", "", -1),
		Domain: strings.Replace(string(b[r.DomainOffset:r.DomainOffset+r.DomainLen]), "\x00", "", -1),
		LmHash: hex.EncodeToString(b[r.LmOffset : r.LmOffset+r.LmLen]),
	}, nil
}
func (sr challengeResponse) getResponseHeader() responseHeader {
	b := sr.hexResponse()
	if len(b) == 0 {
		return responseHeader{}
	}
	return responseHeader{
		Sig:          strings.Replace(string(b[NTLM_SIG_OFFSET:NTLM_SIG_OFFSET+8]), "\x00", "", -1),
		Type:         util.ExtractUint32(b, NTLM_TYPE_OFFSET, NTLM_TYPE_OFFSET+4),
		LmLen:        util.ExtractUint16(b, NTLM_TYPE3_LMRESP_OFFSET, NTLM_TYPE3_LMRESP_OFFSET+2),
		LmMax:        util.ExtractUint16(b, NTLM_TYPE3_LMRESP_OFFSET+2, NTLM_TYPE3_LMRESP_OFFSET+4),
		LmOffset:     util.ExtractUint16(b, NTLM_TYPE3_LMRESP_OFFSET+4, NTLM_TYPE3_LMRESP_OFFSET+6),
		NtLen:        util.ExtractUint16(b, NTLM_TYPE3_NTRESP_OFFSET, NTLM_TYPE3_NTRESP_OFFSET+2),
		NtMax:        util.ExtractUint16(b, NTLM_TYPE3_NTRESP_OFFSET+2, NTLM_TYPE3_NTRESP_OFFSET+4),
		NtOffset:     util.ExtractUint16(b, NTLM_TYPE3_NTRESP_OFFSET+4, NTLM_TYPE3_NTRESP_OFFSET+6),
		DomainLen:    util.ExtractUint16(b, NTLM_TYPE3_DOMAIN_OFFSET, NTLM_TYPE3_DOMAIN_OFFSET+2),
		DomainMax:    util.ExtractUint16(b, NTLM_TYPE3_DOMAIN_OFFSET+2, NTLM_TYPE3_DOMAIN_OFFSET+4),
		DomainOffset: util.ExtractUint16(b, NTLM_TYPE3_DOMAIN_OFFSET+4, NTLM_TYPE3_DOMAIN_OFFSET+6),
		UserLen:      util.ExtractUint16(b, NTLM_TYPE3_USER_OFFSET, NTLM_TYPE3_USER_OFFSET+2),
		UserMax:      util.ExtractUint16(b, NTLM_TYPE3_USER_OFFSET+2, NTLM_TYPE3_USER_OFFSET+4),
		UserOffset:   util.ExtractUint16(b, NTLM_TYPE3_USER_OFFSET+4, NTLM_TYPE3_USER_OFFSET+6),
		HostLen:      util.ExtractUint16(b, NTLM_TYPE3_WORKSTN_OFFSET, NTLM_TYPE3_WORKSTN_OFFSET+2),
		HostMax:      util.ExtractUint16(b, NTLM_TYPE3_WORKSTN_OFFSET+2, NTLM_TYPE3_WORKSTN_OFFSET+4),
		HostOffset:   util.ExtractUint16(b, NTLM_TYPE3_WORKSTN_OFFSET+4, NTLM_TYPE3_WORKSTN_OFFSET+6),
	}
}
