package ntlm

type challengeResponseParsed struct {
	Type            int
	ServerChallenge string
	User            string
	Domain          string
	LmHash          string
	NtHashOne       string
	NtHashTwo       string
}

// LcString return the challenge response data as lc string
func (data challengeResponseParsed) LcString() string {
	// NTLM v1 in .lc format
	if data.Type == NtlmV1 {
		return data.User + "::" + data.Domain + ":" + data.LmHash + ":" + data.ServerChallenge + "\n"
	}
	return data.User + "::" + data.Domain + ":" + data.ServerChallenge + ":" + data.NtHashOne + ":" + data.NtHashTwo + "\n"
}
